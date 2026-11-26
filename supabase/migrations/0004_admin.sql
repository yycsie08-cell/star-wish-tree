-- 後台：只有 admins 裡的帳號（用 Google 登入的使用者編號）可以用
create table public.admins (user_id uuid primary key references auth.users(id) on delete cascade);
insert into public.admins values ('0578d9a1-1864-44a8-bb06-93921e6936f8'); -- 網站管理者（站長的 Google 帳號）
alter table public.admins enable row level security;
revoke all on public.admins from anon, authenticated;

create function public.is_admin() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.admins a where a.user_id = (select auth.uid()));
$$;
revoke execute on function public.is_admin() from public, anon;
grant execute on function public.is_admin() to authenticated;

-- 朋友掛吊飾：從現在起記錄真實 IP 和裝置（隱私權政策同步更新）
alter table public.ornaments add column ip text, add column user_agent text;
alter table public.hang_attempts add column ip text;

-- 封鎖名單：IP（真實或加密值）
create table public.blocked (
  id bigint generated always as identity primary key,
  ip text not null unique,
  reason text,
  created_at timestamptz not null default now()
);
alter table public.blocked enable row level security;
revoke all on public.blocked from anon, authenticated;

-- 登入紀錄：每次登入（建立 session）就記一筆
create table public.login_log (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  email text,
  ip text,
  user_agent text,
  created_at timestamptz not null default now()
);
create index login_log_user on public.login_log (user_id, created_at desc);
alter table public.login_log enable row level security;
revoke all on public.login_log from anon, authenticated;

create function public.log_login() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  insert into public.login_log (user_id, email, ip, user_agent, created_at)
  values (new.user_id, (select u.email from auth.users u where u.id = new.user_id), host(new.ip), new.user_agent, coalesce(new.created_at, now()));
  return new;
end $$;
create trigger on_session_created after insert on auth.sessions for each row execute function public.log_login();
insert into public.login_log (user_id, email, ip, user_agent, created_at)
select s.user_id, u.email, host(s.ip), s.user_agent, s.created_at from auth.sessions s join auth.users u on u.id = s.user_id;

-- 掛吊飾改版：多記真實 IP、裝置；封鎖名單裡的 IP 不能掛；刪掉的位置可以再用
drop function public.hang_note(text);
create function public.hang_note(p_ip text, p_ip_raw text)
returns void language sql volatile security definer set search_path = '' as $$
  delete from public.hang_attempts where created_at < now() - interval '2 days';
  delete from public.used_challenges where created_at < now() - interval '1 day';
  insert into public.hang_attempts (ip_hash, ip) values (p_ip, p_ip_raw);
$$;
revoke execute on function public.hang_note(text, text) from public, anon, authenticated;
grant execute on function public.hang_note(text, text) to service_role;

drop function public.hang_insert(uuid, text, smallint, text, text, text);
create function public.hang_insert(p_tree uuid, p_kind text, p_color smallint, p_from text, p_message text, p_ip text, p_ip_raw text, p_ua text)
returns smallint language plpgsql volatile security definer set search_path = '' as $$
declare cap int; used int;
begin
  if exists (select 1 from public.blocked b where b.ip in (p_ip, p_ip_raw)) then raise exception 'blocked'; end if;
  if (select count(*) from public.hang_attempts where ip_hash = p_ip and created_at > now() - interval '10 minutes') > 5
  or (select count(*) from public.hang_attempts where ip_hash = p_ip and created_at > now() - interval '24 hours') > 30 then
    raise exception 'rate_limited';
  end if;
  select case when eggs_done then 141 else 91 end into cap from public.trees where id = p_tree for update;
  if not found then raise exception 'tree_not_found'; end if;
  if (select count(*) from public.ornaments where tree_id = p_tree and ip_hash = p_ip) >= 3 then
    raise exception 'too_many_on_tree';
  end if;
  select min(g.s) into used from generate_series(0, cap) g(s)
    where not exists (select 1 from public.ornaments o where o.tree_id = p_tree and o.slot = g.s);
  if used is null or used >= cap then raise exception 'tree_full'; end if;
  insert into public.ornaments (tree_id, slot, kind, color, from_name, message, ip_hash, ip, user_agent)
  values (p_tree, used, p_kind, p_color, nullif(btrim(p_from), ''), btrim(p_message), p_ip, p_ip_raw, left(p_ua, 400));
  return used;
end $$;
revoke execute on function public.hang_insert(uuid, text, smallint, text, text, text, text, text) from public, anon, authenticated;
grant execute on function public.hang_insert(uuid, text, smallint, text, text, text, text, text) to service_role;

-- 後台資料：一次拿全部（資料量小，前端篩選）
create function public.admin_data()
returns json language plpgsql stable security definer set search_path = '' as $$
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  return json_build_object(
    'now', now(),
    'users', (select coalesce(json_agg(x order by x.created_at desc), '[]') from (
      select u.id, u.email, u.created_at, u.last_sign_in_at, u.banned_until,
             u.raw_user_meta_data ->> 'full_name' as name, u.raw_user_meta_data ->> 'avatar_url' as avatar,
             u.raw_app_meta_data ->> 'provider' as provider,
             exists (select 1 from public.admins a where a.user_id = u.id) as is_admin,
             t.id as tree_id, t.name as tree_name,
             (select count(*) from public.ornaments o where o.tree_id = t.id) as orn_count,
             (select count(*) from public.login_log l where l.user_id = u.id) as login_count,
             (select l.ip from public.login_log l where l.user_id = u.id order by l.created_at desc limit 1) as last_ip,
             (select l.user_agent from public.login_log l where l.user_id = u.id order by l.created_at desc limit 1) as last_ua
      from auth.users u left join public.trees t on t.owner = u.id) x),
    'trees', (select coalesce(json_agg(x order by x.created_at desc), '[]') from (
      select t.id, t.name, t.tone, t.top, t.eggs_done, t.created_at, t.owner, u.email as owner_email,
             (select count(*) from public.ornaments o where o.tree_id = t.id) as orn_count,
             (select max(o.created_at) from public.ornaments o where o.tree_id = t.id) as last_orn_at
      from public.trees t left join auth.users u on u.id = t.owner) x),
    'ornaments', (select coalesce(json_agg(x order by x.created_at desc), '[]') from (
      select o.id, o.tree_id, t.name as tree_name, o.slot, o.kind, o.color, o.from_name, o.message,
             o.ip, o.ip_hash, o.user_agent, o.created_at
      from public.ornaments o join public.trees t on t.id = o.tree_id
      order by o.created_at desc limit 5000) x),
    'logins', (select coalesce(json_agg(x order by x.created_at desc), '[]') from (
      select l.id, l.user_id, l.email, l.ip, l.user_agent, l.created_at from public.login_log l order by l.created_at desc limit 5000) x),
    'visitors', (select coalesce(json_agg(x order by x.last_at desc), '[]') from (
      select a.ip_hash, max(a.ip) as ip, count(*) as attempts,
             count(*) filter (where a.created_at > now() - interval '24 hours') as attempts_24h,
             (select count(*) from public.ornaments o where o.ip_hash = a.ip_hash) as ornaments,
             min(a.created_at) as first_at, max(a.created_at) as last_at,
             exists (select 1 from public.blocked b where b.ip = a.ip_hash or b.ip = max(a.ip)) as blocked
      from public.hang_attempts a group by a.ip_hash) x),
    'blocked', (select coalesce(json_agg(b order by b.created_at desc), '[]') from public.blocked b)
  );
end $$;
revoke execute on function public.admin_data() from public, anon;
grant execute on function public.admin_data() to authenticated;

-- 後台操作
create function public.admin_action(p_action text, p_id text, p_extra text default null)
returns void language plpgsql volatile security definer set search_path = '' as $$
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  case p_action
    when 'delete_ornament' then delete from public.ornaments where id = p_id::bigint;
    when 'delete_tree'     then delete from public.trees where id = p_id::uuid;
    when 'eggs_on'         then update public.trees set eggs_done = true where id = p_id::uuid;
    when 'eggs_off'        then update public.trees set eggs_done = false where id = p_id::uuid;
    when 'rename_tree'     then update public.trees set name = left(btrim(p_extra), 30) where id = p_id::uuid and char_length(btrim(p_extra)) between 1 and 30;
    when 'ban_user'        then update auth.users set banned_until = now() + make_interval(days => coalesce(nullif(p_extra, '')::int, 36500))
                                  where id = p_id::uuid and id not in (select user_id from public.admins);
    when 'unban_user'      then update auth.users set banned_until = null where id = p_id::uuid;
    when 'delete_user'     then delete from auth.users where id = p_id::uuid and id not in (select user_id from public.admins);
    when 'block_ip'        then insert into public.blocked (ip, reason) values (p_id, p_extra) on conflict (ip) do nothing;
    when 'unblock'         then delete from public.blocked where id = p_id::bigint;
    when 'clear_attempts'  then delete from public.hang_attempts where ip_hash = p_id;
    else raise exception 'unknown_action';
  end case;
end $$;
revoke execute on function public.admin_action(text, text, text) from public, anon;
grant execute on function public.admin_action(text, text, text) to authenticated;
