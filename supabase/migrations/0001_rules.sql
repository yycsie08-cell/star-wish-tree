-- 星願樹 資料庫規則
-- 1. 一個 Google 帳號只能種一棵樹（trees.owner 唯一）
-- 2. 朋友留言不用登入，但只能透過 Edge Function「hang」寫入（有驗證碼、限流）
-- 3. 祝福內容在 2026-12-25 00:00（台灣時間）以前，誰都讀不到，連樹主也不行
-- 4. 祝福只有樹主自己讀得到；別人只看得到吊飾樣子和署名
-- 5. 一棵樹基本 91 個位置，樹主找齊 6 個彩蛋後多 50 個（共 141）

create table public.trees (
  id         uuid primary key default gen_random_uuid(),
  owner      uuid not null unique references auth.users(id) on delete cascade,
  name       text not null check (char_length(btrim(name)) between 1 and 30),
  tone       smallint not null default 0 check (tone between 0 and 9),
  top        text not null default 'star' check (top ~ '^[a-z0-9_]{1,20}$'),
  eggs_done  boolean not null default false,
  created_at timestamptz not null default now()
);

create table public.ornaments (
  id         bigint generated always as identity primary key,
  tree_id    uuid not null references public.trees(id) on delete cascade,
  slot       smallint not null check (slot between 0 and 140),
  kind       text not null check (kind ~ '^[a-z0-9_]{1,40}$'),
  color      smallint not null default -1 check (color between -1 and 7),
  from_name  text check (from_name is null or char_length(from_name) <= 20),
  message    text not null check (char_length(btrim(message)) between 1 and 200),
  ip_hash    text not null,
  created_at timestamptz not null default now(),
  unique (tree_id, slot)
);
create index ornaments_ip_time on public.ornaments (ip_hash, created_at);
create index ornaments_tree on public.ornaments (tree_id);

-- 限流紀錄（由 hang_note 寫入，見 0002）
create table public.hang_attempts (
  id         bigint generated always as identity primary key,
  ip_hash    text not null,
  created_at timestamptz not null default now()
);
create index hang_attempts_ip_time on public.hang_attempts (ip_hash, created_at);

alter table public.trees         enable row level security;
alter table public.ornaments     enable row level security;
alter table public.hang_attempts enable row level security;

-- trees：任何人可以看樹（名字、顏色、樹頂）；登入的人只能建立「自己的」一棵
create policy trees_read   on public.trees for select using (true);
create policy trees_insert on public.trees for insert to authenticated with check (owner = (select auth.uid()));
create policy trees_update on public.trees for update to authenticated using (owner = (select auth.uid())) with check (owner = (select auth.uid()));
revoke insert, update on public.trees from anon;
revoke update on public.trees from authenticated;
grant  update (name, tone, top) on public.trees to authenticated;   -- 只能改這三欄，eggs_done 要走 claim_eggs()

-- ornaments / hang_attempts：前端完全不能直接讀寫，只能走下面的函式
revoke all on public.ornaments     from anon, authenticated;
revoke all on public.hang_attempts from anon, authenticated;

-- 公開：看一棵樹上的吊飾（不含祝福內容）
create function public.tree_ornaments(t uuid)
returns table (slot smallint, kind text, color smallint, from_name text, created_at timestamptz)
language sql stable security definer set search_path = '' as $$
  select o.slot, o.kind, o.color, o.from_name, o.created_at
  from public.ornaments o where o.tree_id = t order by o.slot;
$$;
grant execute on function public.tree_ornaments(uuid) to anon, authenticated;

-- 樹主：讀自己樹上的祝福，12/25 之前回傳空的
create function public.my_messages()
returns table (slot smallint, kind text, color smallint, from_name text, message text, created_at timestamptz)
language sql stable security definer set search_path = '' as $$
  select o.slot, o.kind, o.color, o.from_name, o.message, o.created_at
  from public.ornaments o join public.trees tr on tr.id = o.tree_id
  where tr.owner = (select auth.uid())
    and now() >= timestamptz '2026-12-25 00:00:00+08'
  order by o.slot;
$$;
revoke execute on function public.my_messages() from public, anon;
grant  execute on function public.my_messages() to authenticated;

-- 樹主：找齊彩蛋，樹多 50 個位置
create function public.claim_eggs()
returns void language sql volatile security definer set search_path = '' as $$
  update public.trees set eggs_done = true where owner = (select auth.uid());
$$;
revoke execute on function public.claim_eggs() from public, anon;
grant  execute on function public.claim_eggs() to authenticated;

-- 掛吊飾（只給 Edge Function 用 service_role 呼叫）
-- 限流：同一個 IP 10 分鐘最多 5 次、24 小時最多 30 次；同一個 IP 在同一棵樹最多掛 3 個
create function public.hang_insert(p_tree uuid, p_kind text, p_color smallint, p_from text, p_message text, p_ip text)
returns smallint language plpgsql volatile security definer set search_path = '' as $$
declare cap int; used int;
begin
  insert into public.hang_attempts (ip_hash) values (p_ip);
  if (select count(*) from public.hang_attempts where ip_hash = p_ip and created_at > now() - interval '10 minutes') > 5
  or (select count(*) from public.hang_attempts where ip_hash = p_ip and created_at > now() - interval '24 hours') > 30 then
    raise exception 'rate_limited';
  end if;
  select case when eggs_done then 141 else 91 end into cap from public.trees where id = p_tree for update;
  if not found then raise exception 'tree_not_found'; end if;
  if (select count(*) from public.ornaments where tree_id = p_tree and ip_hash = p_ip) >= 3 then
    raise exception 'too_many_on_tree';
  end if;
  select count(*) into used from public.ornaments where tree_id = p_tree;
  if used >= cap then raise exception 'tree_full'; end if;
  insert into public.ornaments (tree_id, slot, kind, color, from_name, message, ip_hash)
  values (p_tree, used, p_kind, p_color, nullif(btrim(p_from), ''), btrim(p_message), p_ip);
  return used;
end $$;
revoke execute on function public.hang_insert(uuid, text, smallint, text, text, text) from public, anon, authenticated;
grant  execute on function public.hang_insert(uuid, text, smallint, text, text, text) to service_role;
