-- 人機驗證（工作量證明）：每道題目只能用一次
create table public.used_challenges (
  sig        text primary key,
  created_at timestamptz not null default now()
);
alter table public.used_challenges enable row level security;
revoke all on public.used_challenges from anon, authenticated;

-- 順便清掉舊紀錄
create or replace function public.hang_note(p_ip text)
returns void language sql volatile security definer set search_path = '' as $$
  delete from public.hang_attempts where created_at < now() - interval '2 days';
  delete from public.used_challenges where created_at < now() - interval '1 day';
  insert into public.hang_attempts (ip_hash) values (p_ip);
$$;
