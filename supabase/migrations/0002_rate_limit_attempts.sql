-- 修正：嘗試紀錄要在 hang_insert 之外先寫，被擋下的嘗試才會算進限流
create function public.hang_note(p_ip text)
returns void language sql volatile security definer set search_path = '' as $$
  delete from public.hang_attempts where created_at < now() - interval '2 days';
  insert into public.hang_attempts (ip_hash) values (p_ip);
$$;
revoke execute on function public.hang_note(text) from public, anon, authenticated;
grant  execute on function public.hang_note(text) to service_role;
-- hang_insert 改成不再自己寫 hang_attempts（其他規則不變）
