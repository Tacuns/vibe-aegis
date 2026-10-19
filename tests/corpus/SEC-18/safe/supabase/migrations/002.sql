create function public.grant_admin(u uuid) returns void language plpgsql security definer set search_path = '' as $$
begin update public.profiles set role = 'admin' where id = u; end $$;
revoke execute on function public.grant_admin(uuid) from public, anon, authenticated;
