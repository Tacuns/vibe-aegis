create function public.grant_admin(u uuid) returns void language plpgsql security definer as $$
begin update public.profiles set role = 'admin' where id = u; end $$;
