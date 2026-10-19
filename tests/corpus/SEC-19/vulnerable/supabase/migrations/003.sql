create view public.user_emails as select id, email from auth.users;
grant select on public.user_emails to anon;
