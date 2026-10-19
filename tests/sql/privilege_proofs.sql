-- Proof, against a real PostgreSQL, that each SQL rule describes a real vulnerability
-- and that its documented fix closes it. Run by TestPostgresPrivilegeRulesAgainstARealDatabase.
--
-- Emulates only what the rules depend on: Supabase-style anon / authenticated API roles,
-- an auth schema with auth.uid() / auth.jwt() reading the request's JWT claims, and
-- explicit grants. Every result is printed as a NOTICE `KEY=value` for the test to read.
\set ON_ERROR_STOP on
set client_min_messages = notice;
create role anon nologin;
create role authenticated nologin;
create role attacker login;
create schema auth;
create table auth.users (id uuid primary key, email text);
insert into auth.users values ('11111111-1111-1111-1111-111111111111', 'alice@corp.example'),
                              ('22222222-2222-2222-2222-222222222222', 'bob@corp.example');
create function auth.jwt() returns jsonb language sql stable as
  $$ select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb $$;
create function auth.uid() returns uuid language sql stable as $$ select (auth.jwt()->>'sub')::uuid $$;
grant usage on schema auth to anon, authenticated;
grant execute on all functions in schema auth to anon, authenticated;
grant usage on schema public to anon, authenticated, attacker;
create function public.report(k text, v text) returns void language plpgsql as
  $$ begin raise notice '%=%', k, v; end $$;
grant execute on function public.report(text, text) to public;

-- SEC-19: a public view over auth.users, queried with nothing but the anon role.
create view public.user_emails as select email from auth.users;
create view public.user_emails_safe with (security_invoker = true) as select email from auth.users;
grant select on public.user_emails, public.user_emails_safe to anon;
set role anon;
select public.report('SEC19_VULNERABLE_ROWS', (select count(*)::text from public.user_emails));
do $$ begin
  perform count(*) from public.user_emails_safe;
  perform public.report('SEC19_FIXED', 'readable');
exception when insufficient_privilege then
  perform public.report('SEC19_FIXED', 'denied');
end $$;
reset role;

-- SEC-20: a plain view over a table whose RLS lets each user see only their own rows.
create table public.notes (owner_id uuid, body text);
alter table public.notes enable row level security;
create policy own_notes on public.notes for select using (owner_id = auth.uid());
insert into public.notes values ('11111111-1111-1111-1111-111111111111', 'alice'),
                                ('22222222-2222-2222-2222-222222222222', 'bob');
create view public.all_notes as select * from public.notes;
create view public.all_notes_safe with (security_invoker = true) as select * from public.notes;
grant select on public.notes, public.all_notes, public.all_notes_safe to authenticated;
set role authenticated;
select set_config('request.jwt.claims', '{"sub":"11111111-1111-1111-1111-111111111111"}', false);
select public.report('SEC20_TABLE_ROWS', (select count(*)::text from public.notes));
select public.report('SEC20_VULNERABLE_ROWS', (select count(*)::text from public.all_notes));
select public.report('SEC20_FIXED_ROWS', (select count(*)::text from public.all_notes_safe));
reset role;

-- SEC-21: a policy that reads a role from user-editable metadata.
create table public.admin_reports (body text);
alter table public.admin_reports enable row level security;
insert into public.admin_reports values ('payroll');
grant select on public.admin_reports to authenticated;
create policy meta_admin on public.admin_reports for select
  using (auth.jwt() -> 'user_metadata' ->> 'role' = 'admin');
set role authenticated;
-- The claims an ordinary user ends up with after editing their own user_metadata.
select set_config('request.jwt.claims',
  '{"sub":"22222222-2222-2222-2222-222222222222","user_metadata":{"role":"admin"}}', false);
select public.report('SEC21_VULNERABLE_ROWS', (select count(*)::text from public.admin_reports));
reset role;
drop policy meta_admin on public.admin_reports;
create policy app_admin on public.admin_reports for select
  using (auth.jwt() -> 'app_metadata' ->> 'role' = 'admin');
set role authenticated;
select public.report('SEC21_FIXED_ROWS', (select count(*)::text from public.admin_reports));
reset role;

-- SEC-18: SECURITY DEFINER with a search_path the caller controls.
create table public.audit (msg text);
create function public.write_audit(m text) returns void language sql as $$ insert into public.audit values (m) $$;
create function public.record_event(m text) returns void language plpgsql security definer as
  $$ begin perform write_audit(m); end $$;
create function public.record_event_safe(m text) returns void language plpgsql security definer
  set search_path = '' as $$ begin perform public.write_audit(m); end $$;
grant execute on function public.record_event(text), public.record_event_safe(text) to attacker;
create schema evil authorization attacker;
set role attacker;
create function evil.write_audit(m text) returns void language plpgsql as
  $$ begin execute 'alter role attacker superuser'; end $$;
set search_path = evil, public;
select public.record_event_safe('x');
select public.report('SEC18_FIXED_SUPERUSER', (select rolsuper::text from pg_catalog.pg_roles where rolname = 'attacker'));
select public.record_event('x');
select public.report('SEC18_VULNERABLE_SUPERUSER', (select rolsuper::text from pg_catalog.pg_roles where rolname = 'attacker'));
