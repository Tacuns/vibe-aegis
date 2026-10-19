-- Builds the database TestLiveDatabaseCheck.test_against_a_real_database expects
-- (it scans the schemas public and nousage).
-- Run it on a throwaway PostgreSQL 15+ instance, then:
--   AEGIS_TEST_DATABASE_URL=postgresql://user:pass@host:port/db python3 -m unittest \
--       tests.test_scanner.TestLiveDatabaseCheck
-- Roles mirror Supabase's API roles.
create role anon nologin;
create role authenticated nologin;

-- DB-01: reachable by the API roles with row-level security off
create table public.open_notes (id int, body text);
grant select, insert on public.open_notes to anon, authenticated;

-- DB-02: RLS on, but a policy that allows every row
create table public.rls_true (id int);
alter table public.rls_true enable row level security;
create policy "all" on public.rls_true for select to anon using (true);
grant select on public.rls_true to anon;

-- Correct: an owner-scoped policy (silent) ...
create table public.rls_ok (id int, owner uuid);
alter table public.rls_ok enable row level security;
create policy "own" on public.rls_ok for select to authenticated using (owner = gen_random_uuid());
grant select on public.rls_ok to authenticated;
-- ... next to an insert policy WITH CHECK (true) for public (DB-02)
create policy "pub_true" on public.rls_ok for insert to public with check (true);
-- Silent: a RESTRICTIVE policy can only narrow access, even with `true`
create policy "narrow" on public.rls_ok as restrictive for select to anon using (true);

-- Silent: RLS off but no API role can reach it, and a schema the API does not expose
create table public.no_grants (id int);
create schema private;
create table private.secret (id int);
-- Silent: a table grant without USAGE on its schema is unusable (scanned as "nousage")
create schema nousage;
create table nousage.granted (id int);
grant select on nousage.granted to anon;

-- DB-03: a view that runs with its owner's rights; the invoker view is silent
create view public.v_definer as select * from public.rls_ok;
grant select on public.v_definer to anon;
create view public.v_invoker with (security_invoker = true) as select * from public.rls_ok;
grant select on public.v_invoker to anon;
