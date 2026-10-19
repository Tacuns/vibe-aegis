create policy "admins read all" on public.reports for select to authenticated
  using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');
