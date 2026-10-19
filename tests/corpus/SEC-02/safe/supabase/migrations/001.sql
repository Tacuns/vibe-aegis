create policy "own notes" on public.notes for all using (auth.uid() = user_id);
