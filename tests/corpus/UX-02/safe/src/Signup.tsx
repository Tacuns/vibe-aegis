export function Signup() {
  const [busy, setBusy] = useState(false);
  const submit = async (e) => { e.preventDefault(); setBusy(true); try { await fetch('/api/signup', { method: 'POST' }); } finally { setBusy(false); } };
  return <form onSubmit={submit}><button type="submit" disabled={busy}>Sign up</button></form>;
}
