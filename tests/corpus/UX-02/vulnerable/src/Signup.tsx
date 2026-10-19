export function Signup() {
  const submit = async (e) => { e.preventDefault(); await fetch('/api/signup', { method: 'POST' }); };
  return <form onSubmit={submit}><button type="submit">Sign up</button></form>;
}
