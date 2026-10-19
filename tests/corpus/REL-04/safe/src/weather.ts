export async function weather(city: string) {
  const res = await fetch(`https://api.example.com/w?q=${encodeURIComponent(city)}`, { signal: AbortSignal.timeout(5000) });
  return res.json();
}
