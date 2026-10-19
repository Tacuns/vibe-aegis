export async function POST(req: Request) {
  const session = await auth();
  const { prompt } = await req.json();
  return openai.chat.completions.create({ model: 'gpt-4o-mini', messages: [{ role: 'user', content: prompt }] });
}
