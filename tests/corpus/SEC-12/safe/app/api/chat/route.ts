export async function POST(req: Request) {
  const session = await auth();
  const { prompt } = await req.json();
  return openai.chat.completions.create({ model: 'gpt-4o-mini', max_tokens: 512, messages: [{ role: 'user', content: prompt }] });
}
