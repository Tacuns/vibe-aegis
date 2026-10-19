export function Bio({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
