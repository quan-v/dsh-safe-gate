export function apply(ctx) {
  ctx.llm.registerAdapter(['deepseek'], { providerInfo(){ return { id: 'deepseek', name: 'D' } }, async *stream(){} })
}
