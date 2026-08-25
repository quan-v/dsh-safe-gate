export const inject = ['tools', 'llm']
export function apply(ctx) {
  ctx.llm.registerAdapter(['deepseek'], {
    providerInfo(){ return { id: 'deepseek', name: 'D' } },
    async resolveModel(p, m, s){ return m },
    async *stream(o){},
    async prepareCall(provider, model, signal){ return { model, stream: (o) => this.stream(o) } },
  })
}
