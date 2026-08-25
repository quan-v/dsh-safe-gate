export const inject = ['tools', 'settings', 'llm']
export async function apply(ctx) {
  const data = await ctx.settings.get()
  ctx.slots.register({ name: 'settings.plugin.item', key: 'mcp-ui', id: 'mcp-ui', order: 40 }, Card)
}
