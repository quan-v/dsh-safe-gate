// dsh-guard-panel browser half: 设置 > 插件 > 插件配置 > dsh-guard 守门 card.
// 复用 dsh 宿主 PluginCard 的样式 token（镜像 mcp-ui 的 mu-* 类名），
// 让它拥有和内置插件卡片一致的"框"（border + background + border-radius）。
// 自包含实现：window.__ModuleLoader__.load + React.createElement（非 JSX）。
// 守门逻辑在独立 Python 工具 dsh_guard.py；本插件只做"查看面板"。
window.__ModuleLoader__.load({
  id: 'dsh-guard-panel',
  factory: (require) => {
    const module = { exports: {} }
    const exports = module.exports
    Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' })
    const React = require('react')
    const { useState, useMemo } = React
    const h = React.createElement

    const NS = 'dsh-guard-panel'

    // ── 界面文案（中/英）───────────────────────
    const zh = {
      nav: 'dsh-guard 守门',
      desc: '装前守门工具的安全面板：查看守门状态与历史拦截日志。',
      autoAuditLabel: '自动记录审计日志',
      countLabel: '历史显示条数',
      current: '当前配置：',
      noLog: '还没有历史记录 — 先跑一次 dsh-guard check。',
      open: '展开历史',
      collapse: '收起',
    }
    const en = {
      nav: 'dsh-guard',
      desc: 'Pre-flight safety panel: guard status & block history.',
      autoAuditLabel: 'Auto-audit',
      countLabel: 'History size',
      current: 'Config: ',
      noLog: 'No history yet — run dsh-guard check first.',
      open: 'Expand history',
      collapse: 'Collapse',
    }
    const t = (k) => (window.__dsl__ === 'en' ? en : zh)[k] ?? k

    // ── 卡片样式：镜像宿主 PluginCard（mu-card 同款，含完整"框"）────────
    const CSS =
      '.dg-card{border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-3);border-radius:12px;list-style:none;transition:border-color .16s,background .16s}' +
      '.dg-card:hover{border-color:var(--dsw-alias-label-dimmed)}' +
      '.dg-card-open{background:var(--dsw-alias-bg-layer-2);border-color:var(--dsw-alias-label-dimmed)}' +
      '.dg-header{appearance:none;width:100%;font:inherit;color:inherit;text-align:left;cursor:pointer;background:0 0;border:0;border-radius:12px;align-items:center;gap:12px;padding:14px 16px;display:flex}' +
      '.dg-header:focus-visible{outline:2px solid var(--dsw-alias-brand-primary);outline-offset:-2px}' +
      '.dg-headText{flex-direction:column;flex:1;gap:4px;min-width:0;display:flex}' +
      '.dg-name{color:var(--dsw-alias-label-primary);font-size:15px;font-weight:600;line-height:1.4}' +
      '.dg-desc{color:var(--dsw-alias-label-tertiary);font-size:13px;line-height:1.5}' +
      '.dg-chevron{color:var(--dsw-alias-label-tertiary);flex:none;transition:transform .16s;font-size:12px;line-height:1}' +
      '.dg-chevron-open{transform:rotate(180deg)}' +
      '.dg-body{border-top:1px solid var(--dsw-alias-border-l2);margin:0 16px;padding:12px 16px 8px}' +
      '.dg-field{flex-direction:column;gap:6px;padding:10px 0;display:flex}' +
      '.dg-label{color:var(--dsw-alias-label-primary);font-size:13px;font-weight:500;line-height:1.5}' +
      '.dg-check{accent-color:var(--dsw-alias-brand-primary);cursor:pointer}' +
      '.dg-hint{color:var(--dsw-alias-label-tertiary);margin:0;font-size:12px;line-height:1.5}' +
      '.dg-empty{color:var(--dsw-alias-label-tertiary);margin:12px 0 0;font-size:13px;line-height:1.5}' +
      '.dg-row{display:flex;gap:10px;align-items:center;padding:6px 0;border-bottom:1px solid var(--dsw-alias-border-l2);font-size:12px}' +
      '.dg-tag{border-radius:999px;padding:1px 8px;font-size:11px;font-weight:500;line-height:17px;white-space:nowrap}' +
      '.dg-tag-block{background:var(--dsw-alias-bg-module-platform);color:var(--dsw-alias-label-error)}' +
      '.dg-tag-warn{background:var(--dsw-alias-bg-module-platform);color:var(--dsw-alias-label-warn)}' +
      '.dg-tag-allow{background:var(--dsw-alias-bg-module-platform);color:var(--dsw-alias-label-ok)}' +
      '.dg-time{color:var(--dsw-alias-label-tertiary);flex:none}' +
      '.dg-target{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--dsw-alias-label-primary)}'

    function installStyles() {
      if (typeof document === 'undefined') return
      const tagId = 'dsh-guard-panel'
      if (document.querySelector('style[data-plugin-css="' + tagId + '"]') !== null) return
      const tag = document.createElement('style')
      tag.dataset.plugin = 'dsh-guard-panel'
      tag.dataset.pluginCss = tagId
      tag.textContent = CSS
      document.head.appendChild(tag)
    }

    // 卡片主体
    function GuardCard({ scope }) {
      const [open, setOpen] = useState(false)
      const src = useMemo(() => (scope && scope.get) ? scope.get() : {}, [scope])
      const size = src.historySize ?? 30
      const autoAudit = src.autoAudit !== false
      const entries = (src.history && Array.isArray(src.history)) ? src.history : []

      return h('div', { className: 'dg-card' + (open ? ' dg-card-open' : '') },
        h('button', {
          type: 'button',
          className: 'dg-header',
          onClick: () => setOpen(!open),
          'aria-expanded': open,
        },
          h('span', { className: 'dg-headText' },
            h('span', { className: 'dg-name' }, t('nav')),
            h('span', { className: 'dg-desc' }, t('desc')),
          ),
          h('span', { className: 'dg-chevron' + (open ? ' dg-chevron-open' : '') }, '▼'),
        ),
        open
          ? h('div', { className: 'dg-body' },
              h('label', { className: 'dg-field', style: { flexDirection: 'row', alignItems: 'center', gap: 8 } },
                h('input', { type: 'checkbox', className: 'dg-check', checked: autoAudit, readOnly: true }),
                h('span', {}, t('autoAuditLabel')),
              ),
              h('div', { className: 'dg-hint' }, t('current') + t('countLabel') + ': ' + size),
              entries.length === 0
                ? h('p', { className: 'dg-empty' }, t('noLog'))
                : entries.map((e, i) =>
                    h('div', { className: 'dg-row', key: i },
                      h('span', { className: 'dg-time' }, String(e.ts || '')),
                      h('span', { className: 'dg-tag dg-tag-' + (e.verdict === 'block' ? 'block' : e.verdict === 'warn' ? 'warn' : 'allow') }, (e.verdict || '').toUpperCase()),
                      h('span', { className: 'dg-target' }, String(e.target || '')),
                    ),
                  ),
            )
          : null,
      )
    }

    function apply(ctx) {
      const scope = ctx.settingsScope && ctx.settingsScope.bind ? ctx.settingsScope.bind({ namespace: NS }) : null
      ctx.effect(installStyles, 'dsh-guard-panel: card styles')
      ctx.effect(
        () =>
          ctx.slots.inject('settings.plugin.item', function* () {
            yield ctx.slots.register(
              {
                name: 'settings.plugin.item',
                key: NS,
                id: NS,
                order: 45,
                label: () => t('nav'),
                inject: () => ({ scope, t }),
              },
              GuardCard,
            )
          }),
        'dsh-guard-panel: settings card',
      )
    }

    exports.apply = apply
    exports.inject = ['settingsScope', 'slots', 'locale']
    return module.exports
  },
})
