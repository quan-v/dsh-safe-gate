// dsh-guard-panel: 装前守门工具的安全配置面板（dsh 插件）
//
// 作用:
//   1. 在 dsh 插件配置面板显示一张 "dsh-guard 守门" 卡片（自动按 Config schema 渲染）。
//   2. 展示守门状态 + 最近的历史拦截日志（读 ~/.dsh-guard/audit.jsonl）。
//   3. 与独立 Python 工具 dsh_guard.py 共享同一份审计数据 —— 插件只是"查看面板"，
//      实际守门逻辑（供应链/契约/源码扫描）由 Python 工具承担。
//
// 与 dsh-mcp-ui 的关系: 这个插件仿照 mcp-ui 的 cordis 配方（name/inject/Config/apply），
// 但 dsh-guard 不是 MCP 服务器 —— 它不挂载任何 MCP 服务器，只展示状态 + 历史。
//
// 命名说明: 插件名用 "dsh-guard-panel"（非 "dsh-guard"），避免与社区市场
// (awesome-dsh-plugin.com) 里已有的同名仓库 dsh-guard 撞车 —— dshmarket 只按
// name 匹配、不看作者，撞名会把社区那条的 GitHub 链接错配到本插件上。

import z from '@deepseek-ai/schemastery'
import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

export const name = 'dsh-guard-panel'
export const inject = ['settings']

// ── settings 段 schema（决定设置卡片的形状，dsh 自动渲染）────────────
export const Config = z.object({
  historySize: z.number().min(5).max(100).default(30), // 卡片里显示的历史条数
  autoAudit: z.boolean().default(true),                // 每次检查是否自动记录审计日志
})

// ── 读审计日志（与 Python 工具共享 ~/.dsh-guard/audit.jsonl）────────
function auditPath() {
  // Windows: %USERPROFILE%\.dsh-guard\audit.jsonl ; *nix: ~/.dsh-guard/audit.jsonl
  // 注意：数据目录名保持 "dsh-guard"（Python 工具也写这里），与插件名无关。
  const base = process.env.DSH_GUARD_LOG
  if (base) return base
  return join(homedir(), '.dsh-guard', 'audit.jsonl')
}

function readAudit(size) {
  const p = auditPath()
  let entries = []
  try {
    const raw = readFileSync(p, 'utf-8')
    entries = raw.split('\n').filter(Boolean).map((l) => {
      try { return JSON.parse(l) } catch { return null }
    }).filter(Boolean)
    // 倒序：最新在前
    entries.reverse()
  } catch {
    // 无日志文件 —— 返回空
  }
  return entries.slice(0, size)
}

// 最近一次检查结论
function lastVerdict(entries) {
  for (const e of entries) {
    if (e.verdict) return e
  }
  return null
}

// ── 插件逻辑：注册设置命名空间 + 暴露给设置界面 ─────────────────────
export const apply = (ctx) => {
  const NS = 'dsh-guard-panel'
  // 注册命名空间（settings 服务注入）。卡片自动按 Config 渲染，无需写 HTML。
  let scope
  try {
    scope = ctx.settings.register(NS, Config, {})
  } catch (error) {
    ctx.logger?.warn?.(`${NS}: 注册设置命名空间失败: ${String(error)}`)
    return
  }

  // 读已保存配置 + 计算初始摘要
  let historySize = 30
  try {
    const resolved = scope.get()
    historySize = (resolved && resolved.historySize) || 30
  } catch (error) {
    ctx.logger?.warn?.(`${NS}: 读取配置失败: ${String(error)}`)
  }

  const entries = readAudit(historySize)
  const last = lastVerdict(entries)
  ctx.logger?.info?.(`${NS}: 面板已就绪, 历史日志 ${entries.length} 条, 最近: ${last ? last.verdict + ' ' + (last.target || '') : '(暂无)'}`)

  // 暴露给浏览器设置界面（apiproxy 的 exposedNamespaces 需放行这个 namespace）
  try {
    if (ctx.llm && typeof ctx.llm.registerConfigurableProviders === 'function') {
      ctx.llm.registerConfigurableProviders([
        {
          provider: NS,
          displayName: 'dsh-guard 守门',
          settingsNs: NS,
          settingsPath: [],
        },
      ])
      ctx.logger?.info?.(`${NS}: 已注册配置命名空间 (暴露给设置界面)`)
    }
  } catch (error) {
    ctx.logger?.warn?.(`${NS}: 注册配置命名空间失败: ${String(error)}`)
  }

  // 订阅变化：用户在设置卡片保存后自动同步（免重启）
  scope.watch((next) => {
    const size = (next && next.historySize) || 30
    const e = readAudit(size)
    ctx.logger?.info?.(`${NS}: 配置已更新, 历史 ${e.length} 条`)
  })
}
