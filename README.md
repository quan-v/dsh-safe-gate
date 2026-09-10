# dsh-guard

**装前守门工具** —— 给 [DeepSeek Harness](https://github.com/deepseek-ai/dsh) 插件 / MCP 服务器在做安装、运行**之前**把一关。

> **[English README](./README.en.md)**
>
> 命名说明：仓库名是 dsh-safe-gate，工具/命令名是 dsh-guard —— 同一个项目。git+ 安装 URL 用仓库名，命令行用 dsh-guard。

它不替你做决定，但在你（或你的 agent）装东西**之前**，用两套检查提前拦雷：**供应链**（这个包是不是已知投毒/坏版本）和**契约**（这个插件代码会不会让 dsh 加载就崩）。

## 它能干什么

| 检查类型 | 拦什么 | 判定 |
|---|---|---|
| **供应链** | 查 [OSV.dev](https://osv.dev)（免费，含 `MAL-*` 恶意软件命名空间）确认 npm 包是否已知恶意/脆弱；版本未 pinning 也提示 | `block` / `warn` / `allow` |
| **契约** | 静态检查会让 dsh 加载失败的模式：非 async 函数里的 `await`、`inject` 服务不在白名单、keyed slot 缺 `key`、adapter 缺 `prepareCall` | error / warn |
| **源码敌意** | 扫插件源码里的危险行为：投毒标记、`child_process`/`eval`/读密钥、外传/窃密组合、持久化后门 | block / warn |
| **版本跳变** | 自更新时检测大版本跳变（`0.x` 感知），提前预警破坏性更新 | warn |

### 守门判定逻辑（分档严重度）

**单一高危信号也报，良性不打扰** —— 这是"准确"的关键，避免 warn 疲劳：

- 🔴 `block`：投毒/外传标记（`kitty-monitor`、`harkonnen`、`melange`、`/bin/sh -c`…）
- 🟡 `warn`（单独）：高危单一信号（`child_process.exec`、`eval`、读具体密钥）
- 🟡 `warn`（组合）：读密钥+联网 / shell+联网（中危，良性单独出现不报）
- ✅ 忽略：真良性（`setInterval`、裸 `fetch`、泛 `process.env`）

## 安装

不碰 npm、也不需要 PyPI 账号。三种方式任选：

```bash
# 方式一：从 GitHub 直接跑（推荐，无需安装任何账号；@v0.1.0 锁定版本 —— 守门工具自己也不许 main 漂移）
uvx "dsh-guard @ git+https://github.com/quan-v/dsh-safe-gate.git@v0.1.0"

# 方式二：pip 从 GitHub 直接装
pip install "git+https://github.com/quan-v/dsh-safe-gate.git@v0.1.0"

# 方式三：克隆下来直接跑（零依赖安装，最透明）
git clone https://github.com/quan-v/dsh-safe-gate.git
cd dsh-safe-gate && git checkout v0.1.0 && python dsh_guard.py check "@antv/mcp-server-chart@0.11.10"
```

> 说明：本项目未发布到 PyPI（作者无 PyPI 账号），所以不走 `pip install dsh-guard`。上面三个方式都能用，`uvx` 或 `pip install git+` 最省事，克隆最透明。核心逻辑零依赖（除可选的 tree-sitter），也能当单文件直接跑。

## 用法

```bash
# 供应链（block / warn / allow）
dsh-guard check "@antv/mcp-server-chart@0.11.10"   # → BLOCK（MAL-2026-4069）
dsh-guard check "@antv/mcp-server-chart"            # → WARN（未 pinning）
dsh-guard check "@antv/mcp-server-chart@0.9.10"     # → ALLOW

# 契约（本地插件文件，server / client 分半）
dsh-guard check-file ./my-plugin/index.js           # server 半
dsh-guard check-file ./my-plugin/client.js --client # client 半

# 源码敌意扫描
dsh-guard scan ./my-plugin/

# 一起查
dsh-guard all "@antv/mcp-server-chart@0.11.10" ./my-plugin/index.js

# 守门后放行（检查通过才执行 delegate）
dsh-guard safe-add "@antv/mcp-server-chart@0.9.10" --path ./my-plugin/index.js --delegate "dsh plugin add ..."

# 审计日志（每次检查留证据链 → ~/.dsh-guard/audit.jsonl）
dsh-guard log [-n 10] [--grep 关键词]

# 自更新（快照 → diff → 大跳变预警）
dsh-guard update-guard [--exec "更新命令"]

# 可视化 consent 卡片（本地网页）
dsh-guard ui [--port 8170]
```

任意命令加 `--json` → 机器可读输出。

## 作为 MCP 工具接入 dsh

```bash
dsh mcp add dsh-guard -- uvx "dsh-guard @ git+https://github.com/quan-v/dsh-safe-gate.git@v0.1.0" --mcp
```
dsh 的 agent 就能调用 `dsh_guard_check` 工具 —— 装任何插件/MCP 服务器前先问它。

## dsh 插件（安全配置面板）

除了命令行，还有一张嵌进 dsh 插件配置面板的卡片（`dsh-guard-panel`），显示守门状态和历史拦截日志。守门逻辑仍由 Python 工具承担，插件只做"查看面板"。要安装时用 `dsh plugin --profile web add`（本地 `file:` 方式）。

## 审计日志

每次检查的结论（时间 / 命令 / 目标 / verdict）都记到 `~/.dsh-guard/audit.jsonl`，用 `dsh-guard log` 查看，留证据链。

## 平台

**tested on Windows；cross-platform by design。** 需要 Python ≥ 3.9；`node --check` 需要 Node ≥ 18（可选，通过 `shutil.which("node")` 解析）。

## 性能边界（为什么它不是杀毒软件）

dsh-guard 是**决策点闸门**，不是常驻杀毒守卫：

- **只在"装/跑"这一动作时查一次，查完即退，零后台占用**。
- 本地扫描实测 <150ms / 文件；那 ~5s 是网络（OSV/npm），仅装包时偶尔一次。
- **不做**：文件系统实时监视、on-access 钩子、后台常驻守护进程、全盘/整 node_modules 重扫。
- 代价：按需 = 便宜但**不自动**（agent 要调才扫）——这是有意的取舍。

## 已知局限（诚实）

- **只认"已知"告警**：OSV 查的是已收录的通告；冷门/刚冒头/未收录的恶意包查不到。
- **不做行为级沙箱**：它不是隔离器，包跑起来干坏事它也管不了（dsh 的执行层沙箱管那个）。
- **半强制**：作为 MCP 工具时靠 agent 守规矩调用；作为 `check` 命令靠你自己调。要"绕不过去"需要 PATH 劫持或 fork dsh 插件（本文不承诺）。
- **契约检查是启发式**：用 tree-sitter / 正则抓常见模式，可能漏复杂变体。

## 为什么做成外部工具（而非 dsh 插件本体）

守门的不该住进被守的东西里 —— 一个靠供应链分发的供应链守卫，本身就是自毁。核心逻辑是独立 Python 包；dsh 插件只是调用它的薄触发层。

## License

MIT。参考了 [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent)（MIT, © 2025 Nous Research）的设计。

> **免责声明**：本工具是"已知威胁守门"，不是绝对防护。安全没有银弹 —— 别因为装了它就对任何包盲目放行。

---

## 作者声明

我是一个**不深谙编程**的 dsh 用户。这个工具的检查逻辑**通过了自动化测试**（见上方各命令及测试章节），但——

**我本人并不清楚它在真实场景里究竟有几分用处。**

它可能真拦住了投毒包，也可能有漏网、有误报。我只是知道「装东西前多问一句」比「直接装」更稳，**但没法担保效果**。

**请务必自行验证后再依赖它。** 别因为作者写了这堆测试通过，就以为它万无一失 —— 那反而是我写这段想拦住的事。

> 如果你用下来发现它有误报、有漏网、有哪里不对，欢迎提 issue 指正。我是外行，你说的可能就是我没看到的问题。

