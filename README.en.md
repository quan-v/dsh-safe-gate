# dsh-safe-gate

**Pre-flight safety gate** for [DeepSeek Harness](https://github.com/deepseek-ai/dsh) plugins / MCP servers. It checks a package or plugin **before** you install or run it, so you (or your agent) catch a problem early instead of after it's already in your setup.

It doesn't decide for you — it gives you three checks up front:

1. **Supply chain** — is this npm package known-malicious or vulnerable? (queries [OSV.dev](https://osv.dev), free, includes the `MAL-*` malware namespace, and flags versions that aren't pinned)
2. **Plugin contract** — will this plugin code actually load in dsh, or does it hit a known breaking pattern?
3. **Source hostility** — does the code do anything dangerous on your machine (secret reads, shell+network combos, persistence)?

## Features

| Check | What it catches | Verdict |
|---|---|---|
| **Supply chain** | Known-malicious/vulnerable npm packages (OSV/MAL-*); unpinned versions | `block` / `warn` / `allow` |
| **Contract** | Patterns that make dsh fail at load: `await` in a non-async function, an `inject` service outside the whitelist, a keyed slot missing `key`, an adapter missing `prepareCall` | error / warn |
| **Source hostility** | Dangerous behavior in plugin source: malware markers, `eval` / secret reads, exfil and credential combos, persistence backdoors, plus the `child_process` forms that **actually go through a shell** (`exec`/`execSync`; `spawn` is reported only when it launches a shell itself (`bash -c`) or an exfil tool (`curl`/`wget`) — plain `spawn`/`execFile` is normal plugin behavior and stays quiet) | block / warn |
| **Version jump** | Large version jumps on self-update (`0.x`-aware), warn before a breaking update. **Runs only in `update-guard`, not in the pre-install gate.** | warn |

### Verdict logic (tiered severity)

**Single high-signal signals are reported; benign patterns are left alone** — this is what keeps it accurate without causing alert fatigue:

- 🔴 `block`: malware / exfil markers (`kitty-monitor`, `harkonnen`, `melange`, `/bin/sh -c`…)
- 🟡 `warn` (alone): high-risk single signals (`child_process.exec`, `eval`, reading secrets)
- 🟡 `warn` (combo): secret+network / shell+network (medium; benign standalone use is not flagged)
- ✅ ignored: genuinely benign (`setInterval`, bare `fetch`, generic `process.env`)

## Known limits

Static scanning looks at how code *looks*, so these will slip past. Listed so you don't
mistake it for more than it is:

- **Indirection**: `const B = "bash"; spawn(B, ["-c", "curl …"])` — a non-literal program name isn't recognized.
- **Interpreter wrapping**: `spawn("env", ["bash", "-c", …])` or `spawn("python", ["-c", …])` — one layer around it and the check is gone.
- **Destructive-but-offline commands**: `spawn("bash", ["-c", "rm -rf /"])` is not reported. The tool targets
  **exfiltration / credential theft / supply-chain poisoning**; destructive commands are outside its promise.
- **Anything assembled at runtime**: a command fetched from a server and executed, or built by string
  concatenation, is invisible to static analysis.
- **False positives still happen.** It matches patterns, not intent. When it fires, the right reading is
  "worth a look", not "this plugin is bad".

That is also why it should be used as **a check that makes you pause for a second — not a security guarantee.**
**Plugins from the marketplace go through an approval process, and that is your primary defence. This tool
is for what you install from outside it.**

## Install

No npm, no PyPI account needed. Three ways:

```bash
# 1. Run straight from GitHub (recommended)
uvx "dsh-guard @ git+https://github.com/quan-v/dsh-safe-gate.git@v0.1.6"

# 2. pip from GitHub
pip install "git+https://github.com/quan-v/dsh-safe-gate.git@v0.1.6"

# 3. Clone and run (zero install, most transparent)
git clone https://github.com/quan-v/dsh-safe-gate.git
cd dsh-safe-gate && git checkout v0.1.6 && python dsh_guard.py check "@antv/mcp-server-chart@0.11.10"
```

> **Naming:** the repo is dsh-safe-gate, the tool/command is dsh-guard — same project. Install URLs use the repo name, the CLI is dsh-guard.
>
> Not published to PyPI (the author has no PyPI account), so `pip install dsh-guard` from the index won't work. All three methods above do. The core is dependency-free (optional tree-sitter apart), and can even be run as a single file.

## Usage

```bash
# Supply chain (block / warn / allow)
dsh-guard check "@antv/mcp-server-chart@0.11.10"   # → BLOCK (MAL-2026-4069)
dsh-guard check "@antv/mcp-server-chart"            # → WARN (unpinned)
dsh-guard check "@antv/mcp-server-chart@0.9.10"     # → ALLOW

# Contract (local plugin file; server / client halves)
dsh-guard check-file ./my-plugin/index.js           # server half
dsh-guard check-file ./my-plugin/client.js --client # client half

# Source hostility scan
dsh-guard scan ./my-plugin/

# Both at once
dsh-guard all "@antv/mcp-server-chart@0.11.10" ./my-plugin/index.js

# Gate then run (only runs the command if checks pass)
dsh-guard safe-add "@antv/mcp-server-chart@0.9.10" --path ./my-plugin/index.js --delegate "dsh plugin add ..."

# Audit log (every check is recorded → ~/.dsh-guard/audit.jsonl)
dsh-guard log [-n 10] [--grep keyword]

# Self-update (snapshot → diff → jump warning)
dsh-guard update-guard [--exec "update command"]

# Visual consent card (local web page)
dsh-guard ui [--port 8170]
```

Append `--json` to any command for machine-readable output.

## As an MCP tool (into dsh)

```bash
dsh mcp add dsh-guard -- uvx "dsh-guard @ git+https://github.com/quan-v/dsh-safe-gate.git@v0.1.6" --mcp
```

Then dsh's agent can call the `dsh_guard_check` tool — ask it before installing any plugin/MCP server.

## dsh plugin (safety config panel)

Besides the CLI, there's a card embedded in dsh's plugin-config panel (`dsh-guard-panel`) showing guard status and the history of blocked packages. The gate logic still lives in the Python tool; the plugin is only a viewing panel. To add it, use `dsh plugin --profile web add` (local `file:` method).

## Audit log

Every check's result (time / command / target / verdict) is appended to `~/.dsh-guard/audit.jsonl`. View it with `dsh-guard log` — an evidence trail of what got blocked and why.

## Platform

**Tested on Windows; cross-platform by design.** Requires Python ≥ 3.9. `node --check` needs Node ≥ 18 (optional; resolved via `shutil.which("node")`).

## Performance boundary (why it's not an antivirus)

dsh-guard is a **decision-point gate**, not a resident anti-malware scanner:

- **Checks once at the "install/run" moment, exits immediately, zero background footprint.**
- Local scans measure <150ms per file; the ~5s is network (OSV/npm), only occasionally when installing.
- **Does not do**: filesystem real-time watching, on-access hooks, background resident daemons, full-disk / whole node_modules rescans.
- Trade-off: on-demand = cheap but **not automatic** (an agent must call it) — an intentional choice.

## Known limitations

- **Knows only "known" advisories**: OSV covers published advisories; cold/new/not-yet-indexed malicious packages go undetected.
- **Not a behavior sandbox**: it isn't an isolator — if a package does something bad at runtime, it can't stop that (dsh's execution-layer sandbox does).
- **Semi-mandatory**: as an MCP tool it relies on the agent's discipline; as a `check` command it relies on you calling it. A hard, un-bypassable gate would need PATH interception or a forked dsh plugin (not promised here).
- **Contract checks are heuristic**: tree-sitter / regex catch common patterns; complex variants may slip through.

## Why external (not a dsh plugin itself)

The gate must not live inside the thing it protects — a supply-chain guard shipped via the supply chain it guards would be self-defeating. Core logic is a standalone Python package; the dsh plugin is only a thin trigger calling it.

## License

MIT. References the design of [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent) (MIT, © 2025 Nous Research).

> **Disclaimer**: this tool is a "known-threat gate", not absolute protection. There's no silver bullet in security — don't blindly approve packages just because it's installed.

---

## Author's note

I'm a dsh user who **isn't deeply versed in programming**. The check logic **passed automated tests** (see the commands and test section above), but —

**I genuinely don't know how useful it is in real-world scenarios.**

It may have genuinely blocked malicious packages; it may also have false positives or gaps. I just know that "asking before installing" is safer than "installing straight away" — **I can't guarantee the outcome**.

**Please verify it yourself before relying on it.** Don't assume it's foolproof just because the author wrote all these passing tests — that's exactly the kind of blind trust this note is trying to prevent.

> If you find a false positive, a gap, or anything off while using it, please open an issue. I'm an amateur — what you point out may well be a problem I didn't see.
