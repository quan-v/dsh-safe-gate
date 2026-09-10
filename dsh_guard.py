#!/usr/bin/env python3
"""
dsh-guard: pre-flight safety gate for dsh plugins / MCP servers.  (MVP, v2)

用法:
  dsh-guard check <pkg>[@version]        # 供应链检查(OSV + pinning)
  dsh-guard check-file <path> [--client] # 本地插件契约检查(静态)
  dsh-guard all <pkg>[@version] <path>   # 两者都查

输出 block / warn / allow + 原因。MIT。
"""
import argparse, json, sys, urllib.request, urllib.error

try:
    import esprima
    HAVE_ESPRIMA = True
except ImportError:
    HAVE_ESPRIMA = False

SERVER_INJECT = {"tools", "settings", "llm"}
CLIENT_INJECT = {"settingsScope", "slots", "locale", "agent", "storage",
                 "connection", "conversation", "modelSelection", "ui"}
OSV_URL = "https://api.osv.dev/v1/query"
__version__ = "0.1.1"

# ─────────────────────────── 包名解析 ───────────────────────────
def parse_pkg(s):
    """支持 '@scope/name' / '@scope/name@ver' / 'name' / 'name@ver'"""
    if s.startswith("@"):
        if "@" in s[1:] and "/" in s:      # @scope/name@ver
            name, _, ver = s.rpartition("@")
            return name, ver
        return s, None                     # @scope/name
    name, _, ver = s.partition("@")
    return name, ver or None

# ─────────────────────────── OSV / 供应链 ───────────────────────────
# ─────────────────────────── 审计日志(G6)───────────────────────────
def audit(entry):
    import os, json, datetime
    e = dict(entry); e.setdefault("ts", datetime.datetime.now().isoformat(timespec="seconds"))
    d = os.path.dirname(_log_file()); os.makedirs(d, exist_ok=True)
    with open(_log_file(), "a", encoding="utf-8") as f:
        f.write(json.dumps(e, ensure_ascii=False) + "\n")

def show_log(n=10, grep=None):
    import os, json
    p = _log_file()
    if not os.path.exists(p):
        print("(暂无审计日志)"); return
    lines = open(p, encoding="utf-8").read().splitlines()
    if grep:
        lines = [l for l in lines if grep.lower() in l.lower()]
        if not lines:
            print("(无匹配)"); return
    for line in lines[-n:]:
        try: print(json.dumps(json.loads(line), ensure_ascii=False))
        except Exception: print(line)

def _log_file():
    import os
    return os.environ.get("DSH_GUARD_LOG", os.path.join(os.path.expanduser("~"), ".dsh-guard", "audit.jsonl"))

def osv_query(name, version=None):
    body = {"package": {"name": name, "ecosystem": "npm"}}
    if version:
        body["version"] = version
    req = urllib.request.Request(OSV_URL, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)

# ─────────────────────────── 行为启发式(绕过"只认已知")───────────────────────────
_SCRIPT_FIELDS = ("preinstall", "install", "postinstall")

def _npm_doc(name):
    req = urllib.request.Request(
        f"https://registry.npmjs.org/{name}",
        headers={"Accept": "application/vnd.npm.install-v1+json"})
    with urllib.request.urlopen(req, timeout=12) as r:
        return json.load(r)

def install_script_risk(name, version):
    """查 npm 元数据里安装期脚本/可疑依赖 → (flags, detail)"""
    try:
        doc = _npm_doc(name)
    except Exception as e:
        return ([], f"npm 元数据获取失败: {e}")
    flags = []
    ver = doc.get("versions", {}).get(version, {})
    scripts = ver.get("scripts", {}) or {}
    for f in _SCRIPT_FIELDS:
        if f in scripts:
            flags.append(f"含 {f} 脚本(安装时执行代码,高风险)")
    deps = set((ver.get("dependencies") or {})) | set((ver.get("devDependencies") or {}))
    for d in deps:
        dl = d.lower()
        if dl in ("@antv/setup",) or "shai-hulud" in dl or "harkonnen" in dl:
            flags.append(f"依赖可疑投毒标记包 {d}")
    return (flags, "")

def check_supply(name, version):
    if not version:
        return ("warn", f"浮动版本未 pinning — 建议锁定具体版本(如 {name}@0.9.10)")
    # ① 已知告警(OSV)
    osv_verdict = None
    try:
        r = osv_query(name, version)
        vulns = r.get("vulns", [])
        mal = [v for v in vulns if "MAL-" in v.get("id", "") or "malic" in v.get("summary", "").lower()]
        if mal:
            osv_verdict = ("block", f"命中恶意通告 {mal[0].get('id','?')} — {mal[0].get('summary','')[:90]}")
        elif vulns:
            osv_verdict = ("warn", f"命中 {len(vulns)} 条普通漏洞通告(非恶意)")
        else:
            osv_verdict = ("allow", "无已知告警")
    except Exception as e:
        osv_verdict = ("warn", f"OSV 查询失败(网络?) {e}")
    verdict, detail = osv_verdict
    # ② 行为启发式(即使 OSV 无记录也可能抓住)
    bflags, bdetail = install_script_risk(name, version)
    joined = detail + ((" " + bdetail) if bdetail else "")
    if bflags:
        risky = any("投毒标记" in f for f in bflags)   # 已知投毒标记 → block
        flagtxt = "; ".join(bflags)
        if verdict == "allow":
            verdict = "block" if risky else "warn"
        joined = f"{joined} [行为] {flagtxt}"
    return (verdict, joined)

# ─────────────────────────── 契约检查(node --check + 正则)───────────────────────────
import re as _re, subprocess as _sp, os as _os

def _norm_path(p):
    """git-bash 的 /c/Users/... → Windows 的 C:/Users/... (仅当 MSYS 形式存在时)"""
    if p and not _os.path.exists(p):
        m = _re.match(r"^/([a-zA-Z])/(.*)$", p)
        if m:
            cand = f"{m.group(1).upper()}:/{m.group(2)}"
            if _os.path.exists(cand):
                return cand
    return p

try:
    from tree_sitter import Language as _TSLang, Parser as _TSParser
    import tree_sitter_javascript as _tsjs
    _TS = _TSLang(_tsjs.language())
    _TS_PARSER = _TSParser(); _TS_PARSER.language = _TS
    HAVE_TS = True
except Exception:
    HAVE_TS = False

_TS_FUNC = {"function_declaration", "function_expression", "arrow_function",
            "generator_function_declaration", "method_definition", "generator_function"}

def _ts_is_async(node):
    return any(c.type == "async" for c in node.children)

def _find_await_bug(src, path):
    if not HAVE_TS:
        return []
    hits = []
    tree = _TS_PARSER.parse(src.encode())
    def walk(node, in_async):
        if node.type == "await_expression" and not in_async:
            hits.append(f"await 出现在非 async 作用域(第 {node.start_point[0]+1} 行)")
            return
        child = in_async
        if node.type in _TS_FUNC:
            child = _ts_is_async(node)
        for c in node.named_children:
            walk(c, child)
    walk(tree.root_node, False)
    return hits

def _node():
    import os, shutil
    n = shutil.which("node")
    if n:
        return n
    for cand in (os.path.expanduser("~/AppData/Local/hermes/node/node.exe"), "node.exe"):
        if cand and os.path.exists(cand):
            return cand
    return "node"

def _node_check(path):
    try:
        r = _sp.run([_node(), "--check", path], capture_output=True, text=True)
    except (FileNotFoundError, OSError):
        return None  # node 可选:缺失时跳过权威语法检查(tree-sitter 仍覆盖 await 检查)
    if r.returncode != 0:
        err = (r.stderr or r.stdout).strip().splitlines()
        return f"node --check 失败:{err[-1][:130] if err else '语法错误'}"
    return None

def check_file(path, is_client=False):
    path = _norm_path(path)
    src = open(path, encoding="utf-8").read()
    findings = []
    # 1) 语法 + await-in-non-async: 交给 node --check(权威,支持现代 JS)
    nerr = _node_check(path)
    if nerr:
        findings.append(("error", nerr))
    for hit in _find_await_bug(src, path):
        findings.append(("error", hit))
    # 2) inject 白名单(只对 inject 数组,server/client 分半)
    allowed = CLIENT_INJECT if is_client else SERVER_INJECT
    half = "client" if is_client else "server"
    for m in _re.finditer(r"inject\s*=\s*\[([^\]]*)\]", src):
        for n in _re.findall(r"['\"]([A-Za-z]+)['\"]", m.group(1)):
            if n not in allowed:
                findings.append(("warn", f"inject 含 '{n}' 不在白名单({half}半)"))
    # 3) keyed-slot 缺 key
    for m in _re.finditer(r"name:\s*['\"](settings\.(?:plugin|general)\.item)['\"]", src):
        chunk = src[m.end():m.end()+400]
        obj_end = chunk.find("}")
        obj = chunk[:obj_end] if obj_end != -1 else chunk
        if "key:" not in obj:
            findings.append(("warn", f"keyed-slot {m.group(1)} 缺显式 key(报 requires options.key)"))
    # 4) adapter 缺 prepareCall(识 compat 包装)
    if "registerAdapter" in src and "prepareCall" not in src \
       and "ensureAdapterPrepareCall" not in src and "wrapLlmService" not in src:
        findings.append(("warn", "registerAdapter 存在但无 prepareCall 且未见 compat 包装(旧契约)"))
    return findings, src

# ─────────────────────────── 源码级敌意扫描(scan,分档严重度:单一高危也报)───────────────────────────
# block=投毒标记;warn(单独)=高危单信号(shell/eval/读密钥);warn(组合)=中危(net+secret/net+shell);忽略=真良性(setInterval/裸fetch/裸atob)
HOSTILE_MARKER = [r"kitty-monitor", r"harkonnen", r"melange", r"/bin/sh\s+-c", r"\bnc\s+-e"]
HOSTILE_HIGH = {
    "shell_exec":    [r"child_process\.(exec|execSync|spawn|spawnSync)|require\(['\"]child_process['\"]\)"],
    "arbitrary_eval":[r"\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\("],
    "secret_read":   [r"process\.env\.(?:AWS_|GITHUB|OPENAI|ANTHROPIC|NPM|DEEPSEEK|GOOGLE|AZURE|TOKEN|API_KEY|SECRET|PASSWORD)|toJSON\(secrets\)|credentials\.ya?ml|auth\.json"],
}
HOSTILE_NET = [r"require\(['\"](?:http|https|net|dgram|tls)['\"]\)|/dev/tcp/|\bcurl\s+|\bfetch\(|WebClient|DownloadString"]
HOSTILE_PERSIST = [r"cron\.schedule|\bRun Copilot\b|schtasks|/etc/cron|Registry\\\\.*Run"]

def _hostile_scan(path):
    import os
    path = _norm_path(path)
    if os.path.isdir(path):
        files = [os.path.join(dp, f) for dp, _, fs in os.walk(path) for f in fs if f.endswith((".js", ".mjs", ".cjs"))]
    else:
        files = [path]
    hits = []
    for f in files:
        try:
            src = open(f, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        if any(_re.search(p, src) for p in HOSTILE_MARKER):
            hits.append(("error", "投毒/外传标记", f))
        for name, pats in HOSTILE_HIGH.items():
            if any(_re.search(p, src) for p in pats):
                hits.append(("warn", f"高危单信号:{name}", f))
        has_net = any(_re.search(p, src) for p in HOSTILE_NET)
        has_shell = any(_re.search(p, src) for p in HOSTILE_HIGH["shell_exec"])
        has_secret = any(_re.search(p, src) for p in HOSTILE_HIGH["secret_read"])
        if has_net and has_secret:
            hits.append(("warn", "读密钥+网络(疑似窃密)", f))
        if has_net and has_shell:
            hits.append(("warn", "shell+网络(疑似外传)", f))
        if any(_re.search(p, src) for p in HOSTILE_PERSIST):
            hits.append(("warn", "持久化/后门迹象", f))
    return hits

# ─────────────────────────── MCP server(--mcp,纯 stdlib)───────────────────────────
def _mcp_result_obj(package, path, client):
    """跑供应链 + 可选契约,返回结构化结果"""
    name, ver = parse_pkg(package)
    v, d = check_supply(name, ver)
    lines = [f"[{v.upper()}] 供应链: {d}"]
    file_findings = []
    if path:
        file_findings, _ = check_file(path, client)
        for lvl, msg in file_findings:
            lines.append(f"[{lvl.upper()}] 契约: {msg}")
    return {"verdict": v, "detail": d, "contract": file_findings,
            "text": "\n".join(lines)}

def serve_mcp():
    """Run as a stdio MCP server (JSON-RPC 2.0, newline-delimited)."""
    import json, sys
    TOOL = {
        "name": "dsh_guard_check",
        "description": ("Pre-flight safety gate for dsh plugins/MCP servers. "
                        "Checks an npm package against OSV (block/warn/allow) and, "
                        "optionally, a local plugin JS file for contract bugs. "
                        "Call before installing a plugin or MCP server."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {"type": "string", "description": "npm package, e.g. @antv/mcp-server-chart@0.11.10"},
                "path": {"type": "string", "description": "optional local plugin file to contract-check"},
                "client": {"type": "boolean", "description": "client half of the plugin (default false)"},
            },
            "required": ["package"],
        },
    }
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            continue
        method = msg.get("method")
        rid = msg.get("id")
        if method == "initialize":
            resp = {"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}}, "serverInfo": {"name": "dsh-guard", "version": __version__}}}
        elif method == "notifications/initialized" or msg.get("method", "").startswith("notifications"):
            resp = None
        elif method == "tools/list":
            resp = {"jsonrpc": "2.0", "id": rid, "result": {"tools": [TOOL]}}
        elif method == "tools/call":
            params = msg.get("params", {})
            name = params.get("name")
            args = params.get("arguments", {})
            if name != "dsh_guard_check":
                resp = {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": f"unknown tool {name}"}], "isError": True}}
            else:
                out = _mcp_result_obj(args.get("package", ""), args.get("path"), bool(args.get("client")))
                resp = {"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text", "text": out["text"]}],
                    "isError": out["verdict"] == "block"}}
        else:
            resp = {"jsonrpc": "2.0", "id": rid, "result": {}}
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()

# ─────────────────────────── 守门后放行(G4 safe-add)───────────────────────────
def _safe_add(pkg, path, client, delegate, yes=False):
    import subprocess
    name, ver = parse_pkg(pkg)
    v, d = check_supply(name, ver)
    print(f"[{v.upper()}] 供应链: {d}")
    findings = []
    if path:
        findings, _ = check_file(path, client)
        for lvl, msg in findings:
            print(f"[{lvl.upper()}] 契约: {msg}")
    has_error = v == "block" or any(l == "error" for l, _ in findings)
    if has_error:
        print("REFUSED → 未通过检查,不执行安装。")
        audit({"cmd": "safe-add", "target": pkg, "path": path, "verdict": "block", "detail": d})
        return 1
    has_warn = v == "warn" or any(l == "warn" for l, _ in findings)
    if has_warn and delegate and not yes:
        import sys as _sys
        if not _sys.stdin.isatty():
            print("REFUSED → 有 warn 级发现,非交互环境需 --yes 显式放行。")
            audit({"cmd": "safe-add", "target": pkg, "path": path, "verdict": "warn-refused", "detail": d})
            return 1
        ans = input("有 warn 级发现,仍要执行? [y/N] ").strip().lower()
        if ans not in ("y", "yes"):
            print("REFUSED → 用户未确认。")
            audit({"cmd": "safe-add", "target": pkg, "path": path, "verdict": "warn-refused", "detail": d})
            return 1
    print("SAFE → 检查通过。")
    if delegate:
        print(f"执行: {delegate}")
        import sys as _sys
        _sys.stdout.flush()
        rc = subprocess.run(delegate, shell=True).returncode
        audit({"cmd": "safe-add", "target": pkg, "path": path, "verdict": "executed", "delegate_rc": rc})
        return rc
    audit({"cmd": "safe-add", "target": pkg, "path": path, "verdict": v, "detail": d})
    return 0

# ─────────────────────────── 自更新治理(G7 update-guard)───────────────────────────
def _snapshot():
    import json, os
    prof = os.path.expanduser("~/.dsh/profiles/web/package.json")
    deps = {}
    try:
        d = json.load(open(prof, encoding="utf-8"))
        deps = d.get("dependencies", {})
    except Exception:
        pass
    core = "?"
    for cand in (
        os.path.expanduser("~/.dsh/profiles/web/node_modules/@deepseek-ai/dsh/package.json"),
        os.path.expanduser("~/AppData/Local/hermes/node/node_modules/@deepseek-ai/dsh/package.json"),
    ):
        try:
            core = json.load(open(cand, encoding="utf-8")).get("version", "?")
            break
        except Exception:
            continue
    return {"dsh_core": core, "plugins": deps}

def _major_jump(b, a):
    def mj(v):
        try:
            p = [int(x) for x in str(v).replace("-", ".").split(".") if x.isdigit()]
        except Exception:
            return None
        if not p:
            return None
        return p[1] if (p[0] == 0 and len(p) > 1) else p[0]
    mb, ma = mj(b), mj(a)
    if mb is None or ma is None:
        return False
    return ma > mb

def update_guard(cmd):
    import subprocess
    before = _snapshot()
    print(f"更新前: dsh 核心 {before['dsh_core']}, {len(before['plugins'])} 个插件")
    audit({"cmd": "update-guard", "stage": "before", "verdict": "ok",
           "dsh_core": before["dsh_core"], "plugins_n": len(before["plugins"])})
    if cmd:
        print(f"执行: {cmd}")
        import sys as _sys; _sys.stdout.flush()
        r = subprocess.run(cmd, shell=True)
        if r.returncode != 0:
            print(f"⚠️ 更新命令退出码 {r.returncode}")
            audit({"cmd": "update-guard", "stage": "exec", "verdict": "error", "exit": r.returncode})
            return r.returncode
    after = _snapshot()
    diff = {n: {"before": before["plugins"].get(n), "after": v}
            for n, v in after["plugins"].items() if before["plugins"].get(n) != v}
    print("版本变更:", end=" ")
    if diff:
        print("")
        for n, d in diff.items():
            flag = " ⚠️ 大跳变" if _major_jump(d["before"], d["after"]) else ""
            print(f"  {n}: {d['before']} → {d['after']}{flag}")
    else:
        print("(无变化)")
    core_jump = _major_jump(before["dsh_core"], after["dsh_core"])
    if core_jump:
        print(f"⚠️ dsh 核心大版本跳变 {before['dsh_core']} → {after['dsh_core']},破坏性更新风险高")
    audit({"cmd": "update-guard", "stage": "after", "verdict": "warn" if (diff or core_jump) else "allow",
           "changed": len(diff), "dsh_core": after["dsh_core"], "core_jump": core_jump})
    return 0

# ─────────────────────────── G5: consent 卡片 UI───────────────────────────
UI_HTML = r"""<!doctype html><html lang="zh"><head><meta charset="utf-8"><title>dsh-guard 守门</title>
<style>body{font-family:ui-sans-serif,system-ui;background:#0f1115;color:#e6e8ee;margin:0;padding:24px;display:flex;justify-content:center}
.card{max-width:720px;width:100%;background:#161a22;border:1px solid #2a3040;border-radius:12px;padding:24px}
h1{font-size:18px;margin:0 0 16px}.tabs{display:flex;gap:8px;margin-bottom:14px}.tab{padding:6px 14px;border-radius:8px;border:1px solid #2a3040;background:transparent;color:#9aa4b5;cursor:pointer;font-size:13px}.tab.on{background:#2f6fed;color:#fff;border-color:#2f6fed}
.inputrow{display:flex;gap:8px;margin-bottom:12px}
input,select{flex:1;background:#0f1115;border:1px solid #2a3040;color:#e6e8ee;padding:8px 10px;border-radius:8px;font-size:14px}
button{background:#2f6fed;color:#fff;border:0;padding:8px 16px;border-radius:8px;cursor:pointer;font-size:14px}
.verdict{margin-top:16px;padding:16px;border-radius:10px;border:1px solid}
.allow{background:#12261a;border-color:#1f7a3d;color:#63d08a}.warn{background:#261d0e;border-color:#c08a1f;color:#e0b054}.block{background:#2a1215;border-color:#c0392b;color:#ff8a80}
.finding{margin:6px 0;font-size:13px}.act{margin-top:16px;display:flex;gap:10px}.act button{border:1px solid #2a3040;background:transparent;color:#e6e8ee}.act .go{background:#1f7a3d}.act .no{background:#c0392b}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:12px}th,td{padding:7px 8px;border-bottom:1px solid #2a3040;text-align:left;vertical-align:top}th{color:#9aa4b5;font-weight:600}.tag{display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px}.tag.b{background:#c0392b;color:#fff}.tag.w{background:#c08a1f;color:#111}.tag.a{background:#1f7a3d;color:#fff}
.histfilter{display:flex;gap:8px;margin-bottom:10px}</style></head><body><div class="card">
<h1>🛡️ dsh-guard 装前守门</h1>
<div class="tabs"><button class="tab on" id="tab-check" onclick="show('check',this)">检查</button><button class="tab" id="tab-hist" onclick="show('hist',this)">历史</button></div>
<div id="check-view">
<div class="inputrow"><input id="q" placeholder="@antv/mcp-server-chart@0.11.10 或 插件路径" /><select id="mode"><option value="supply">供应链</option><option value="contract">契约</option><option value="scan">源码敌意</option></select><button onclick="go()">检查</button></div><div id="out"></div>
</div>
<div id="hist-view" style="display:none">
<div class="histfilter"><input id="hf" placeholder="筛选(包名 / block / allow / 关键词)…" /><button onclick="loadHist()">刷新</button></div><div id="hist"></div>
</div>
<script>function show(v,btn){document.getElementById('check-view').style.display=v==='check'?'':'none';document.getElementById('hist-view').style.display=v==='hist'?'':'none';document.getElementById('tab-check').className='tab'+(v==='check'?' on':'');document.getElementById('tab-hist').className='tab'+(v==='hist'?' on':'');if(v==='hist')loadHist();}
async function go(){const q=document.getElementById('q').value.trim(),m=document.getElementById('mode').value,o=document.getElementById('out');o.innerHTML='<div class="verdict" style="border-color:#3a4152;color:#9aa4b5">检查中…</div>';
const r=await fetch('/api/check?q='+encodeURIComponent(q)+'&mode='+m);const d=await r.json();const cls=d.verdict==='block'?'block':(d.verdict==='warn'?'warn':'allow');
const t={block:'🔴 BLOCK 拦截',warn:'🟡 WARN 需确认',allow:'🟢 ALLOW 通过'}[d.verdict]||d.verdict;
let h='<div class="verdict '+cls+'"><b>'+t+'</b> — '+esc(d.detail||'');(d.findings||[]).forEach(f=>h+='<div class="finding">'+esc(f)+'</div>');h+='</div><div class="act">';
if(d.verdict==='block')h+='<button class="no" onclick="c(\'block\')">拦截：不予安装</button>';else if(d.verdict==='warn')h+='<button class="go" onclick="c(\'allow\')">确认继续</button><button class="no" onclick="c(\'block\')">终止</button>';else h+='<button class="go" onclick="c(\'allow\')">确认</button>';h+='</div>';o.innerHTML=h;}
function esc(s){return String(s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
async function c(v){const q=document.getElementById('q').value;await fetch('/api/consent',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:q,decision:v})});document.getElementById('out').innerHTML='<div class="verdict allow">已记录你的决定：<b>'+(v==='allow'?'放行':'拦截')+'</b></div>';}
async function loadHist(){const f=document.getElementById('hf').value.trim(),o=document.getElementById('hist');o.innerHTML='<div class="verdict" style="border-color:#3a4152;color:#9aa4b5">加载中…</div>';
const r=await fetch('/api/history?f='+encodeURIComponent(f));const d=await r.json();
if(!d.length){o.innerHTML='<div class="verdict" style="border-color:#3a4152;color:#9aa4b5">(暂无历史记录 — 先跑一次检查)</div>';return;}
let h='<table><tr><th>时间</th><th>结论</th><th>命令</th><th>目标</th></tr>';
d.forEach(e=>{const v=e.verdict||'',tag=v==='block'?'b':(v==='warn'?'w':'a'),label=v==='block'?'BLOCK':(v==='warn'?'WARN':'ALLOW');
h+='<tr><td>'+esc(e.ts||'')+'</td><td><span class="tag '+tag+'">'+label+'</span></td><td>'+esc(e.cmd||'')+'</td><td>'+esc(e.target||'')+'</td></tr>';});
h+='</table>';o.innerHTML=h;}
</script></body></html>"""

def _api_check(q, mode):
    import os, json
    findings = []; detail = ""; verdict = "allow"
    try:
        if mode in ("supply", "contract", "scan"):
            pass
        if mode == "supply":
            name, ver = parse_pkg(q); v, d = check_supply(name, ver); verdict = v; detail = d
            if v in ("block", "warn"): findings.append(d)
        else:
            p = _norm_path(q)
            if not os.path.exists(p):
                detail = "路径不存在"; verdict = "warn"; findings.append(detail)
            elif mode == "contract":
                fnd, _ = check_file(p)
                for l, m in fnd: findings.append(f"[{l}] {m}")
                if any(l == "error" for l, _ in fnd): verdict = "block"
                detail = "契约检查"
            elif mode == "scan":
                hits = _hostile_scan(p)
                for l, k, f in hits: findings.append(f"[{l}] {k}: {os.path.basename(f)}")
                if any(l == "error" for l, _, _ in hits): verdict = "block"
                detail = "源码敌意扫描"
    except Exception as e:
        verdict = "warn"; detail = f"检查异常: {e}"
    return {"verdict": "block" if verdict == "block" else verdict, "detail": detail, "findings": findings, "q": q}

def _read_audit(flt=""):
    import os, json
    p = _log_file()
    if not os.path.exists(p):
        return []
    out = []
    flt = (flt or "").strip().lower()
    for line in open(p, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue
        if flt:
            blob = " ".join(str(v) for v in e.values()).lower()
            if flt not in blob:
                continue
        out.append(e)
    out.reverse()
    return out

def serve_ui(port=8170):
    import http.server, socketserver, json, urllib.parse
    class H(http.server.BaseHTTPRequestHandler):
        def _send(self, body, ct="application/json"):
            self.send_response(200); self.send_header("Content-Type", ct); self.end_headers(); self.wfile.write(body)
        def _host_ok(self):
            h = self.headers.get("Host", "")
            return h in ("127.0.0.1:%s" % port, "localhost:%s" % port)
        def do_GET(self):
            if not self._host_ok():
                self.send_response(403); self.end_headers(); return
            u = urllib.parse.urlparse(self.path)
            if u.path == "/":
                self._send(UI_HTML.encode("utf-8"), "text/html;charset=utf-8"); return
            if u.path == "/api/check":
                qs = urllib.parse.parse_qs(u.query)
                self._send(json.dumps(_api_check(qs.get("q", [""])[0], qs.get("mode", ["supply"])[0]), ensure_ascii=False).encode("utf-8")); return
            if u.path == "/api/history":
                qs = urllib.parse.parse_qs(u.query)
                flt = qs.get("f", [""])[0]
                self._send(json.dumps(_read_audit(flt), ensure_ascii=False).encode("utf-8")); return
            self.send_response(404); self.end_headers()
        def do_POST(self):
            if not self._host_ok():
                self.send_response(403); self.end_headers(); return
            if self.path == "/api/consent":
                ln = int(self.headers.get("Content-Length", 0))
                data = json.loads(self.rfile.read(ln) or b"{}")
                audit({"cmd": "consent", "target": data.get("target"), "decision": data.get("decision")})
                self._send(b'{"ok":true}'); return
            self.send_response(404); self.end_headers()
        def log_message(self, *a):
            pass
    with socketserver.TCPServer(("127.0.0.1", port), H) as httpd:
        print(f"🛡️ dsh-guard UI: http://127.0.0.1:{port}  (Ctrl+C 退出)")
        httpd.serve_forever()

# ─────────────────────────── CLI ───────────────────────────
def _jsonout(obj):
    import json as _json
    print(_json.dumps(obj, ensure_ascii=False))

def main():
    import json as _json
    ap = argparse.ArgumentParser(prog="dsh-guard")
    ap.add_argument("--mcp", action="store_true", help="run as stdio MCP server")
    sub = ap.add_subparsers(dest="cmd")
    p1 = sub.add_parser("check", help="供应链检查 pkg[@version]"); p1.add_argument("pkg"); p1.add_argument("--json", action="store_true")
    p2 = sub.add_parser("check-file", help="本地插件契约检查"); p2.add_argument("path"); p2.add_argument("--client", action="store_true"); p2.add_argument("--json", action="store_true")
    p3 = sub.add_parser("all", help="两者都查"); p3.add_argument("pkg"); p3.add_argument("path"); p3.add_argument("--client", action="store_true")
    p4 = sub.add_parser("safe-add", help="守门后放行:检查通过才执行(delegate)"); p4.add_argument("pkg"); p4.add_argument("--path"); p4.add_argument("--client", action="store_true"); p4.add_argument("--delegate"); p4.add_argument("--yes", action="store_true", help="warn 级发现仍放行(非交互环境必填)")
    p5 = sub.add_parser("scan", help="源码级敌意模式扫描(外传/窃密/后门/混淆)"); p5.add_argument("path"); p5.add_argument("--json", action="store_true")
    p6 = sub.add_parser("log", help="查看审计日志"); p6.add_argument("-n", type=int, default=10); p6.add_argument("--grep", default=None)
    p7 = sub.add_parser("update-guard", help="自更新治理:快照→执行→diff→审计"); p7.add_argument("--exec", default=None)
    p8 = sub.add_parser("ui", help="G5:consent 卡片本地网页(浏览器打开)"); p8.add_argument("--port", type=int, default=8170)
    args = ap.parse_args()

    if args.mcp:
        serve_mcp(); return
    if args.cmd is None:
        ap.print_help(); return

    if args.cmd == "check":
        name, ver = parse_pkg(args.pkg); v, d = check_supply(name, ver)
        audit({"cmd": "check", "target": args.pkg, "verdict": v, "detail": d})
        if args.json:
            _jsonout({"cmd": "check", "target": args.pkg, "verdict": v, "detail": d})
        else:
            print(f"[{v.upper()}] 供应链: {d}")
        sys.exit(0 if v != "block" else 1)
    elif args.cmd == "check-file":
        fnd, _ = check_file(args.path, args.client)
        ver = "error" if any(l == "error" for l, _ in fnd) else ("warn" if fnd else "allow")
        audit({"cmd": "check-file", "target": args.path, "verdict": ver, "findings": len(fnd)})
        if args.json:
            _jsonout({"cmd": "check-file", "target": args.path, "verdict": ver, "findings": [m for _, m in fnd]})
        else:
            for level, msg in fnd:
                print(f"[{level.upper()}] 契约: {msg}")
        sys.exit(0 if ver != "error" else 1)
    elif args.cmd == "all":
        name, ver = parse_pkg(args.pkg); v, d = check_supply(name, ver)
        print(f"[{v.upper()}] 供应链: {d}")
        fnd, _ = check_file(args.path, args.client)
        for level, msg in fnd:
            print(f"[{level.upper()}] 契约: {msg}")
        audit({"cmd": "all", "target": args.pkg, "path": args.path, "verdict": v, "findings": len(fnd)})
        sys.exit(0 if v != "block" and not any(l == "error" for l, _ in fnd) else 1)
    elif args.cmd == "safe-add":
        sys.exit(_safe_add(args.pkg, args.path, args.client, args.delegate, getattr(args, "yes", False)))
    elif args.cmd == "scan":
        hits = _hostile_scan(args.path)
        ver = "error" if any(l == "error" for l, _, _ in hits) else ("warn" if hits else "allow")
        audit({"cmd": "scan", "target": args.path, "verdict": ver, "hits": len(hits)})
        if args.json:
            _jsonout({"cmd": "scan", "target": args.path, "verdict": ver, "findings": [{"level": l, "kind": k, "file": f} for l, k, f in hits]})
        else:
            for level, kind, f in hits:
                print(f"[{level.upper()}] {kind}: {f}")
        sys.exit(0 if ver != "error" else 1)
    elif args.cmd == "log":
        show_log(args.n, args.grep)
    elif args.cmd == "update-guard":
        sys.exit(update_guard(args.exec))
    elif args.cmd == "ui":
        serve_ui(args.port)
    else:
        ap.print_help()

if __name__ == "__main__":
    main()
