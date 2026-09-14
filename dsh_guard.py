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
__version__ = "0.1.8"

_KNOWN_SERVICE_CACHE = None


def _is_reparse_point(path):
    """是不是符号链接 / Windows junction。

    坑:Windows 的 junction **不是 symlink**,os.path.islink() 对它返回 False,
    所以 os.walk(followlinks=False) 形同虚设 —— 实测一个指向扫描根之外的 junction
    会让 scan 跟着它读出去(越界读取,而且那些路径还会被写进审计日志)。
    junction 在 Windows 上带 FILE_ATTRIBUTE_REPARSE_POINT 位(0x400),用这个判。
    """
    try:
        if _os.path.islink(path):
            return True
        st = _os.lstat(path)
        return bool(getattr(st, "st_file_attributes", 0) & 0x400)
    except Exception:
        return False


def _discover_services():
    """从 dsh 已装的插件里现扫服务名,与内置基础名单合并。

    为什么必须动态:dsh 是插件化架构,服务名是**开放集合** —— DSH 自带插件就用了 24 个
    不同名字(实测),而硬编码白名单只有 12 个,于是真实插件 6/11 被判"不在白名单"。
    硬编码必然滞后于生态,越补越漏。扫一遍已装插件,名单就自己跟上。
    """
    global _KNOWN_SERVICE_CACHE
    if _KNOWN_SERVICE_CACHE is not None:
        return _KNOWN_SERVICE_CACHE
    names = set(SERVER_INJECT) | set(CLIENT_INJECT)
    try:
        import os as _os2
        prof_dir = _os2.path.join(_os2.path.expanduser("~"), ".dsh", "profiles")
        roots = []
        if _os2.path.isdir(prof_dir):
            for prof in _os2.listdir(prof_dir):
                nm = _os2.path.join(prof_dir, prof, "node_modules")
                if _os2.path.isdir(nm):
                    roots.append(nm)
        seen = 0
        for root in roots:
            base_depth = root.rstrip("\\/").count(_os2.sep)
            for dp, dirs, fs in _os2.walk(root):
                if dp.count(_os2.sep) - base_depth > 3:      # 只扫浅层,别陷进依赖深处
                    dirs[:] = []
                    continue
                dirs[:] = [d for d in dirs
                           if d not in (".bin", ".cache", "node_modules")
                           and not _is_reparse_point(_os2.path.join(dp, d))]
                for f in fs:
                    if not f.endswith((".js", ".mjs", ".cjs")) or seen > 5000:
                        continue
                    fp = _os2.path.join(dp, f)
                    try:
                        if _os2.path.getsize(fp) > 2 * 1024 * 1024:
                            continue
                        txt = open(fp, encoding="utf-8", errors="replace").read()
                    except Exception:
                        continue
                    seen += 1
                    for m in _re.finditer(r"inject\s*=\s*\[([^\]]*)\]", txt):
                        for n in _re.findall(r"['\"]([A-Za-z_$][\w$]*)['\"]", m.group(1)):
                            names.add(n)
    except Exception:
        pass
    _KNOWN_SERVICE_CACHE = names
    return names


def _edit_distance_one(a, b):
    """a 与 b 是否只差一个字符(增/删/替)。"""
    if a == b:
        return False
    if len(a) == len(b):
        return sum(1 for x, y in zip(a, b) if x != y) == 1
    if len(a) + 1 == len(b):
        a, b = b, a
    if len(a) != len(b) + 1:
        return False
    i = 0
    while i < len(b) and a[i] == b[i]:
        i += 1
    return a[i + 1:] == b[i:]


def _looks_like_typo(name, known):
    """名字是否"像把某个已知服务名写错了"。

    这条检查原来的判据是"不在白名单 ⇒ 有问题",但 dsh 的服务名是开放集合(硬编码 12 vs
    实际 24),于是真实插件误报 55%。改成只在"与某个已知名字仅差一个字符"时提示 ——
    那才是能确定有问题的情况(这种拼错会让 dsh 加载真的失败)。
    名字对不上又不像拼错的(比如 fs / webServer):宁可漏,不误报。
    """
    for k in known:
        if abs(len(k) - len(name)) <= 1 and _edit_distance_one(name, k):
            return k
    return None


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
def _auto_audit_enabled():
    """读 dsh 面板上那个"自动记录审计日志"开关,决定是否写审计。

    这个开关住在 ~/.dsh/settings.yaml 的 dsh-guard-panel.autoAudit —— 而写日志的是
    本工具。以前这里没人读它,于是开关纯属装饰:用户关掉了、日志照写。
    默认开(true);读不出也当开(宁可多记,不可静默不记)。
    """
    try:
        path = _settings_path()
        if not _os.path.exists(path):
            return True
        with open(path, encoding="utf-8") as f:
            txt = f.read()
        # 流式写法:dsh-guard-panel: {autoAudit: false}(同一行)
        m_flow = _re.search(r"^dsh-guard-panel:[ \t]*\{([^}]*)\}", txt, _re.M)
        if m_flow:
            mm = _re.search(r"autoAudit\s*:\s*['\"]?(true|false)['\"]?", m_flow.group(1), _re.I)
            return True if not mm else (mm.group(1).lower() != "false")
        # 块式写法(带引号的 "false" 同样合法,以前读不出来)
        m = _re.search(r"^dsh-guard-panel:[^\n]*\n((?:[ \t]+.*\n?)*)", txt, _re.M)
        if not m:
            return True
        mm = _re.search(r"^[ \t]+autoAudit:[ \t]*['\"]?(true|false)['\"]?[ \t]*$", m.group(1), _re.M | _re.I)
        return True if not mm else (mm.group(1).lower() != "false")
    except Exception:
        return True


def _recent_entries(n=30):
    """读审计日志最后 n 条(给 dsh 面板用;条数很少,直接读文件最省事)。"""
    import os, json
    path = _LOG_PATH or next((x for x in _log_candidates() if os.path.exists(x)), None)
    if not path:
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = [x for x in f.read().splitlines() if x.strip()]
    except Exception:
        return []
    out = []
    for ln in lines[-n:]:
        try:
            out.append(json.loads(ln))
        except Exception:
            continue
    return out


def audit(entry):
    """追加一条审计记录。

    结果优先:日志写不进去也不能影响命令本身的输出 —— 依次尝试候选路径,
    全部失败只告警(stderr),绝不抛异常(沙箱/只读环境里命令仍要正常给出结果)。
    """
    global _LOG_PATH
    import os, json, datetime, sys
    # 面板上的"自动记录审计日志"开关真的管用:关掉就不写(以前这里没读它,开关是装饰)
    if not _auto_audit_enabled():
        return
    e = dict(entry); e.setdefault("ts", datetime.datetime.now().isoformat(timespec="seconds"))
    line = json.dumps(e, ensure_ascii=False) + "\n"
    for p in ([_LOG_PATH] if _LOG_PATH else _log_candidates()):
        try:
            d = os.path.dirname(p)
            if d:
                os.makedirs(d, exist_ok=True)
            with open(p, "a", encoding="utf-8") as f:
                f.write(line)
            _LOG_PATH = p
            # 顺手把最近记录发布给 dsh 的守门面板(settings.yaml)。
            # 面板的数据通道只有这一条:浏览器读不了本地文件,服务端插件又写不进 settings,
            # 所以由这里直接写进配置文件。失败绝不影响检查结果。
            try:
                _publish_history_to_settings(_recent_entries(30), 30)
            except Exception:
                pass
            return
        except Exception:
            continue
    print("[dsh-guard] 警告:审计日志写入失败(已跳过,不影响检查结果)", file=sys.stderr)

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

_LOG_PATH = None  # 实际写入成功的日志路径(首次成功后缓存,避免每次都试探)

def _settings_path():
    """dsh 的 settings.yaml 路径(面板插件从这里读数据)。"""
    return _os.path.expanduser(_os.path.join("~", ".dsh", "settings.yaml"))


def _publish_history_to_settings(entries, limit=30):
    """把最近若干条审计记录写进 dsh 的 settings.yaml(最新在前),供守门面板显示。

    为什么绕这一圈:dsh 的 settings 通道是"浏览器端能写、服务端插件写不进",而浏览器读不了
    本地文件 —— 外部产生的数据只能由本工具写进配置文件。代价:面板显示的是快照。

    这个函数以前"手太重",实测被指出四处越权/粗糙(REPORT13 #7),逐条收住:
      a) 面板没装(settings.yaml 里没有 dsh-guard-panel: 段)时**不凭空创建** ——
         跑一次安全检查不该等于"往用户的 DSH 主配置里加一个新顶层键";
      b) 用二进制读写**保留原有行尾** —— 文本模式会把 CRLF 归一、写回时全文件变 CRLF,
         实测一次 check 就能让整个 settings.yaml 的每一行都变(与"其余原文照抄"不符);
      c) 流式写法 dsh-guard-panel: {autoAudit: false} 一律**不动** ——
         旧实现会把它整段拆掉、连用户设的 autoAudit 一起丢;
      d) 写前再对一次 mtime+size,文件在"读-改-写"之间被别人改过就**放弃本次写入**,
         不去覆盖 DSH 刚保存的设置;
      另外:备份、只动本段、异常全吞(不影响检查命令)都保持不变。
    """
    try:
        if _os.environ.get("DSH_GUARD_NO_PUBLISH"):
            return False
        path = _settings_path()
        if not _os.path.exists(path):
            return False
        st_before = _os.stat(path)
        with open(path, "rb") as f:                      # (b) 二进制读,行尾原样保留
            raw = f.read()
        text = raw.decode("utf-8", "replace")
        nl = "\r\n" if "\r\n" in text else "\n"
        lines = text.split(nl)

        start = None
        for i, ln in enumerate(lines):
            if ln.startswith("dsh-guard-panel:"):
                start = i
                break
        if start is None:                                # (a) 没装面板 → 不创建
            return False
        if lines[start].strip() != "dsh-guard-panel:":   # (c) 流式写法 → 不动
            return False

        end = len(lines)
        for j in range(start + 1, len(lines)):
            if lines[j] and not lines[j][0].isspace():
                end = j
                break

        # 段内保留除 history 以外的整行(用户改过的 autoAudit 等不能丢)
        kept = []
        k = start + 1
        while k < end:
            if lines[k].startswith("  history:"):
                k += 1
                while k < end and lines[k].startswith("    "):
                    k += 1
                continue
            if lines[k].strip():
                kept.append(lines[k])
            k += 1

        block = ["  history:"]
        for e in list(reversed(entries or []))[:limit]:   # 最新在前
            block.append("    - ts: " + json.dumps(str(e.get("ts", ""))))
            block.append("      verdict: " + json.dumps(str(e.get("verdict", ""))))
            block.append("      cmd: " + json.dumps(str(e.get("cmd", ""))))
            block.append("      target: " + json.dumps(str(e.get("target", ""))))

        out = lines[:start] + ["dsh-guard-panel:"] + kept + block + lines[end:]

        st_now = _os.stat(path)                          # (d) 期间被改过 → 放弃
        if (st_now.st_mtime_ns, st_now.st_size) != (st_before.st_mtime_ns, st_before.st_size):
            return False

        with open(path + ".dsh-guard.bak", "wb") as f:
            f.write(raw)
        with open(path, "wb") as f:                      # (b) 二进制写,行尾不变
            f.write(nl.join(out).encode("utf-8"))
        return True
    except Exception:
        return False


def _log_candidates():
    """审计日志候选路径:环境变量指定 > 家目录 > 当前工作区 > 临时目录。

    沙箱(workspace-write)里家目录通常在工作区外、不可写;如果只有家目录一个选择,
    一次写入失败就会 traceback 拖垮整条命令(连检查结果都输不出来)。所以必须能依次回退。
    """
    import os, tempfile
    cands = []
    env = os.environ.get("DSH_GUARD_LOG")
    if env:
        cands.append(env)
    cands.append(os.path.join(os.path.expanduser("~"), ".dsh-guard", "audit.jsonl"))
    try:
        cands.append(os.path.join(os.getcwd(), ".dsh-guard", "audit.jsonl"))
    except Exception:
        pass
    cands.append(os.path.join(tempfile.gettempdir(), "dsh-guard", "audit.jsonl"))
    return cands

def _log_file():
    """读取审计日志用:优先返回已存在的日志文件路径。"""
    import os
    if _LOG_PATH and os.path.exists(_LOG_PATH):
        return _LOG_PATH
    cands = _log_candidates()
    for p in cands:
        if os.path.exists(p):
            return p
    return cands[0]

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

def _npm_version_doc(name, version):
    """取单个版本的完整文档。

    为什么不能用 install-v1 精简元数据:它**刻意省略** scripts 与每版本 dependencies,
    于是 install_script_risk 里 ver.get("scripts") / ver.get("dependencies") 恒为空,
    行为启发式(安装脚本 / 投毒依赖)永不触发 —— 实测 esbuild@0.24.2、core-js@3.36.0、
    puppeteer@22.0.0 三个真含 postinstall 的包全部漏报。
    /{name}/{version} 单版本文档体积小、字段全,是这里正确的取法。
    """
    req = urllib.request.Request(
        f"https://registry.npmjs.org/{name}/{version}",
        headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=12) as r:
        return json.load(r)

def install_script_risk(name, version):
    """查 npm 元数据里安装期脚本/可疑依赖 → (flags, detail)"""
    flags = []
    note = ""
    ver = {}
    # ① 首选:单版本完整文档(含 scripts / dependencies)
    if version:
        try:
            ver = _npm_version_doc(name, version)
        except Exception as e:
            note = f"单版本元数据获取失败({e}),已退到精简元数据"
    # ② 退化:精简元数据(至少能给出 hasInstallScript)
    if not isinstance(ver, dict) or not ver:
        try:
            ver = _npm_doc(name).get("versions", {}).get(version, {}) or {}
        except Exception as e:
            return ([], f"npm 元数据获取失败: {e}")
    if not isinstance(ver, dict):
        ver = {}
    scripts = ver.get("scripts", {}) or {}
    for f in _SCRIPT_FIELDS:
        if f in scripts:
            flags.append(f"含 {f} 脚本(安装时执行代码,高风险)")
    # 兜底:精简元数据只带 hasInstallScript 布尔值,拿不到脚本名时也要提示出来
    if not scripts and ver.get("hasInstallScript"):
        flags.append("含安装期脚本(元数据仅给出 hasInstallScript,未取到脚本名)")
    deps = set((ver.get("dependencies") or {})) | set((ver.get("devDependencies") or {}))
    for d in deps:
        dl = d.lower()
        if dl in ("@antv/setup",) or "shai-hulud" in dl or "harkonnen" in dl:
            flags.append(f"依赖可疑投毒标记包 {d}")
    return (flags, note)

def _npm_latest_version(name):
    """从 npm 的 dist-tags 取 latest —— 没写版本号时先解析出实际版本,而不是跳过检查。

    精简元数据(install-v1)里带 dist-tags,不用取全量文档。
    """
    try:
        req = urllib.request.Request(
            "https://registry.npmjs.org/" + name,
            headers={"Accept": "application/vnd.npm.install-v1+json"})
        with urllib.request.urlopen(req, timeout=12) as r:
            doc = json.load(r)
        v = (doc.get("dist-tags") or {}).get("latest")
        return str(v) if v else None
    except Exception:
        return None


def check_supply(name, version):
    _resolved_note = ""
    if not version:
        # 没有版本号 ≠ 可以不查。原实现直接 return 一条"浮动版本未 pinning"的 warn,
        # 而 warn 是可被 --yes 覆盖的 —— 实测 `safe-add <恶意包裸名> --yes` 会 SAFE 放行并执行。
        # 正确做法:先向 npm 问出实际版本(latest)再照常查;问不到就按 unknown 硬拒
        # (unknown 与断网/超大文件同档:检查未完成,不许 --yes 覆盖)。
        resolved = _npm_latest_version(name)
        if not resolved:
            return ("unknown", f"未指定版本,且无法从 npm 解析出实际版本 —— 未做检查,不放行")
        version = resolved
        _resolved_note = f"(未指定版本,按 npm latest {resolved} 检查)"
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
        # 网络失败 ≠ 安全:明确区分"确认无害"与"无法确认",避免下游把它当成 allow 放行
        osv_verdict = ("unknown", f"无法确认(OSV 查询失败,可能断网): {_sanitize(str(e), 80)}")
    verdict, detail = osv_verdict
    try:
        if _resolved_note:
            detail = detail + " " + _resolved_note
    except NameError:
        pass
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

# 统一输出编码:中文 Windows 控制台默认 GBK,emoji/特殊字符会直接崩掉整条命令(或 ui 启动)
try:
    import sys as _sys
    _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    _sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


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
    # 顶层 await 在 ES module 里完全合法（插件常见写法：export const m = await import(...)），
    # 所以 Program 根按“合法上下文”起步，只有进入非 async 的**函数体**才报错。
    # （CJS 里非法的顶层 await 由 node --check 的 commonjs 复核兜住，不会漏。）
    walk(tree.root_node, True)
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

_NODE_MISSING = "@@node-missing@@"   # node 不可用时返回此标记,由调用方转为显式 warn

def _node_check(path):
    """语法检查。

    注意：不要用 `node --check <file>` —— Node 对 .js 文件会走 CommonJS 校验路径，
    遇到 ESM 语法（export/import）时**跳过语法校验**，导致坏文件被静默放行（rc=0）。
    而 dsh 插件恰好全是 "type":"module" 的 .js，所以那条路径恰好在最该生效的场景失效。

    改为：把源码从 stdin 喂进去按 module 模式检查；若不通过，再按 commonjs 复核
    （避免误报纯 CJS 文件）—— 任一模式通过即视为语法合法。
    """
    try:
        src = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return None
    first_err = None
    for mode in ("module", "commonjs"):
        try:
            # encoding 必须显式 utf-8：否则会跟随系统 locale（中文 Windows = cp936），
            # 源码里的 ¥ / emoji / 中文标识符会让 stdin 编码直接崩（UnicodeEncodeError，零输出）。
            r = _sp.run([_node(), "--check", "--input-type=" + mode],
                        input=src, capture_output=True, encoding="utf-8", errors="replace")
        except (FileNotFoundError, OSError):
            # node 不可用 → 语法检查整类会静默失效。这属于 fail-open,必须显式告知调用方
            return _NODE_MISSING
        if r.returncode == 0:
            return None
        if first_err is None:
            lines = [l.strip() for l in (r.stderr or r.stdout).strip().splitlines() if l.strip()]
            # 优先挑带 Error 的那行(末行通常只是 "Node.js v22.x",没有信息量)
            first_err = next((l for l in lines if "Error" in l), lines[0] if lines else "语法错误")
    return f"node --check 失败:{first_err[:130]}"

def _object_around(src, pos):
    """向前找最近的 '{'，再用括号配平（跳过字符串与注释）取回整个对象字面量的文本。

    用于 keyed-slot 的 key 检查：原先用固定 400 字符窗口，key 稍远（中间有大段注释）就误报缺 key。
    取不到返回 None。
    """
    start = src.rfind("{", max(0, pos - 300), pos)
    if start == -1:
        return None
    depth = 0
    i = start
    n = len(src)
    quote = None
    while i < n:
        c = src[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "\"'`":
            quote = c
        elif c == "/" and i + 1 < n and src[i + 1] == "/":
            nl = src.find("\n", i)
            i = n if nl == -1 else nl
            continue
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            end = src.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return src[start:i + 1]
        i += 1
    return None

MAX_CHECK_BYTES = 5 * 1024 * 1024   # 超过 5MB 不做完整检查(避免读爆内存 / AST 爆栈)

def check_file(path, is_client=False):
    path = _norm_path(path)
    findings = []
    # 入口防护:路径与文件内容都来自不可信输入(agent/用户),任何异常都不能让调用方崩 ——
    # CLI 零输出、MCP 服务死亡都属于 fail-open,比"返回一个错误结论"危险得多。
    if not _os.path.exists(path):
        return [("error", f"路径不存在: {_sanitize(path, 120)}")], ""
    if _os.path.isdir(path):
        return [("error", f"是目录而非文件: {_sanitize(path, 120)}")], ""
    try:
        size = _os.path.getsize(path)
    except OSError as e:
        return [("error", f"无法读取文件属性: {_sanitize(str(e), 120)}")], ""
    if size > MAX_CHECK_BYTES:
        return [("unknown", f"文件过大({size // 1048576}MB),检查未完成")], ""
    try:
        # errors="replace":二进制 / 非 UTF-8 内容不能让检查崩掉
        src = open(path, encoding="utf-8", errors="replace").read()
    except OSError as e:
        return [("error", f"读取失败: {_sanitize(str(e), 120)}")], ""
    # 1) 语法 + await-in-non-async: 交给 node --check(权威,支持现代 JS)
    nerr = _node_check(path)
    if nerr == _NODE_MISSING:
        findings.append(("unknown", "node 不可用,语法检查未完成(结论不可信)"))
    elif nerr:
        findings.append(("error", nerr))
    try:
        for hit in _find_await_bug(src, path):
            findings.append(("error", hit))
    except RecursionError:
        # 深层嵌套(混淆代码常见)会撑爆 Python 递归 → 降级跳过本项,绝不冒泡
        findings.append(("unknown", "AST 嵌套过深,await 检查未完成(疑似混淆代码)"))
    # 2) inject 名字核对:只报"像把已知服务名写错了"的
    #    旧判据是"不在白名单 ⇒ 有问题",而 dsh 的服务名是开放集合(自带插件就用 24 个,
    #    硬编码只有 12 个)—— 实测真实插件 6/11 被冤枉,误报 55%。误报会把门变成噪音。
    known = _discover_services()
    half = "client" if is_client else "server"
    for m in _re.finditer(r"inject\s*=\s*\[([^\]]*)\]", src):
        for n in _re.findall(r"['\"]([A-Za-z_$][\w$]*)['\"]", m.group(1)):
            if n in known:
                continue
            like = _looks_like_typo(n, known)
            if like:
                findings.append(("warn", f"inject 里的 '{n}' 像是 '{like}' 写错了({half}半)—— dsh 会因找不到该服务而加载失败"))
    # 3) keyed-slot 的 key —— 该判据已移除
    #    原先报"缺显式 key",但 DSH 自家插件(dsh-client-ui-theme)注册 settings.general.item 时
    #    同样只有 id、没有 key,照样正常渲染;key 在 dsh 里是可选的(用于按 key 定位 entry,
    #    不传走常规渲染)。判据不成立 ⇒ 只会误报真实插件(cost-meter 就是这么被冤枉的)。
    #    宁可漏,不误报 —— 这是本工具反复吃过教训的地方。
    # 4) adapter 缺 prepareCall(识 compat 包装)
    if "registerAdapter" in src and "prepareCall" not in src \
       and "ensureAdapterPrepareCall" not in src and "wrapLlmService" not in src:
        findings.append(("warn", "registerAdapter 存在但无 prepareCall 且未见 compat 包装(旧契约)"))
    return findings, src

# ─────────────────────────── 源码级敌意扫描(scan,分档严重度:单一高危也报)───────────────────────────
# block=投毒标记;warn(单独)=高危单信号(shell/eval/读密钥);warn(组合)=中危(net+secret/net+shell);忽略=真良性(setInterval/裸fetch/裸atob)
HOSTILE_MARKER = [r"kitty-monitor", r"harkonnen", r"melange", r"/bin/sh\s+-c", r"\bnc\s+-e"]
HOSTILE_HIGH = {
    # exec/execSync 与 execFile 风险不同(execFile 不走 shell、参数以数组传递)→ 加负向前瞻,
    # 否则 "child_process.execFile" 会被 "exec" 前缀吃掉,真实插件实测误报。
    # 只有 exec/execSync 会走 shell(命令字符串拼接 → 注入面),单信号即报。
    # spawn/spawnSync/execFile 参数以数组传递、不经 shell,是插件起子进程的常态
    # (实测把 spawn 当单信号会让真实插件刷出 101 条告警 → 误报灾难,见 REPORT5 的教训)。
    "shell_exec":    [r"child_process\.(?:exec|execSync)(?![\w$])"],
    "arbitrary_eval":[r"\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\("],
    # 只认"名字本身就是密钥"的变量:裸厂商前缀会把 DEEPSEEK_BASE_URL(地址)也算进来。
    # 泛 process.env 一律不报(README 已把"泛 process.env"列为良性)。
    "secret_read":   [r"process\.env\.[A-Za-z0-9_]*?(?:API_?KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|ACCESS_KEY)[A-Za-z0-9_]*|toJSON\(secrets\)|credentials\.ya?ml|auth\.json"],
}
# spawn/execFile 绝大多数形态不报(数组传参、起子进程是插件常态)。只有两类需要报,
# 且两类都必须"程序名 + 上下文"一起看,单看程序名会误报:
#   ① 调外传工具 —— spawn('curl', …) / ('curl.exe', …) :程序名本身就是动作,直接报
#   ② 调 shell 本体 —— 光看程序名不行:Windows 插件用 powershell 查进程信息(Get-Process)
#      是常见良性写法(实测:11 个真实插件因此多出 1 条误报)。改为要求"参数里出现联网 /
#      管道执行 token"才报 —— 这样 spawn('bash',['-c','curl … | sh']) 仍报,纯本地查询不报。
HOSTILE_SPAWN_EXFIL = [r"\b(?:spawn|spawnSync|execFile)\s*\(\s*['\"](?:[^'\"]*[\\/])?(?:curl|wget|ncat|nc)(?:\.exe)?\s*['\"]"]
_SPAWN_SHELL_HOST = r"\b(?:spawn|spawnSync|execFile)\s*\(\s*['\"](?:[^'\"]*[\\/])?(?:sh|bash|zsh|cmd(?:\.exe)?|powershell|pwsh)(?:\.exe)?\s*['\"]"
# 只收"动作类"证据:裸 https?:// 的证据强度太弱(URL 常出现在日志/帮助文本/常量里),
# 用它会误报 —— 实测 spawn('bash', ['-c', 'echo 文档见 http://docs.example']) 被判为联网。
# 每个名字都带前导 \b:少了它 "spawnSync(" 里的 "Sync" 会被 "nc\b" 咬到(工具名也出现在调用表达式里)。
_SHELL_ARGV_DANGER = (r"(?:\bcurl\b|\bwget\b|\bncat\b|\bnc\b|/dev/tcp|\|\s*(?:sh|bash)\b|\biex\b|"
                      r"Invoke-Expression|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|DownloadString|DownloadFile|"
                      r"base64\s+-d|certutil\s+-urlcache)")
HOSTILE_NET = [r"require\(['\"](?:http|https|net|dgram|tls)['\"]\)|/dev/tcp/|\bcurl\s+|\bfetch\(|WebClient|DownloadString"]
HOSTILE_PERSIST = [r"cron\.schedule|\bRun Copilot\b|schtasks|/etc/cron|Registry\\\\.*Run"]

def _strip_noise(src, keep_strings=False):
    """把注释与字符串内容抹成等长空白(保留换行,行号仍对齐),只留真实代码。

    keep_strings=True:只抹注释、保留字符串内容 —— 供"引入了哪个模块"这类需要读字面量
    的判定使用(模块名是代码语义,不是噪音)。


    为什么必须做:正则直接跑原始全文时,注释里写一句 "child_process.exec is dangerous"
    就会报 warn —— 实测真实插件集 196 个命中里 34 个(17%)落在注释/字符串内。
    更要命的是"组合信号":注释里提一句 auth.json 就能拼出"读密钥+网络(疑似窃密)",
    与真的读 API_KEY 往外发**输出逐字相同**,最高危信号因此完全失去区分度。
    """
    out = list(src)
    i, n = 0, len(src)
    NL = chr(10)
    BS = chr(92)
    st = "code"
    while i < n:
        c = src[i]
        nx = src[i + 1] if i + 1 < n else ""
        if st == "code":
            if c == "/" and nx in ("/", "*"):
                st = "line" if nx == "/" else "block"
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if c in ("'", '"', "`"):
                st = {"'": "sq", '"': "dq", "`": "tpl"}[c]
                if not keep_strings:
                    out[i] = " "
                i += 1
                continue
        elif st == "line":
            if c == NL:
                st = "code"
            else:
                out[i] = " "
        elif st == "block":
            if c == "*" and nx == "/":
                out[i] = out[i + 1] = " "
                i += 2
                st = "code"
                continue
            if c != NL:
                out[i] = " "
        else:   # sq / dq / tpl
            q = {"sq": "'", "dq": '"', "tpl": "`"}[st]
            if c == BS:                      # 转义序列:内容一并抹掉
                if not keep_strings:
                    out[i] = " "
                    if i + 1 < n and src[i + 1] != NL:
                        out[i + 1] = " "
                i += 2
                continue
            if c == q:
                if not keep_strings:
                    out[i] = " "
                st = "code"
                i += 1
                continue
            if c != NL and not keep_strings:
                out[i] = " "
        i += 1
    return "".join(out)


def _cp_import_line(src, names):
    """引入 child_process 且引出的名字落在 names 里时的行号,否则 None。

    模块名住在字符串里,而 _strip_noise 会抹掉字符串 —— 所以这一组在"只抹注释、保留字符串"
    的 code_s 上跑(注释里的示例代码依然不会误报)。
    覆盖四种真实写法(REPORT6 的 s1/s2/s4/t4/s7 正是前几种的漏网之鱼):
      ① 解构     const { exec } = require('child_process') / import { execSync } from 'node:child_process'
      ② 别名     const cp = require('child_process'); cp.exec(…)
      ③ 命名空间 import * as cp from 'node:child_process'; cp.exec(…)
      ④ 内联     require('child_process').exec(…)
    never 裸报 \bexec\(:JS 里 RegExp.prototype.exec 到处都是,只有确认与 child_process 绑定才报。
    """
    NL = chr(10)
    SPEC = r"\s*['\"](?:node:)?child_process['\"]"
    ALT = r"(?:" + "|".join(names) + r")(?![\w$])"

    def line_of(m):
        return src.count(NL, 0, m.start()) + 1

    # ① 解构 / 命名导入:看引出来的名字
    for m in _re.finditer(r"(?:\{([^}]*)\}\s*=\s*require\s*\(|import\s*\{([^}]*)\}\s*from)" + SPEC, src):
        if _re.search(r"\b" + ALT, (m.group(1) or m.group(2) or "")):
            return line_of(m)
    # ② 别名 / 命名空间导入:看那个变量有没有被 .<name>( 调用
    for m in _re.finditer(r"(?:\b([A-Za-z_$][\w$]*)\s*=\s*require\s*\(|import\s+(?:\*\s*as\s+)?([A-Za-z_$][\w$]*)\s+from)" + SPEC, src):
        var = m.group(1) or m.group(2)
        if _re.search(r"\b" + _re.escape(var) + r"\s*\.\s*" + ALT, src):
            return line_of(m)
    # ③ 内联:require('child_process').<name>(…)
    for m in _re.finditer(r"require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)\s*\.\s*" + ALT, src):
        return line_of(m)
    return None


def _call_args(src, start):
    """取从 start 处那次调用的完整参数区间(按括号配对),而不是"往后 N 个字符"。

    为什么不能用固定字符窗口:那是"邻近性",不是"归属" —— 实测良性探针后面 90 字符处
    另一条语句里的 fetch 会被算进它的上下文(误报),而蓄意在参数内填 900 个字符又能把
    危险 token 推出窗口(绕过)。按括号配对取真正的参数区间,才是结构性归属的廉价近似。
    """
    i = src.find("(", start)
    if i < 0:
        return ""
    depth = 0
    end = min(len(src), i + 20000)
    for j in range(i, end):
        c = src[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return src[i:j + 1]
    return src[i:end]


def _shell_host_argv_line(src):
    """spawn/execFile 调 shell 本体、且参数里出现联网/管道执行 token 时的行号。

    用 tree-sitter 取调用的 arguments 节点范围,而不是自己数括号:手写配对会把字符串里的
    括号也算成结构括号,于是诱饵字符串(如 "echo ]]")能让参数区间提前截断,把后面的
    curl 留在区间外。真解析器对字符串/模板/注释/正则天然正确,这一类缺口随之消失。

    为什么不能单看程序名:Windows 插件用 powershell 做本地查询(Get-Process)是常见良性写法,
    一律报就是误报。所以两个条件同时成立才报:程序名是 shell 本体 **且** 参数里有动作类 token。
    已知边界(设计取舍,非缺陷):变量间接 spawn(B,…)、解释器包裹 spawn("env",["bash",…])、
    以及无网络的纯破坏性命令都不在覆盖内 —— 与本工具"主打外传/窃密/投毒"的定位一致。
    """
    if not HAVE_TS:
        # 没有解析器时退回朴素括号配对:可能被诱饵字符串截断,但比整类检查静默失效好
        NL = chr(10)
        for m in _re.finditer(_SPAWN_SHELL_HOST, src, _re.I):
            if _re.search(_SHELL_ARGV_DANGER, _call_args(src, m.start()), _re.I):
                return src.count(NL, 0, m.start()) + 1
        return None

    names = {"spawn", "spawnSync", "execFile"}
    hits = []

    def walk(node):
        if node.type == "call_expression":
            fn = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            if fn is not None and args is not None:
                callee = src[fn.start_byte:fn.end_byte].split(".")[-1]
                if callee in names:
                    argv = src[args.start_byte:args.end_byte]
                    if _re.match(r"""\(\s*['"](?:[^'"]*[\\/])?(?:sh|bash|zsh|cmd(?:\.exe)?|powershell|pwsh)(?:\.exe)?\s*['"]""", argv, _re.I) \
                       and _re.search(_SHELL_ARGV_DANGER, argv, _re.I):
                        hits.append(node.start_point[0] + 1)
            for c in node.named_children:
                walk(c)
            return
        for c in node.named_children:
            walk(c)

    try:
        walk(_TS_PARSER.parse(src.encode()).root_node)
    except RecursionError:
        return None
    return hits[0] if hits else None


def _shell_command_has_net(src):
    """exec('curl …') 这类:命令字符串是"真会执行的东西",不算噪音。

    剥离器抹字符串是为了防"注释里提一句 curl 就误报",但 exec/execSync 的参数恰恰是真命令 ——
    这里单独把参数取出来判网络行为,兼顾两头。
    """
    for m in _re.finditer(r"\b(?:exec|execSync)\s*\(\s*(['\"])((?:\\.|(?!\1).)*?)\1", src):
        if _re.search(r"\b(?:curl|wget|ncat|nc|/dev/tcp)\b", m.group(2)):
            return True
    return False


def _hit_line(src, pats, ignore_case=False):
    """第一条命中的行号(1-based),没命中返回 None。

    告警必须带行号+可自查的位置:否则用户只看到一个文件名,无法判断真伪,
    自然就学会了无视告警。
    """
    flags = _re.I if ignore_case else 0
    for pat in pats:
        m = _re.search(pat, src, flags)
        if m:
            return src.count(chr(10), 0, m.start()) + 1
    return None


MAX_SCAN_FILES = 2000   # 目录扫描的文件数上限(防止 scan 一个大目录吃满内存/时间)

def _hostile_scan(path):
    import os
    path = _norm_path(path)
    if os.path.isdir(path):
        files = []
        truncated = False
        for dp, dirs, fs in os.walk(path):
            # 剪枝:不进入插件自带的 node_modules —— 第三方依赖的代码不该算在插件头上
            # (实测某插件自身只有 18 个 .js,目录里却含 246 个嵌套依赖 .js)
            if "node_modules" in dirs:
                dirs.remove("node_modules")
            # 剪枝:不跟着符号链接/junction 跑出扫描根。os.walk 的 followlinks=False
            # 对 Windows junction 无效(它不是 symlink),实测能越界读到扫描根之外。
            dirs[:] = [d for d in dirs if not _is_reparse_point(_os.path.join(dp, d))]
            for f in fs:
                if f.endswith((".js", ".mjs", ".cjs")):
                    if len(files) >= MAX_SCAN_FILES:
                        truncated = True
                        break
                    files.append(os.path.join(dp, f))
            if truncated:
                break
    else:
        files = [path]
        truncated = False
    hits = []
    if truncated:
        hits.append(("warn", f"文件数超过上限,仅扫描前 {MAX_SCAN_FILES} 个", path))
    for f in files:
        # 单文件大小上限:与 check-file 同一把尺子(此前 scan 无界:50MB → 171MB 内存)
        try:
            if os.path.getsize(f) > MAX_CHECK_BYTES:
                hits.append(("warn", f"文件过大({os.path.getsize(f) // 1048576}MB),跳过扫描", f))
                continue
        except OSError:
            continue
        try:
            src = open(f, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        # 两遍剥离,各行其职:
        #   code   —— 注释+字符串都抹掉,用来判"代码干了什么"(字符串里写 exec 不算行为)
        #   code_s —— 只抹注释,保留字符串,用来判"引入了哪个模块"(模块名是语义,不是噪音)
        code = _strip_noise(src)
        code_s = _strip_noise(src, keep_strings=True)
        # 投毒标记本身就是"引用了哪个包名",必然出现在字符串里 → 用 code_s(注释已抹、字符串保留)
        ln = _hit_line(code_s, HOSTILE_MARKER)
        if ln:
            hits.append(("error", f"投毒/外传标记(第 {ln} 行)", f))
        # shell_exec:调用式(child_process.exec…)或引入式(require('child_process'))任一命中
        ln_shell = _hit_line(code, HOSTILE_HIGH["shell_exec"]) or _cp_import_line(code_s, ("exec", "execSync"))
        ln_eval = _hit_line(code, HOSTILE_HIGH["arbitrary_eval"])
        ln_secret = _hit_line(code, HOSTILE_HIGH["secret_read"])
        if ln_shell:
            hits.append(("warn", f"高危单信号:shell_exec(第 {ln_shell} 行)", f))
        if ln_eval:
            hits.append(("warn", f"高危单信号:arbitrary_eval(第 {ln_eval} 行)", f))
        if ln_secret:
            hits.append(("warn", f"高危单信号:secret_read(第 {ln_secret} 行)", f))
        has_net = _hit_line(code, HOSTILE_NET) is not None or _shell_command_has_net(code_s)
        # 组合信号:两个信号现在都来自真实代码,注释凑不出"疑似窃密"
        if has_net and ln_secret:
            hits.append(("warn", f"读密钥+网络(疑似窃密;密钥在第 {ln_secret} 行)", f))
        # shell 侧只用走 shell 的 exec/execSync:spawn/execFile 参数以数组传递、不经 shell,
        # 而"起子进程 + 联网"在真实插件里是常态(实测纳入后仅 11 个插件就刷出 46 条) ——
        # 宁可少查一类低风险行为,也不让门被噪音淹掉(REPORT5 的核心教训)。
        if has_net and ln_shell:
            hits.append(("warn", f"shell+网络(疑似外传;shell 在第 {ln_shell} 行)", f))
        # spawn 的两种无歧义形态(shell 宿主 / 调外传工具)——字符串里,所以在 code_s 上判
        ln_host = _shell_host_argv_line(code_s)
        if ln_host:
            hits.append(("warn", f"高危单信号:shell 执行(spawn 调 shell 本体 + 参数含联网/管道执行;第 {ln_host} 行)", f))
        ln_exfil = _hit_line(code_s, HOSTILE_SPAWN_EXFIL, ignore_case=True)
        if ln_exfil:
            hits.append(("warn", f"高危单信号:外传工具(spawn 调 curl/wget 等;第 {ln_exfil} 行)", f))
        ln = _hit_line(code, HOSTILE_PERSIST)
        if ln:
            hits.append(("warn", f"持久化/后门迹象(第 {ln} 行)", f))
    return hits

# ─────────────────────────── MCP server(--mcp,纯 stdlib)───────────────────────────
def _sanitize(s, limit=200):
    """把来自外部输入的内容净化成安全单行文本。

    必要性:MCP 的结论是给人/agent 读的纯文本。若外部输入(包名/路径/报错)原样拼进去,
    输入里的换行就能**伪造出额外的结论行**(实测可凭空多一行 "[ALLOW] 供应链: 无已知告警")。
    安全门最不该有的缺陷就是"可以被问它的问题操纵"。
    """
    import unicodedata
    out = []
    for ch in str(s):
        # 覆盖 C0/C1 控制符 + Unicode 行分隔符(U+2028/U+2029/U+0085):
        # 只判 ch < " " 是不够的 —— U+2028 等仍会被 splitlines() 当成换行,伪造依旧成立。
        if ch in ("\u2028", "\u2029", "\u0085") or unicodedata.category(ch)[0] == "C":
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)[:limit]

def _mcp_result_obj(package, path, client):
    """跑供应链 + 可选契约,返回结构化结果(供 MCP 返回)。"""
    name, ver = parse_pkg(package)
    v, d = check_supply(name, ver)
    lines = [f"[{v.upper()}] 供应链: {_sanitize(d, 300)}"]
    # 注意:三个标志都要在 if 外初始化 —— 否则"只查包名不带 path"时 has_unfinished 未定义,
    # 触发 UnboundLocalError(而这恰是 agent 最常用的调用方式)。
    file_findings, has_contract_error, has_unfinished = [], False, False
    if path:
        file_findings, _ = check_file(path, client)
        has_contract_error = any(l == "error" for l, _ in file_findings)
        has_unfinished = any(l == "unknown" for l, _ in file_findings)
        for lvl, msg in file_findings:
            lines.append(f"[{lvl.upper()}] 契约: {_sanitize(msg, 300)}")
    return {
        "verdict": v,
        "detail": d,
        "contract": file_findings,
        # isError 必须把契约 error 也算进去:否则语法坏掉的插件会拿到 isError:false,
        # 靠 isError 判断的 MCP 客户端会以为"调用成功、无问题"
        "isError": (v in ("block", "unknown")) or has_contract_error or has_unfinished,
        "text": "\n".join(lines),
    }

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
    def _dispatch(msg):
        """处理单条 JSON-RPC 消息。异常由调用方兜住 —— 主循环绝不退出。"""
        method = msg.get("method")
        rid = msg.get("id")
        if method == "initialize":
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}}, "serverInfo": {"name": "dsh-guard", "version": __version__}}}
        if method == "notifications/initialized" or (method or "").startswith("notifications"):
            return None
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": rid, "result": {"tools": [TOOL]}}
        if method == "tools/call":
            params = msg.get("params", {})
            name = params.get("name")
            args = params.get("arguments", {})
            if name != "dsh_guard_check":
                return {"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text", "text": f"unknown tool {_sanitize(name)}"}], "isError": True}}
            out = _mcp_result_obj(args.get("package", ""), args.get("path"), bool(args.get("client")))
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": out["text"]}],
                "isError": bool(out["isError"])}}
        return {"jsonrpc": "2.0", "id": rid, "result": {}}

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            continue
        rid = msg.get("id")
        try:
            resp = _dispatch(msg)
        except Exception as e:
            # 关键防护:任何异常都回一条 error 响应,主循环绝不退出。
            # 否则一次坏输入(例如传了不存在的路径)就能打死守门服务,此后所有调用全部 fail-open。
            resp = {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": f"[ERROR] dsh-guard 内部错误: {_sanitize(str(e))}"}],
                "isError": True}}
        if resp is not None:
            try:
                sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                sys.stdout.flush()
            except Exception:
                pass

# ─────────────────────────── 守门后放行(G4 safe-add)───────────────────────────
def _safe_add(pkg, path, client, delegate, yes=False):
    import subprocess
    name, ver = parse_pkg(pkg)
    v, d = check_supply(name, ver)
    print(f"[{v.upper()}] 供应链: {d}")
    findings = []
    if path:
        # ① 契约检查
        contract, _ = check_file(path, client)
        for lvl, msg in contract:
            print(f"[{lvl.upper()}] 契约: {msg}")
        findings += contract
        # ② 源码敌意扫描 —— 此前漏接:safe-add 只做契约检查,
        #    于是含 child_process.exec / 读密钥 / eval 的文件照样被判 SAFE 放行。
        hostile = [("error" if l == "error" else "warn", f"{k} ({_os.path.basename(f)})")
                   for l, k, f in _hostile_scan(path)]
        for lvl, msg in hostile:
            print(f"[{lvl.upper()}] 源码: {msg}")
        findings += hostile

    # 「没查成」≠「没问题」:unknown 表示检查未完成,一律硬拒,且 --yes 不能覆盖。
    # 否则网络失败 / 文件过大 / node 缺失 / 嵌套过深 这些降级路径,会变成攻击者的默认路径
    # (agent 的常规用法就是带 --yes)。
    has_unfinished = v == "unknown" or any(l == "unknown" for l, _ in findings)
    has_error = v == "block" or any(l == "error" for l, _ in findings)
    if has_error or has_unfinished:
        if has_error:
            print("REFUSED → 发现问题,不执行安装。")
            audit({"cmd": "safe-add", "target": pkg, "path": path, "verdict": "block", "detail": d})
        else:
            print("REFUSED → 检查未能完成,结果不可信,不执行安装。（--yes 不能覆盖未完成的检查）")
            audit({"cmd": "safe-add", "target": pkg, "path": path, "verdict": "unknown", "detail": d})
        return 1

    has_warn = v == "warn" or any(l == "warn" for l, _ in findings)
    if has_warn and delegate and not yes:
        import sys as _sys
        if not _sys.stdin.isatty():
            print("REFUSED → 有 warn 级发现,非交互环境需 --yes 显式放行。")
            audit({"cmd": "safe-add", "target": pkg, "path": path, "verdict": "warn-refused", "detail": d})
            return 1
        try:
            ans = input("有 warn 级发现,仍要执行? [y/N] ").strip().lower()
        except EOFError:
            # isatty() 为真 ≠ 读得到输入:agent/MCP 调用时 stdin 可能"连着终端但已 EOF"
            # (本机实测 isatty=True 却立刻 EOF)。这种"问不到人"要干净拒绝,
            # 而不是把未捕获的 traceback 抛给调用方。
            print("REFUSED → 读不到输入(非交互环境),需 --yes 显式放行。")
            audit({"cmd": "safe-add", "target": pkg, "path": path, "verdict": "warn-refused", "detail": d})
            return 1
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
            # 解析这一步以前没人管:直接 split(".") 再按 isdigit() 过滤,于是 "^1" 不是数字被整段丢掉
            # —— ^1.0.0 与 ^2.0.0 解析结果完全相同(都是 [0,0]),跳变检查在真实 profile 上全瞎
            # (而真实依赖的写法恰恰全是 ^)。
            # ① 剥掉范围前缀 ^ ~ >= <= > < = v 与空白;② 预发布串(-rc.1/-beta)只留前三段。
            raw = _re.sub(r"^[\s\^~=><!v]+", "", str(v).strip())
            raw = _re.split(r"[-+]", raw)[0]
            p = [int(x) for x in raw.split(".")[:3] if x.strip().isdigit()]
        except Exception:
            return None
        if not p:
            return None
        # 量纲归一化后再比较:
        #   0.x  → (0, minor)   —— 0.x 项目里 minor 变化才是"事实上的大版本"
        #   1.x+ → (1, major)   —— 进入正式版后只看 major
        # 旧写法"0.x 返回 minor、否则返回 major"是混合量纲:0.9.0 → 9,1.0.0 → 1,
        # 比出 1 > 9 = False,恰好漏掉 0.x→1.x 这个最剧烈的破坏性升级;
        # 而 1.0.0→0.9.0(降级)反被误报成跳变。
        # 也不能直接用 (major, minor):那样 1.0.0→1.5.0 会被误报(实际只是 minor 升级)。
        return (0, p[1] if len(p) > 1 else 0) if p[0] == 0 else (1, p[0])
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
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:12px}th,td{padding:7px 8px;border-bottom:1px solid #2a3040;text-align:left;vertical-align:top}th{color:#9aa4b5;font-weight:600}.tag{display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px}.tag.b{background:#c0392b;color:#fff}.tag.w{background:#c08a1f;color:#111}.tag.a{background:#1f7a3d;color:#fff}.tag.u{background:#5a6478;color:#fff}
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
const r=await fetch('/api/check?q='+encodeURIComponent(q)+'&mode='+m);const d=await r.json();const cls=d.verdict==='block'?'block':(d.verdict==='warn'?'warn':(d.verdict==='unknown'?'unknown':'allow'));
const t={block:'🔴 BLOCK 拦截',warn:'🟡 WARN 需确认',allow:'🟢 ALLOW 通过',unknown:'△ 检查未完成 — 不可据此放行'}[d.verdict]||d.verdict;
let h='<div class="verdict '+cls+'"><b>'+t+'</b> — '+esc(d.detail||'');(d.findings||[]).forEach(f=>h+='<div class="finding">'+esc(f)+'</div>');h+='</div><div class="act">';
if(d.verdict==='block')h+='<button class="no" onclick="c(\'block\')">拦截：不予安装</button>';else if(d.verdict==='unknown')h+='<button class="no" onclick="c(\'block\')">终止(检查未完成，不放行)</button>';else if(d.verdict==='warn')h+='<button class="go" onclick="c(\'allow\')">确认继续</button><button class="no" onclick="c(\'block\')">终止</button>';else h+='<button class="go" onclick="c(\'allow\')">确认</button>';h+='</div>';o.innerHTML=h;}
function esc(s){return String(s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
async function c(v){const q=document.getElementById('q').value;await fetch('/api/consent',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:q,decision:v})});document.getElementById('out').innerHTML='<div class="verdict allow">已记录你的决定：<b>'+(v==='allow'?'放行':'拦截')+'</b></div>';}
async function loadHist(){const f=document.getElementById('hf').value.trim(),o=document.getElementById('hist');o.innerHTML='<div class="verdict" style="border-color:#3a4152;color:#9aa4b5">加载中…</div>';
const r=await fetch('/api/history?f='+encodeURIComponent(f));const d=await r.json();
if(!d.length){o.innerHTML='<div class="verdict" style="border-color:#3a4152;color:#9aa4b5">(暂无历史记录 — 先跑一次检查)</div>';return;}
let h='<table><tr><th>时间</th><th>结论</th><th>命令</th><th>目标</th></tr>';
d.forEach(e=>{const v=e.verdict||'',tag=v==='block'?'b':(v==='warn'?'w':'a'),label=v==='block'?'BLOCK':(v==='warn'?'WARN':(v==='unknown'?'未完成':'ALLOW'));
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
                # 检查未完成(unknown)必须单独露出,不能悄悄留在默认的 allow
                if any(l == "error" for l, _ in fnd):
                    verdict = "block"
                elif any(l == "unknown" for l, _ in fnd):
                    verdict = "unknown"
                detail = "契约检查"
            elif mode == "scan":
                hits = _hostile_scan(p)
                for l, k, f in hits: findings.append(f"[{l}] {k}: {os.path.basename(f)}")
                if any(l == "error" for l, _, _ in hits):
                    verdict = "block"
                elif any(l == "warn" for l, _, _ in hits):
                    verdict = "warn"
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
        def _origin_ok(self):
            """CSRF 防护:浏览器的跨站请求一定带 Origin/Referer,必须校验为本机 UI。

            否则任意恶意网页都能 POST /api/consent,往审计日志里塞"放行"假记录,污染证据链
            (dsh 实测:Content-Type: text/plain 可绕过 CORS 预检,浏览器会真的发出去)。
            无 Origin/Referer 的是本机命令行客户端(如 curl),不构成 CSRF,放行。
            """
            local = ("http://127.0.0.1:%s" % port, "http://localhost:%s" % port)

            def _same_site(u):
                # 必须"整个 authority 相同",不能只用 startswith:
                # 否则 http://127.0.0.1:8170.evil.com 这种以本机地址开头的恶意域名也能混过。
                return any(u == pre or u.startswith(pre + "/") for pre in local)

            origin = self.headers.get("Origin")
            if origin is not None:
                return origin in local
            referer = self.headers.get("Referer")
            if referer is not None:
                return _same_site(referer)
            return True
        def do_GET(self):
            # GET 同样是副作用入口(会发起网络查询、读任意路径文件、起 node 子进程),
            # 跨站可盲触发做探测/DoS → 与 POST 一样校验 Origin
            if not self._host_ok() or not self._origin_ok():
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
            if not self._host_ok() or not self._origin_ok():
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
        sys.exit(0 if v not in ("block", "unknown") else 1)
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
