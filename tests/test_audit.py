import os, subprocess, sys, tempfile, json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(tempfile.gettempdir(), "dg_test_audit.jsonl")
if os.path.exists(LOG): os.remove(LOG)

def cli(*args):
    env = dict(os.environ, DSH_GUARD_LOG=LOG)
    return subprocess.run([sys.executable, os.path.join(ROOT, "dsh_guard.py"), *args],
                          capture_output=True, text=True, env=env)

def test_check_writes_log():
    cli("check", "@antv/mcp-server-chart@0.9.10")   # allow
    assert os.path.exists(LOG)
    txt = open(LOG, encoding="utf-8").read()
    rec = [json.loads(l) for l in txt.splitlines() if l.strip()]
    assert any(r["cmd"] == "check" and r["verdict"] == "allow" for r in rec)

def test_log_subcommand_reads_back():
    cli("check", "@antv/mcp-server-chart@0.9.10")
    r = cli("log", "-n", "10")
    assert "verdict" in r.stdout and "check" in r.stdout
