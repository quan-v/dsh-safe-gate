import os, subprocess, sys, json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def mcp(lines):
    r = subprocess.run([sys.executable, os.path.join(ROOT, "dsh_guard.py"), "--mcp"],
                       input="\n".join(lines) + "\n", capture_output=True, text=True)
    return [json.loads(l) for l in r.stdout.strip().splitlines() if l.strip()]

def test_initialize_caps():
    out = mcp(['{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'])
    assert out[0]["result"]["capabilities"]["tools"] == {}
    assert out[0]["result"]["serverInfo"]["name"] == "dsh-guard"

def test_tools_list_has_guard():
    out = mcp(['{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}',
               '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'])
    tools = [t["name"] for t in out[1]["result"]["tools"]]
    assert "dsh_guard_check" in tools

def test_call_block_on_malicious():
    out = mcp(['{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}',
               '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"dsh_guard_check","arguments":{"package":"@antv/mcp-server-chart@0.11.10"}}}'])
    r = out[1]["result"]
    assert r["isError"] is True
    assert "MAL-2026-4069" in r["content"][0]["text"]

def test_call_allow_on_clean():
    out = mcp(['{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}',
               '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"dsh_guard_check","arguments":{"package":"@antv/mcp-server-chart@0.9.10"}}}'])
    r = out[1]["result"]
    assert r["isError"] is False
    assert "ALLOW" in r["content"][0]["text"]
