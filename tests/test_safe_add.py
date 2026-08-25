import os, subprocess, sys, json
import pytest
import dsh_guard

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def cli(*args):
    return subprocess.run([sys.executable, os.path.join(ROOT, "dsh_guard.py"), *args],
                          capture_output=True, text=True)

def test_safe_add_refuses_block():
    # 恶意包 → 拒绝执行 delegate(不调用),exit 非0
    r = cli("safe-add", "@antv/mcp-server-chart@0.11.10", "--delegate", "echo SHOULD_NOT_RUN")
    assert r.returncode != 0
    assert "REFUSED" in r.stdout
    assert "SHOULD_NOT_RUN" not in r.stdout  # delegate 未执行

def test_safe_add_allows_and_delegates(monkeypatch):
    # 干净包 + 契约通过 → 执行 delegate
    r = cli("safe-add", "@antv/mcp-server-chart@0.9.10",
            "--path", os.path.join(ROOT, "tests", "fixtures", "good.js"),
            "--delegate", "echo SHOULD_RUN")
    assert r.returncode == 0
    assert "SAFE" in r.stdout
    assert "SHOULD_RUN" in r.stdout

def test_safe_add_contract_error_refuses():
    # 契约 error(await 雷)→ 拒绝
    fx = os.path.join(ROOT, "tests", "fixtures", "bad_await.js")
    r = cli("safe-add", "@antv/mcp-server-chart@0.9.10", "--path", fx, "--delegate", "echo NO")
    assert r.returncode != 0
    assert "REFUSED" in r.stdout

def test_safe_add_no_delegate_exit_zero():
    r = cli("safe-add", "@antv/mcp-server-chart@0.9.10")
    assert r.returncode == 0
