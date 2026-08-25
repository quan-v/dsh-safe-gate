import os
import dsh_guard

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
def fx(name): return os.path.join(FIX, name)

def msgs(path, client=False):
    f, _ = dsh_guard.check_file(path, client)
    return [m for lvl, m in f]

def errors(path, client=False):
    f, _ = dsh_guard.check_file(path, client)
    return [m for lvl, m in f if lvl == "error"]

# ── 真阳性:每个 bug 必须被抓 ──
def test_await_bug_caught():
    assert any("await 出现在非 async" in m for m in msgs(fx("bad_await.js")))

def test_inject_bug_caught():
    assert any("inject 含 'logger'" in m for m in msgs(fx("bad_inject.js")))

def test_keyed_bug_caught():
    assert any("缺显式 key" in m for m in msgs(fx("bad_keyed.js")))

def test_adapter_bug_caught():
    assert any("prepareCall" in m for m in msgs(fx("bad_adapter.js")))

# ── 零误报:好代码不许被冤枉 ──
def test_good_clean():
    assert errors(fx("good.js")) == []

def test_good_adapter_clean():
    assert errors(fx("good_adapter.js")) == []

# ── 真实 dsh 插件回归护栏 ──
REAL = r"%USERPROFILE%\.dsh\profiles\web\node_modules"
def test_vision_router_no_error():
    assert errors(os.path.join(REAL, "dsh-vision-router", "index.js")) == []

def test_mcp_ui_client_no_error():
    assert errors(os.path.join(REAL, "dsh-mcp-ui", "lib", "client.js"), client=True) == []
