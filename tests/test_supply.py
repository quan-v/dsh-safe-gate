import dsh_guard
from dsh_guard import parse_pkg, check_supply

# ── 包名解析 ──
def test_parse_scoped_with_version():
    assert parse_pkg("@antv/mcp-server-chart@0.11.10") == ("@antv/mcp-server-chart", "0.11.10")

def test_parse_scoped_no_version():
    assert parse_pkg("@antv/mcp-server-chart") == ("@antv/mcp-server-chart", None)

def test_parse_unscoped_with_version():
    assert parse_pkg("lodash@4.17.21") == ("lodash", "4.17.21")

def test_parse_unscoped_no_version():
    assert parse_pkg("lodash") == ("lodash", None)

# ── 供应链判定(mock OSV,不打网络)──
def test_floating_version_warns():
    v, d = check_supply("@antv/mcp-server-chart", None)
    assert v == "warn" and "pinning" in d

def test_malicious_blocks(monkeypatch):
    monkeypatch.setattr(dsh_guard, "osv_query",
                        lambda n, v: {"vulns": [{"id": "MAL-2026-4069", "summary": "Malicious code in x"}]})
    v, d = check_supply("@antv/mcp-server-chart", "0.11.10")
    assert v == "block"

def test_cve_warns(monkeypatch):
    monkeypatch.setattr(dsh_guard, "osv_query",
                        lambda n, v: {"vulns": [{"id": "CVE-2026-0001"}]})
    v, d = check_supply("x", "1.0.0")
    assert v == "warn"

def test_clean_allows(monkeypatch):
    monkeypatch.setattr(dsh_guard, "osv_query", lambda n, v: {"vulns": []})
    v, d = check_supply("x", "1.0.0")
    assert v == "allow"
