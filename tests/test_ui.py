import os
import dsh_guard

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

def test_ui_supply_block():
    assert dsh_guard._api_check("@antv/mcp-server-chart@0.11.10", "supply")["verdict"] == "block"
def test_ui_supply_allow():
    assert dsh_guard._api_check("@antv/mcp-server-chart@0.9.10", "supply")["verdict"] == "allow"
def test_ui_contract_block():
    assert dsh_guard._api_check(os.path.join(FIX, "bad_await.js"), "contract")["verdict"] == "block"
def test_ui_contract_ok():
    assert dsh_guard._api_check(os.path.join(FIX, "good.js"), "contract")["verdict"] == "allow"
def test_ui_html_complete():
    h = dsh_guard.UI_HTML
    assert ("function go()" in h)
    assert "/api/check" in h and "/api/consent" in h
