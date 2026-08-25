import os
import pytest
import dsh_guard

# 可选网络冒烟测试:默认跳过,设 RUN_NETWORK=1 才跑。
# 验证 OSV 真能查到 @antv/mcp-server-chart 的 MAL-2026-4069(不 mock)。
pytestmark = pytest.mark.skipif(os.environ.get("RUN_NETWORK") != "1",
                                reason="网络测试,设 RUN_NETWORK=1 启用")

def test_real_malicious_blocked():
    v, d = dsh_guard.check_supply("@antv/mcp-server-chart", "0.11.10")
    assert v == "block" and "MAL-2026-4069" in d

def test_real_clean_version_allowed():
    v, d = dsh_guard.check_supply("@antv/mcp-server-chart", "0.9.10")
    assert v == "allow"
