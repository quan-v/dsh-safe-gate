import dsh_guard

def test_major_jump_true():
    assert dsh_guard._major_jump("0.9.10", "0.10.0") is True
def test_major_jump_false_patch():
    assert dsh_guard._major_jump("0.9.10", "0.9.11") is False
def test_major_jump_false_minor():
    assert dsh_guard._major_jump("1.0.0", "1.5.0") is False
def test_major_jump_none_before():
    assert dsh_guard._major_jump(None, "1.2.3") is False
def test_snapshot_reads_profile():
    s = dsh_guard._snapshot()
    assert "plugins" in s and isinstance(s["plugins"], dict)
