import os, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def cli(*args):
    return subprocess.run([sys.executable, os.path.join(ROOT, "dsh_guard.py"), *args],
                          capture_output=True, text=True)

def test_cli_check_file_bad_exit_nonzero():
    r = cli("check-file", os.path.join(ROOT, "tests", "fixtures", "bad_await.js"))
    assert r.returncode != 0

def test_cli_check_file_good_exit_zero():
    r = cli("check-file", os.path.join(ROOT, "tests", "fixtures", "good.js"))
    assert r.returncode == 0

def test_cli_check_file_client_good_exit_zero():
    r = cli("check-file", os.path.join(ROOT, "tests", "fixtures", "good.js"), "--client")
    assert r.returncode == 0

def test_cli_check_file_missing_client_half():
    r = cli("check-file", os.path.join(ROOT, "tests", "fixtures", "good.js"))
    assert "退出" not in r.stdout  # 良好 fixture 不产生意外输出
