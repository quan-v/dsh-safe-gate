import os, subprocess, sys, tempfile, json
import dsh_guard

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _cli(*args):
    return subprocess.run([sys.executable, os.path.join(ROOT, "dsh_guard.py"), *args],
                          capture_output=True, text=True)

def test_norm_path_handles_msys():
    p = os.path.join(tempfile.gettempdir(), "dg_np.js")
    open(p, "w", encoding="utf-8").write("")
    try:
        # MSYS 形式 /c/Users/.../dg_np.js
        drive = os.path.splitdrive(p)[0].replace(":", "")   # "C"
        rc = p.split(":", 1)[1].replace("\\", "/")          # "/Users/.../dg_np.js"
        msys = f"/{drive.lower()}{rc}"
        normed = dsh_guard._norm_path(msys)
        assert os.path.exists(normed), "归一化后应指向存在的文件"
        assert os.path.normcase(normed) == os.path.normcase(p), "应解析到同一文件"
        assert dsh_guard._norm_path(p) == p, "Windows 路径应原样"
    finally:
        os.remove(p)

def test_json_output_check_file():
    fx = os.path.join(ROOT, "tests", "fixtures", "bad_await.js")
    r = _cli("check-file", fx, "--json")
    data = json.loads(r.stdout)
    assert data["verdict"] == "error" and any("await" in m for m in data["findings"])

def test_json_output_scan():
    p = os.path.join(tempfile.gettempdir(), "dg_json_scan.js")
    open(p, "w", encoding="utf-8").write("kitty-monitor:1\n")
    try:
        r = _cli("scan", p, "--json")
        data = json.loads(r.stdout)
        assert data["verdict"] == "error"
    finally:
        os.remove(p)
