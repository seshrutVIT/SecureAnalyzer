"""
app.py -- local web GUI for scan.py.

    pip install flask
    python app.py            # opens http://127.0.0.1:5000

Runs only on your machine (127.0.0.1). Put it in the same folder as scan.py, features.py,
index.html and model.joblib.
"""
import argparse
import ast
import hashlib
import os
import subprocess
import sys
import threading
import time
import webbrowser

from flask import Flask, jsonify, request, send_from_directory

import scan as scanner

BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
SKIP = {"__pycache__", "node_modules", "venv", "env", "site-packages", "build", "dist"}
_models = {}


def get_bundle(name):
    """Returns (bundle|None, error|None, default_threshold|None)."""
    cands = [name] if os.path.isabs(name) else [os.path.join(BASE, name), os.path.join(os.getcwd(), name)]
    p = next((c for c in cands if os.path.isfile(c)), None)
    if not p:
        return None, f"Model file not found: {name}", None
    key = (p, os.path.getmtime(p))
    if key not in _models:
        try:
            import joblib
            b = joblib.load(p)
            b["clf"].n_jobs = 1
            _models[key] = b
        except Exception as e:  # noqa: BLE001
            return None, f"Could not load model: {e}", None
    b = _models[key]
    return b, None, float(b["threshold"])


def list_py(path):
    if os.path.isfile(path):
        return [path]
    out = []
    for root, dirs, files in os.walk(path):
        dirs[:] = sorted(d for d in dirs if d not in SKIP and not d.startswith("."))
        out += [os.path.join(root, f) for f in sorted(files) if f.endswith(".py")]
        if len(out) > 2000:
            break
    return out


def signature(path):
    h = hashlib.md5()
    for f in list_py(path):
        try:
            st = os.stat(f)
            h.update(f"{f}{st.st_mtime_ns}{st.st_size}".encode())
        except OSError:
            pass
    return h.hexdigest()


@app.get("/")
def index():
    return send_from_directory(BASE, "index.html")


@app.get("/api/info")
def info():
    b, err, thr = get_bundle(request.args.get("model") or "model.joblib")
    return jsonify(available=b is not None, error=err, threshold=thr)


@app.post("/api/browse")
def browse():
    kind = (request.get_json(force=True) or {}).get("kind", "file")
    code = ("import sys, tkinter as tk\nfrom tkinter import filedialog as fd\n"
            "r = tk.Tk(); r.withdraw(); r.attributes('-topmost', True)\n"
            "p = fd.askopenfilename(filetypes=[('Python files', '*.py')]) if sys.argv[1] == 'file' else fd.askdirectory()\n"
            "print(p)\n")
    try:
        r = subprocess.run([sys.executable, "-c", code, kind], capture_output=True, text=True, timeout=600)
        return jsonify(path=os.path.normpath(r.stdout.strip()) if r.stdout.strip() else "")
    except Exception as e:  # noqa: BLE001
        return jsonify(error=f"File dialog unavailable ({e}). Type the path instead."), 500


@app.get("/api/file")
def get_file():
    p = request.args.get("path", "")
    if not p.endswith(".py") or not os.path.isfile(p):
        return jsonify(error="Not a Python file"), 400
    with open(p, encoding="utf-8", errors="ignore") as fh:
        return jsonify(text=fh.read())


@app.get("/api/sig")
def sig():
    p = request.args.get("path", "")
    return jsonify(sig=signature(p) if os.path.exists(p) else "")


@app.post("/api/scan")
def scan():
    d = request.get_json(force=True)
    path = d.get("path", "")
    if not path or not os.path.exists(path):
        return jsonify(error=f"Path not found: {path}"), 400
    sg = signature(path)
    bundle, model_err, default_thr = (None, None, None)
    if not d.get("rules_only"):
        bundle, model_err, default_thr = get_bundle(d.get("model") or "model.joblib")
    thr = float(d.get("threshold", default_thr if default_thr is not None else 0.5))
    base = os.path.dirname(path) if os.path.isfile(path) else path
    t_all, files = time.perf_counter(), []
    for fp in list_py(path):
        t0 = time.perf_counter()
        e = {"path": fp, "rel": os.path.relpath(fp, base), "results": []}
        try:
            with open(fp, encoding="utf-8", errors="ignore") as fh:
                code = fh.read()
            ast.parse(code)
            for r in scanner.scan_source(code, bundle, fp, thr, thr):
                e["results"].append({
                    "function": r["function"], "line": r["line"], "end": r["end"], "by": r["by"],
                    "score": r["score"] if bundle else None,
                    "evidence": [{"line": ln, "family": f, "message": m} for ln, f, m in r["evidence"]]})
        except (SyntaxError, ValueError, RecursionError) as ex:
            e["error"] = f"Could not parse ({ex.__class__.__name__}, line {getattr(ex, 'lineno', '?')})"
        except OSError as ex:
            e["error"] = str(ex)
        e["ms"] = (time.perf_counter() - t0) * 1000
        files.append(e)
    return jsonify(files=files, sig=sg, model_used=bundle is not None, model_error=model_err,
                   threshold=thr, total_ms=(time.perf_counter() - t_all) * 1000)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=5000)
    a = ap.parse_args()
    threading.Timer(1.0, lambda: webbrowser.open(f"http://127.0.0.1:{a.port}")).start()
    app.run(host="127.0.0.1", port=a.port, debug=False)
