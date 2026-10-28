"""
scan.py -- Stage 3b: the "Smart Checker". Hybrid detector = AST rules + trained ML model.

    python scan.py target.py                 # one-shot scan
    python scan.py target.py --watch         # re-scan every time the file is saved (real-time)
    python scan.py src/ --model model.joblib # scan a directory
    python scan.py target.py --rules-only    # skip the ML model entirely
    python scan.py target.py --threshold 0.4 # override the model's decision threshold

A function is flagged if EITHER
    * the rule engine found concrete evidence (dangerous call + tainted/dynamic argument, etc.), OR
    * the model's risk score is >= the threshold.
"""
import argparse
import os
import time

from features import extract, split_functions


def load_bundle(path, rules_only=False):
    if rules_only:
        return None
    if not os.path.exists(path):
        print(f"[warn] model '{path}' not found -> running rules-only")
        return None
    import joblib
    bundle = joblib.load(path)
    bundle["clf"].n_jobs = 1          # avoid spinning up a thread pool for every tiny predict call
    return bundle


MODEL_ONLY_MIN = 0.5   # a model-only flag (no rule evidence) must score at least this high


def scan_source(code, bundle, path="<stdin>", threshold=None, model_only_min=MODEL_ONLY_MIN):
    items = []
    for name, start, src in split_functions(code):
        feats, evidence = extract(src)
        if feats is None:
            continue
        items.append((name, start, feats, evidence, src))
    if not items:
        return []

    scores = [0.0] * len(items)
    thr = 2.0                          # impossible threshold when there is no model
    if bundle is not None:
        thr = threshold if threshold is not None else bundle["threshold"]
        X = bundle["vec"].transform([it[2] for it in items])     # one batched call
        scores = bundle["clf"].predict_proba(X)[:, 1]

    results = []
    for (name, start, _, evidence, src), p in zip(items, scores):
        by_rules = bool(evidence)
        by_model = float(p) >= thr and (by_rules or float(p) >= model_only_min)
        if by_model or by_rules:
            results.append({
                "file": path, "function": name, "line": start, "end": start + src.count("\n"), "score": float(p),
                "by": "+".join(x for x, ok in (("rules", by_rules), ("model", by_model)) if ok),
                "evidence": [(start + ln - 1, fam, msg) for ln, fam, msg in evidence],
            })
    return results


def report(results, ms, have_model):
    if not results:
        print(f"  no vulnerabilities flagged  ({ms:.0f} ms)")
        return
    for r in sorted(results, key=lambda r: (-len(r["evidence"]), -r["score"])):
        risk = f"  model-risk={r['score']:.2f}" if have_model else ""
        print(f"  [!] {r['file']}:{r['line']}  {r['function']}()  [{r['by']}]{risk}")
        for ln, fam, msg in r["evidence"]:
            print(f"        line {ln}: {fam}: {msg}")
    n_ev = sum(len(r["evidence"]) for r in results)
    print(f"  -> {len(results)} function(s) flagged, {n_ev} finding(s)  ({ms:.0f} ms)")


def scan_path(path, bundle, threshold=None):
    files = []
    if os.path.isdir(path):
        for root, _, fs in os.walk(path):
            files += [os.path.join(root, f) for f in fs if f.endswith(".py")]
    else:
        files = [path]
    for fp in files:
        t0 = time.perf_counter()
        with open(fp, encoding="utf-8", errors="ignore") as fh:
            res = scan_source(fh.read(), bundle, fp, threshold)
        print(f"\n{fp}")
        report(res, (time.perf_counter() - t0) * 1000, bundle is not None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--model", default="model.joblib")
    ap.add_argument("--rules-only", action="store_true", help="ignore the ML model")
    ap.add_argument("--threshold", type=float, default=None, help="override model threshold")
    ap.add_argument("--watch", action="store_true")
    a = ap.parse_args()
    bundle = load_bundle(a.model, a.rules_only)

    scan_path(a.path, bundle, a.threshold)
    if a.watch:
        last = os.path.getmtime(a.path)
        print("\nwatching for changes (Ctrl+C to stop)...")
        while True:
            time.sleep(0.3)
            m = os.path.getmtime(a.path)
            if m != last:
                last = m
                scan_path(a.path, bundle, a.threshold)


if __name__ == "__main__":
    main()
