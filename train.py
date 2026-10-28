"""
train.py -- Stage 3a: train the Random Forest on a REAL labelled dataset.

Input: CSV or JSONL with columns
    code   : source of ONE function (or snippet)
    label  : 1 = vulnerable, 0 = safe
    group  : (optional but strongly recommended) project / commit / CVE id.
             Used for a group-wise split so near-duplicate functions from the
             same project never appear in both train and test (prevents leakage).

Usage:
    python train.py --data cvefixes_python.csv --out model.joblib
"""
import argparse
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_curve, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit, train_test_split

from features import extract


def load(path):
    if path.endswith(".jsonl"):
        return pd.read_json(path, lines=True)
    return pd.read_csv(path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--out", default="model.joblib")
    ap.add_argument("--trees", type=int, default=300)
    ap.add_argument("--target-recall", type=float, default=0.85,
                    help="pick the highest threshold that still reaches this recall")
    args = ap.parse_args()

    df = load(args.data).dropna(subset=["code", "label"])
    print(f"[data] {len(df)} samples | vulnerable={int(df.label.sum())} safe={int((1 - df.label).sum())}")

    rows, y, groups = [], [], []
    for i, r in df.iterrows():
        f, _ = extract(str(r["code"]))
        if f is None:               # unparsable -> skip
            continue
        rows.append(f)
        y.append(int(r["label"]))
        groups.append(r["group"] if "group" in df.columns else i)
    y = np.array(y)
    print(f"[parse] {len(rows)}/{len(df)} samples parsed into ASTs")

    vec = DictVectorizer(sparse=False)
    X = vec.fit_transform(rows)
    print(f"[features] {X.shape[1]} features")

    if "group" in df.columns:
        gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
        tr, te = next(gss.split(X, y, groups))
    else:
        print("[warn] no 'group' column: using random split (results may be optimistic)")
        tr, te = train_test_split(np.arange(len(y)), test_size=0.2, random_state=42, stratify=y)

    clf = RandomForestClassifier(
        n_estimators=args.trees, max_depth=None, min_samples_leaf=2,
        class_weight="balanced_subsample", n_jobs=-1, random_state=42)
    clf.fit(X[tr], y[tr])

    proba = clf.predict_proba(X[te])[:, 1]
    print(f"[eval] ROC-AUC = {roc_auc_score(y[te], proba):.3f}")

    # choose a decision threshold: high precision while keeping recall (fewer false alarms)
    p, r, t = precision_recall_curve(y[te], proba)
    ok = np.where(r[:-1] >= args.target_recall)[0]
    thr = float(t[ok[-1]]) if len(ok) else 0.5
    thr = min(max(thr, 0.3), 0.7)   # keep the cut-off in a sane range (avoid thr=1.0 on easy data)
    pred = (proba >= thr).astype(int)
    print(f"[eval] threshold = {thr:.3f}")
    print(classification_report(y[te], pred, target_names=["safe", "vulnerable"], digits=3))
    print("confusion matrix [[TN FP] [FN TP]]:\n", confusion_matrix(y[te], pred))

    t0 = time.perf_counter()
    for code in df["code"].head(200):
        f, _ = extract(str(code))
        if f is not None:
            clf.predict_proba(vec.transform([f]))
    n = min(200, len(df))
    print(f"[latency] avg parse+predict = {(time.perf_counter() - t0) / n * 1000:.1f} ms / function")

    imp = sorted(zip(vec.feature_names_, clf.feature_importances_), key=lambda x: -x[1])[:15]
    print("[top features]")
    for k, v in imp:
        print(f"   {k:32s} {v:.4f}")

    joblib.dump({"vec": vec, "clf": clf, "threshold": thr}, args.out)
    print(f"[saved] {args.out}")


if __name__ == "__main__":
    main()
