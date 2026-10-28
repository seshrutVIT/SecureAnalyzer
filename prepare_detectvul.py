"""
prepare_detectvul.py -- download the Python dataset DetectVul/CVEFixes from Hugging Face and
convert it into the CSV (code,label,group) that train.py expects.

    pip install datasets
    python prepare_detectvul.py --out detectvul_python.csv

The dataset is labelled per STATEMENT (fields: lines, raw_lines, label, type).
We rebuild each function from `raw_lines` and call it vulnerable (1) if ANY statement is labelled 1.

This script prints diagnostics so you can check the assumptions on the first run:
  - the field names / one example row
  - the distribution of label values
  - how many rebuilt functions actually parse as Python
"""
import argparse
import ast
import csv
import hashlib
import textwrap
from collections import Counter


def parses(code):
    try:
        ast.parse(code)
        return True
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False


def convert(rows, min_lines=2, max_lines=300, verbose=True):
    """rows: iterable of dicts with 'raw_lines' (list[str]) and 'label' (list[int])."""
    out, seen = [], set()
    st = Counter()
    label_values = Counter()
    for r in rows:
        st["rows"] += 1
        raw, lab = r.get("raw_lines"), r.get("label")
        if not raw or lab is None:
            st["missing"] += 1
            continue
        label_values.update(lab)
        code = textwrap.dedent("\n".join(raw)).strip("\n") + "\n"
        n = code.count("\n")
        if n < min_lines or n > max_lines:
            st["size"] += 1
            continue
        if not parses(code):
            st["unparsable"] += 1
            continue
        y = int(any(int(v) == 1 for v in lab))
        if (code, y) in seen:
            st["dup"] += 1
            continue
        seen.add((code, y))
        # No commit/project column exists in this dataset, so use a proxy group: the signature line.
        # The vulnerable and fixed versions of one function share it, so they stay on the same side
        # of the train/test split.
        first = next((l.strip() for l in code.splitlines() if l.strip()), "")
        grp = hashlib.md5(first.encode()).hexdigest()[:12]
        out.append((code, y, grp))
        st["kept"] += 1
    if verbose:
        print("[diag] label values seen (per statement):", dict(label_values))
        print("[diag]", dict(st))
        pos = sum(y for _, y, _ in out)
        print(f"[diag] functions kept={len(out)}  vulnerable={pos}  safe={len(out) - pos}")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="DetectVul/CVEFixes")
    ap.add_argument("--out", default="detectvul_python.csv")
    a = ap.parse_args()

    from datasets import load_dataset
    ds = load_dataset(a.repo)
    print("[info] splits:", {k: len(v) for k, v in ds.items()})
    first_split = next(iter(ds.values()))
    print("[info] columns:", first_split.column_names)
    ex = first_split[0]
    print("[info] example raw_lines[:3]:", ex.get("raw_lines", [])[:3])
    print("[info] example label[:10]  :", ex.get("label", [])[:10])

    rows = (r for split in ds.values() for r in split)
    out = convert(rows)

    with open(a.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["code", "label", "group"])
        w.writerows(out)
    print(f"[done] wrote {a.out}")
    if len(out) < 200:
        print("[warn] very few functions parsed. Look at the example above: if raw_lines lost their "
              "indentation, the rebuilt code won't parse. Paste the [info]/[diag] lines to me.")


if __name__ == "__main__":
    main()
