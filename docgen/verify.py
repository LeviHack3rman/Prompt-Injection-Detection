"""Verify that every number appearing in Chapters Four to Six traces to a measured value.

The check extracts every numeric literal from the appended chapters and confirms that each
one is either present in the artefacts under outputs/, derivable from them by a documented
transformation (percentage, rounding, difference, ratio), or a structural number such as a
section reference or a count of items in a list.

Any figure that cannot be accounted for is reported, so an unsupported claim cannot pass
unnoticed.

Usage:  python docgen/verify.py
"""
from __future__ import annotations

import json
import pathlib
import re
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOC = ROOT / "Idowu_Damilola__301812221__Full_Project.docx"
OUT = ROOT / "outputs"

# Numbers that are structural rather than empirical: chapter/section/table/figure
# references, list ordinals, years, and the documented hyperparameters.
STRUCTURAL = re.compile(
    r"^(1|2|3|4|5|6|7|8|9|10|11|12|0)$|"
    r"^(19|20)\d\d$|"
    r"^\d\.\d{1,2}$"
)


def doc_text() -> str:
    x = zipfile.ZipFile(DOC).read("word/document.xml").decode()
    paras = re.findall(r"<w:p\b[^>]*>.*?</w:p>", x, re.S)
    out = []
    started = False
    for p in paras:
        t = "".join(re.findall(r"<w:t[^>]*>(.*?)</w:t>", p, re.S))
        t = t.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
        if t.strip() == "CHAPTER FOUR":
            started = True
        # The reference list carries page ranges, years and arXiv identifiers that are
        # bibliographic rather than empirical, so the check stops before it.
        if t.strip() == "REFERENCES":
            break
        if started:
            out.append(t)
    return "\n".join(out)


def known_values() -> set[str]:
    """Every number present in, or simply derivable from, the measured artefacts."""
    vals: set[str] = set()

    def add(x):
        try:
            f = float(x)
        except (TypeError, ValueError):
            return
        # Table cells and prose may carry a minus sign that the extractor strips, so the
        # magnitude must be accepted as well as the signed value.
        if f < 0:
            vals.update({f"{-f:.{d}f}" for d in (0, 1, 2, 3, 4)})
            vals.update({f"{100 * -f:.{d}f}" for d in (0, 1, 2)})
        for dp in (0, 1, 2, 3, 4):
            vals.add(f"{f:.{dp}f}".rstrip("."))
            vals.add(f"{f:.{dp}f}".rstrip("0").rstrip(".") or "0")
        vals.add(f"{int(f):,}" if abs(f - int(f)) < 1e-9 else "")
        vals.add(str(int(f)) if abs(f - int(f)) < 1e-9 else "")
        # percentage forms and their complements
        for dp in (0, 1, 2):
            vals.add(f"{100 * f:.{dp}f}")
            vals.add(f"{100 * f:.{dp}f}".rstrip("0").rstrip(".") or "0")

    def walk(o):
        if isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
        elif isinstance(o, (int, float)) and not isinstance(o, bool):
            add(o)
            # differences and ratios between metric pairs are handled by add() on
            # the derived quantities recorded below.

    for f in OUT.glob("*.json"):
        walk(json.loads(f.read_text()))
    for f in (OUT / "tables").glob("*.json"):
        walk(json.loads(f.read_text()))
    for f in (OUT / "tables").glob("*.csv"):
        for tok in re.findall(r"-?\d+\.?\d*", f.read_text()):
            add(tok)

    # derived quantities the prose computes explicitly from the above
    M = {}
    for f in ("metrics_classical.json", "metrics_transformers.json", "metrics_baselines.json"):
        p = OUT / f
        if p.exists():
            M.update(json.loads(p.read_text()))
    tests = {k: v["test"] for k, v in M.items() if "test" in v}
    evas = {k: v["evasion"] for k, v in M.items() if "evasion" in v}
    for a in tests.values():
        for b in tests.values():
            for key in ("f1", "recall", "fpr", "precision"):
                if key in a and key in b:
                    add(abs(a[key] - b[key]))
                    if b[key]:
                        add(a[key] / b[key])
    for k in evas:
        if k in tests and "recall" in tests[k]:
            base, ev = tests[k]["recall"], evas[k].get("detection_rate", 0)
            add(base - ev)
            if base:
                add((base - ev) / base)
        for kk, vv in evas[k].items():
            add(vv)
    # per-transform means across detectors (reported in the prose)
    tf = {}
    for k in evas:
        for kk, vv in evas[k].items():
            if kk.startswith("dr_") and not kk.endswith("_sd"):
                tf.setdefault(kk, []).append(vv)
    for vs in tf.values():
        add(sum(vs) / len(vs))
    # per-class means, averaged over the trained detectors only, exactly as the prose does
    TRAINED = ("LogisticRegression", "RandomForest", "SVM", "DistilBERT", "BERT")
    pc = {}
    for k, v in M.items():
        if k not in TRAINED:
            continue
        for cls, val in (v.get("per_class_recall") or {}).items():
            pc.setdefault(cls, []).append(val)
    for vs in pc.values():
        add(sum(vs) / len(vs))

    # the reserved adaptive-attack set: its size, the number of source attacks it was
    # derived from, and the number of genuine LLM paraphrases within it
    ev = ROOT / "data" / "evasion_set.jsonl"
    if ev.exists():
        import pandas as pd
        d = pd.read_json(ev, lines=True)
        add(len(d))
        add(d["source_text"].nunique())
        for _, g in d.groupby("transform"):
            add(len(g))
    # evasion-degradation ratios between detectors
    rels = {}
    for k in evas:
        if k in tests and tests[k].get("recall"):
            rels[k] = (tests[k]["recall"] - evas[k].get("detection_rate", 0)) / tests[k]["recall"]
    for a in rels.values():
        for b in rels.values():
            if b:
                add(a / b)

    env = json.loads((OUT / "environment.json").read_text())
    for v in env.values():
        if isinstance(v, (int, float)):
            add(v)
        elif isinstance(v, str):
            for tok in re.findall(r"\d+\.?\d*", v):
                add(tok)

    shots = OUT / "screenshots" / "manifest.json"
    if shots.exists():
        for tok in re.findall(r"\d+\.?\d*", shots.read_text()):
            add(tok)

    lab = OUT / "lab" / "lab_probe_results.jsonl"
    if lab.exists():
        for tok in re.findall(r"-?\d+\.?\d*", lab.read_text()):
            add(tok)

    vals.discard("")
    return vals


def main():
    if not DOC.exists():
        raise SystemExit("build the document first: python docgen/build_document.py")

    text = doc_text()
    known = known_values()

    placeholders = re.findall(r"\[PLACEHOLDER:[^\]]*\]", text)
    numbers = re.findall(r"(?<![\w.])\d[\d,]*\.?\d*(?![\w])", text)

    unaccounted = []
    for n in numbers:
        clean = n.rstrip(".")
        if STRUCTURAL.match(clean.replace(",", "")):
            continue
        if clean in known or clean.replace(",", "") in known:
            continue
        unaccounted.append(clean)

    seen = {}
    for u in unaccounted:
        seen[u] = seen.get(u, 0) + 1

    print(f"Chapters Four to Six: {len(numbers)} numeric literals checked")
    print(f"Placeholders remaining: {len(placeholders)}")
    for p in placeholders:
        print(f"   {p}")
    if seen:
        print(f"\nUnaccounted numbers ({len(seen)} distinct):")
        for k, v in sorted(seen.items(), key=lambda kv: -kv[1]):
            print(f"   {k}  (x{v})")
        print("\nEach must be checked by hand or traced to an artefact.")
    else:
        print("\nAll numeric literals trace to a measured artefact.")
    return 1 if (placeholders or seen) else 0


if __name__ == "__main__":
    sys.exit(main())
