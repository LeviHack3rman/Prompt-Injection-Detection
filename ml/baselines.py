"""The two comparison baselines of Chapter Three, Section 3.8.

  1. A simple keyword filter, representing the rudimentary defences still common in
     practice. It reuses the lab's own TRICK_PATTERNS, so the baseline is the defence
     actually shipped in the artefact under study rather than a straw man.
  2. An established off-the-shelf detector: ProtectAI's DeBERTa-based prompt-injection
     model, the published detector named in Chapter Three.

Both are evaluated on exactly the same held-out test set and the same adaptive-attack set
as the trained models. The purpose, as Section 3.8 states, is not merely to claim
superiority but to give an honest account of where the proposed approach improves on
existing tooling and where it does not.

Usage:  python ml/baselines.py
"""
from __future__ import annotations

import pathlib
import sys
import time

import numpy as np
import pandas as pd

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from common import OUT, load, metrics, save_json, splits  # noqa: E402
from middleware.detector import KeywordDetector  # noqa: E402

EVASION = pathlib.Path(__file__).resolve().parent.parent / "data" / "evasion_set.jsonl"
OFF_THE_SHELF = "protectai/deberta-v3-base-prompt-injection-v2"


def eval_keyword(test, evasion):
    det = KeywordDetector()
    t0 = time.perf_counter()
    sc = np.array(det.score(test["text"].tolist()))
    elapsed = time.perf_counter() - t0
    m = metrics(test["label"], (sc >= 0.5).astype(int), sc)
    m["mean_latency_ms"] = round(1000 * elapsed / len(test), 4)

    out = {"test": m, "detector": "keyword filter (lab TRICK_PATTERNS)"}
    if evasion is not None and len(evasion):
        ev = np.array(det.score(evasion["text"].tolist()))
        ev_pred = (ev >= 0.5).astype(int)
        e = {"detection_rate": float(ev_pred.mean())}
        for tf, g in evasion.groupby("transform"):
            idx = evasion.index.get_indexer(g.index)
            e[f"dr_{tf}"] = float(ev_pred[idx].mean())
        out["evasion"] = e

    per_class = {}
    pred = (sc >= 0.5).astype(int)
    for cls in ("direct_injection", "jailbreak", "indirect_injection"):
        mask = (test.attack_class == cls).values
        if mask.sum():
            per_class[cls] = float((pred[mask] == 1).mean())
    out["per_class_recall"] = per_class
    return out


def eval_off_the_shelf(test, evasion):
    """The published DeBERTa detector, downloaded and run unmodified."""
    try:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        tok = AutoTokenizer.from_pretrained(OFF_THE_SHELF)
        model = AutoModelForSequenceClassification.from_pretrained(OFF_THE_SHELF)
        model.eval()
        dev = torch.device("mps") if torch.backends.mps.is_available() else torch.device("cpu")
        model.to(dev)
    except Exception as exc:
        print(f"  ! off-the-shelf detector unavailable: {type(exc).__name__}: {exc}")
        return {"unavailable": True, "checkpoint": OFF_THE_SHELF, "error": str(exc)[:300],
                "placeholder": "[PLACEHOLDER: run `python ml/baselines.py` with network "
                               "access to huggingface.co to populate this row]"}

    # The model's label mapping is read from its own config rather than assumed.
    id2label = {int(k): str(v).upper() for k, v in model.config.id2label.items()}
    inj_idx = next((i for i, v in id2label.items() if "INJECT" in v or v == "LABEL_1"), 1)
    print(f"  off-the-shelf id2label={id2label}, using index {inj_idx} as the injection class")

    def score(texts, bs=32):
        out = []
        t0 = time.perf_counter()
        with torch.no_grad():
            for i in range(0, len(texts), bs):
                enc = tok(texts[i:i + bs], truncation=True, padding=True,
                          max_length=256, return_tensors="pt").to(dev)
                p = torch.softmax(model(**enc).logits.float(), dim=-1)[:, inj_idx]
                out.extend(p.cpu().numpy().tolist())
        return np.array(out), time.perf_counter() - t0

    sc, elapsed = score(test["text"].tolist())
    m = metrics(test["label"], (sc >= 0.5).astype(int), sc)
    m["mean_latency_ms"] = round(1000 * elapsed / len(test), 3)
    res = {"test": m, "detector": OFF_THE_SHELF, "id2label": id2label}

    if evasion is not None and len(evasion):
        ev, _ = score(evasion["text"].tolist())
        ev_pred = (ev >= 0.5).astype(int)
        e = {"detection_rate": float(ev_pred.mean())}
        for tf, g in evasion.groupby("transform"):
            idx = evasion.index.get_indexer(g.index)
            e[f"dr_{tf}"] = float(ev_pred[idx].mean())
        res["evasion"] = e

    per_class = {}
    pred = (sc >= 0.5).astype(int)
    for cls in ("direct_injection", "jailbreak", "indirect_injection"):
        mask = (test.attack_class == cls).values
        if mask.sum():
            per_class[cls] = float((pred[mask] == 1).mean())
    res["per_class_recall"] = per_class
    return res


def main():
    _, _, test = splits(load())
    evasion = pd.read_json(EVASION, lines=True).reset_index(drop=True) if EVASION.exists() else None
    print(f"test={len(test)} evasion={0 if evasion is None else len(evasion)}")

    results = {}
    print("Keyword baseline ...")
    results["KeywordFilter"] = eval_keyword(test, evasion)
    print(f"  F1={results['KeywordFilter']['test']['f1']:.4f} "
          f"FPR={results['KeywordFilter']['test']['fpr']:.4f}")

    print(f"Off-the-shelf detector ({OFF_THE_SHELF}) ...")
    results["OffTheShelfDeBERTa"] = eval_off_the_shelf(test, evasion)
    if "test" in results["OffTheShelfDeBERTa"]:
        print(f"  F1={results['OffTheShelfDeBERTa']['test']['f1']:.4f} "
              f"FPR={results['OffTheShelfDeBERTa']['test']['fpr']:.4f}")

    save_json(results, OUT / "metrics_baselines.json")
    print(f"\nWrote {OUT / 'metrics_baselines.json'}")


if __name__ == "__main__":
    main()
