"""Experiment 4 of Chapter Three, Section 3.7: the operational characteristics of the
middleware — the latency it adds to each request, and the rate at which it over-blocks
legitimate traffic.

Latency is measured end to end through the running Flask service (so it includes HTTP
and serialisation overhead, not just model inference), and separately in-process for each
detector back-end. Over-blocking is measured on the benign half of the held-out test set
and, separately, on the authored hard negatives — the prompts most likely to be
misclassified, and therefore the sternest test of over-defence.

Requires the middleware to be running:  python -m middleware.app

Usage:  python ml/bench_latency.py
"""
from __future__ import annotations

import json
import pathlib
import statistics
import sys
import time

import numpy as np
import requests

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from common import OUT, load, save_json, splits  # noqa: E402

URL = "http://127.0.0.1:5001"
N_LATENCY = 200


def http_latency(texts) -> dict:
    lat = []
    for t in texts:
        t0 = time.perf_counter()
        r = requests.post(f"{URL}/screen", json={"content": t, "channel": "user"}, timeout=30)
        r.raise_for_status()
        lat.append((time.perf_counter() - t0) * 1000)
    lat.sort()
    return {"n": len(lat),
            "mean_ms": round(statistics.mean(lat), 2),
            "median_ms": round(statistics.median(lat), 2),
            "p95_ms": round(lat[int(0.95 * (len(lat) - 1))], 2),
            "p99_ms": round(lat[int(0.99 * (len(lat) - 1))], 2),
            "min_ms": round(lat[0], 2), "max_ms": round(lat[-1], 2)}


def inprocess_latency(kind: str, texts) -> dict | None:
    from middleware.detector import load_detector
    try:
        det = load_detector(kind)
    except SystemExit as exc:
        print(f"  ! {kind}: {exc}")
        return None
    det.score(texts[:8])  # warm up
    lat = []
    for t in texts:
        t0 = time.perf_counter()
        det.score([t])
        lat.append((time.perf_counter() - t0) * 1000)
    lat.sort()
    t0 = time.perf_counter()
    det.score(texts)
    batch_ms = (time.perf_counter() - t0) * 1000
    return {"detector": det.name, "n": len(lat),
            "mean_ms": round(statistics.mean(lat), 2),
            "median_ms": round(statistics.median(lat), 2),
            "p95_ms": round(lat[int(0.95 * (len(lat) - 1))], 2),
            "batched_mean_ms_per_item": round(batch_ms / len(texts), 3)}


def over_blocking(texts, label: str) -> dict:
    """Proportion of legitimate traffic that is not simply allowed through."""
    r = requests.post(f"{URL}/screen_batch",
                      json={"items": [{"content": t, "channel": "user"} for t in texts]},
                      timeout=600)
    r.raise_for_status()
    res = r.json()["results"]
    counts = {}
    for d in res:
        counts[d["decision"]] = counts.get(d["decision"], 0) + 1
    n = len(res)
    blocked = counts.get("block", 0)
    intervened = n - counts.get("allow", 0)
    return {"set": label, "n": n, "decisions": counts,
            "block_rate": round(blocked / n, 4),
            "any_intervention_rate": round(intervened / n, 4),
            "mean_ms_per_item": r.json()["mean_ms_per_item"]}


def main():
    try:
        health = requests.get(f"{URL}/health", timeout=10).json()
    except Exception:
        raise SystemExit("middleware not reachable at http://127.0.0.1:5001 - "
                         "start it with: python -m middleware.app")
    print("middleware:", health)

    _, _, test = splits(load())
    benign = test[test.label == 0]
    sample = benign.text.sample(min(N_LATENCY, len(benign)), random_state=42).tolist()

    out = {"middleware_health": health}
    print("HTTP latency ...")
    out["http_latency"] = http_latency(sample)
    print("  ", out["http_latency"])

    print("In-process latency by back-end ...")
    out["inprocess_latency"] = {}
    for kind in ("keyword", "classical", "transformer"):
        m = inprocess_latency(kind, sample)
        if m:
            out["inprocess_latency"][kind] = m
            print(f"   {kind}: {m['mean_ms']} ms mean, {m['p95_ms']} ms p95")

    print("Over-blocking on legitimate traffic ...")
    out["over_blocking"] = []
    out["over_blocking"].append(over_blocking(benign.text.tolist(), "held-out benign test set"))

    hard = benign[benign.source.str.contains("hard negatives", na=False)]
    if len(hard):
        out["over_blocking"].append(over_blocking(hard.text.tolist(), "authored hard negatives"))
    domain = benign[benign.source.str.contains("matched-domain", na=False)]
    if len(domain):
        out["over_blocking"].append(over_blocking(domain.text.tolist(),
                                                  "authored matched-domain benign"))
    for o in out["over_blocking"]:
        print(f"   {o['set']}: n={o['n']} block_rate={o['block_rate']} "
              f"any_intervention={o['any_intervention_rate']}")

    save_json(out, OUT / "latency.json")
    print(f"\nWrote {OUT / 'latency.json'}")


if __name__ == "__main__":
    main()
