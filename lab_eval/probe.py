"""Probe the running lab with each payload at each guardrail level and record the outcome.

Usage: python lab_eval/probe.py <level> [<level> ...]
Writes/updates outputs/lab/lab_probe_results.jsonl
"""
import json, pathlib, sys, time
import requests

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lab_eval"))
from payloads import PAYLOADS, BENIGN_PROBES  # noqa: E402

API = "http://127.0.0.1:8000/chat"
OUT = ROOT / "outputs" / "lab" / "lab_probe_results.jsonl"
OUT.parent.mkdir(parents=True, exist_ok=True)


def send(text, level):
    t0 = time.perf_counter()
    r = requests.post(API, json={"level": level, "messages": [{"role": "user", "content": text}]}, timeout=180)
    r.raise_for_status()
    d = r.json()
    d["latency_s"] = round(time.perf_counter() - t0, 3)
    return d


def main(levels):
    with OUT.open("a", encoding="utf-8") as fh:
        for level in levels:
            for name, cls, text in PAYLOADS:
                d = send(text, level)
                rec = {"level": level, "payload": name, "kind": cls, "is_attack": True,
                       "secret_leaked": d.get("secret_leaked"),
                       "guardrails_triggered": d.get("guardrails_triggered"),
                       "latency_s": d["latency_s"], "reply": d.get("reply", "")}
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n"); fh.flush()
                print(f"L{level} {name:28s} leaked={str(rec['secret_leaked']):5s} "
                      f"triggered={rec['guardrails_triggered']} {rec['latency_s']}s")
            for name, text in BENIGN_PROBES:
                d = send(text, level)
                rec = {"level": level, "payload": name, "kind": "benign", "is_attack": False,
                       "secret_leaked": d.get("secret_leaked"),
                       "guardrails_triggered": d.get("guardrails_triggered"),
                       "latency_s": d["latency_s"], "reply": d.get("reply", "")}
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n"); fh.flush()
                print(f"L{level} {name:28s} BENIGN triggered={rec['guardrails_triggered']} {rec['latency_s']}s")


if __name__ == "__main__":
    main([int(a) for a in sys.argv[1:]] or [1])
