"""The real-time prompt-injection screening middleware (objective 4).

A model-agnostic Flask service that sits between the user and the protected LLM. It
screens two distinct channels, as Chapter Three, Section 3.6 requires:

    channel = "user"       the user's own prompt        -> direct injection, jailbreak
    channel = "retrieved"  retrieved (RAG) content      -> indirect injection

and applies the block / sanitise / escalate decision policy. Every decision and score is
logged to middleware/logs/decisions.jsonl for auditing and later analysis.

Run:  python -m middleware.app          (or: flask --app middleware.app run -p 5001)
Env:  MIDDLEWARE_DETECTOR = auto | transformer | classical | keyword
      MIDDLEWARE_PORT     = 5001
"""
from __future__ import annotations

import datetime
import json
import os
import pathlib
import time

from flask import Flask, jsonify, request

from .detector import load_detector
from .policy import PolicyConfig, decide

ROOT = pathlib.Path(__file__).resolve().parent.parent
LOG_PATH = ROOT / "middleware" / "logs" / "decisions.jsonl"
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)

_detector = None
_config = PolicyConfig()


def detector():
    global _detector
    if _detector is None:
        _detector = load_detector(os.getenv("MIDDLEWARE_DETECTOR", "auto"))
        app.logger.info("detector loaded: %s", _detector.name)
    return _detector


def _log(record: dict) -> None:
    record["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


@app.get("/health")
def health():
    return jsonify({"status": "ok", "detector": detector().name,
                    "thresholds": {"block": _config.block_threshold,
                                   "escalate": _config.escalate_threshold,
                                   "sanitise": _config.sanitise_threshold}})


@app.post("/screen")
def screen():
    """Screen a single item of content on a named channel."""
    body = request.get_json(silent=True) or {}
    content = body.get("content", "")
    channel = body.get("channel", "user")
    if not isinstance(content, str) or not content.strip():
        return jsonify({"error": "content must be a non-empty string"}), 400
    if channel not in ("user", "retrieved"):
        return jsonify({"error": "channel must be 'user' or 'retrieved'"}), 400

    t0 = time.perf_counter()
    score = detector().score([content])[0]
    outcome = decide(score, content, channel, _config)
    outcome["latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    outcome["detector"] = detector().name

    _log({"channel": channel, "score": outcome["score"], "decision": outcome["decision"],
          "detector": outcome["detector"], "latency_ms": outcome["latency_ms"],
          "content_preview": content[:300], "reason": outcome["reason"]})
    return jsonify(outcome)


@app.post("/screen_batch")
def screen_batch():
    """Screen many items in one call; used by the evaluation harness."""
    body = request.get_json(silent=True) or {}
    items = body.get("items", [])
    if not isinstance(items, list) or not items:
        return jsonify({"error": "items must be a non-empty list"}), 400

    texts = [(i.get("content") if isinstance(i, dict) else str(i)) or "" for i in items]
    chans = [(i.get("channel", "user") if isinstance(i, dict) else "user") for i in items]

    t0 = time.perf_counter()
    scores = detector().score(texts)
    total_ms = (time.perf_counter() - t0) * 1000

    results = []
    for text, chan, sc in zip(texts, chans, scores):
        out = decide(sc, text, chan, _config)
        out["detector"] = detector().name
        results.append(out)
    _log({"batch": len(items), "total_ms": round(total_ms, 2),
          "detector": detector().name,
          "decisions": {d: sum(1 for r in results if r["decision"] == d)
                        for d in {r["decision"] for r in results}}})
    return jsonify({"results": results,
                    "total_ms": round(total_ms, 2),
                    "mean_ms_per_item": round(total_ms / len(items), 3)})


@app.post("/config")
def configure():
    """Adjust thresholds at runtime, so sensitivity can be traded against over-blocking."""
    global _config
    body = request.get_json(silent=True) or {}
    _config = PolicyConfig(
        block_threshold=float(body.get("block_threshold", _config.block_threshold)),
        escalate_threshold=float(body.get("escalate_threshold", _config.escalate_threshold)),
        sanitise_threshold=float(body.get("sanitise_threshold", _config.sanitise_threshold)),
        channel_overrides=body.get("channel_overrides", _config.channel_overrides),
    )
    return jsonify({"ok": True, "block_threshold": _config.block_threshold,
                    "escalate_threshold": _config.escalate_threshold,
                    "sanitise_threshold": _config.sanitise_threshold})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("MIDDLEWARE_PORT", "5001")), debug=False)
