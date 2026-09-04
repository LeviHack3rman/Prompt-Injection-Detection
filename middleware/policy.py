"""The decision policy of the detection middleware (Chapter Three, Section 3.6).

The policy is deliberately separated from the web layer and from the detector, so that it
can be unit-tested in isolation and so the middleware remains model-agnostic: it operates
on a score in [0, 1] and a channel, never on the protected model.

Three configurable responses are supported, as Section 3.6 specifies:

    BLOCK     - the content is refused outright and never reaches the protected model.
    SANITISE  - the injected instruction is neutralised and the remainder proceeds.
    ESCALATE  - the content is held for human review.
    ALLOW     - benign content passes unchanged.

Thresholds are configurable so that an operator can trade sensitivity against the cost of
over-blocking: a financial chatbot and a general information assistant tolerate very
different levels of over-defence.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

BLOCK = "block"
SANITISE = "sanitise"
ESCALATE = "escalate"
ALLOW = "allow"

# Markers stripped by the sanitise action. These neutralise the instruction-bearing
# scaffolding of an injection while leaving legitimate surrounding text intact.
_SANITISE_PATTERNS = [
    r"(?i)ignore\s+(all\s+|the\s+|your\s+|any\s+)?(previous|prior|above|preceding)[^.\n]*",
    r"(?i)disregard\s+(all\s+|the\s+|your\s+|any\s+)?(previous|prior|above|preceding)[^.\n]*",
    r"(?i)forget\s+(everything|all\s+previous|your\s+instructions)[^.\n]*",
    r"(?i)\byou\s+are\s+now\b[^.\n]*",
    r"(?i)\bfrom\s+now\s+on\b[^.\n]*",
    r"(?i)system\s*prompt",
    r"(?i)developer\s+mode",
    r"(?i)\bDAN\b",
    r"</?\s*(system|assistant|user|instructions?)\s*>",
    r"\[/?INST\]",
]
_COMPILED = [re.compile(p) for p in _SANITISE_PATTERNS]


def sanitise(text: str) -> tuple[str, bool]:
    """Strip injection scaffolding. Returns the cleaned text and whether it changed."""
    cleaned = text or ""
    for pat in _COMPILED:
        cleaned = pat.sub(" ", cleaned)
    cleaned = re.sub(r"\s{2,}", " ", cleaned).strip()
    return cleaned, cleaned != (text or "").strip()


@dataclass
class PolicyConfig:
    """Per-channel thresholds.

    The retrieved-content channel is configured more conservatively by default: retrieved
    content carries no legitimate instruction-giving authority, so blocking it costs the
    user far less than blocking their own prompt.
    """
    block_threshold: float = 0.90
    escalate_threshold: float = 0.70
    sanitise_threshold: float = 0.50
    channel_overrides: dict = field(default_factory=lambda: {
        "retrieved": {"block_threshold": 0.80, "escalate_threshold": 0.60,
                      "sanitise_threshold": 0.40},
    })

    def for_channel(self, channel: str) -> "PolicyConfig":
        ov = self.channel_overrides.get(channel)
        if not ov:
            return self
        return PolicyConfig(
            block_threshold=ov.get("block_threshold", self.block_threshold),
            escalate_threshold=ov.get("escalate_threshold", self.escalate_threshold),
            sanitise_threshold=ov.get("sanitise_threshold", self.sanitise_threshold),
            channel_overrides={},
        )


def decide(score: float, text: str, channel: str = "user",
           config: PolicyConfig | None = None) -> dict:
    """Map a detector score onto one of the four responses."""
    cfg = (config or PolicyConfig()).for_channel(channel)
    score = float(score)

    if score >= cfg.block_threshold:
        return {"decision": BLOCK, "score": score, "channel": channel,
                "content": None, "modified": False,
                "reason": f"score {score:.3f} >= block threshold {cfg.block_threshold}"}

    if score >= cfg.escalate_threshold:
        return {"decision": ESCALATE, "score": score, "channel": channel,
                "content": text, "modified": False,
                "reason": f"score {score:.3f} >= escalate threshold {cfg.escalate_threshold}"}

    if score >= cfg.sanitise_threshold:
        cleaned, changed = sanitise(text)
        # If nothing could be neutralised, sanitising is not a meaningful mitigation;
        # escalate instead of silently passing suspicious content through.
        if not changed:
            return {"decision": ESCALATE, "score": score, "channel": channel,
                    "content": text, "modified": False,
                    "reason": f"score {score:.3f} above sanitise threshold but no "
                              f"injection markers found to neutralise"}
        return {"decision": SANITISE, "score": score, "channel": channel,
                "content": cleaned, "modified": True,
                "reason": f"score {score:.3f} >= sanitise threshold {cfg.sanitise_threshold}; "
                          f"injection markers removed"}

    return {"decision": ALLOW, "score": score, "channel": channel,
            "content": text, "modified": False,
            "reason": f"score {score:.3f} below sanitise threshold {cfg.sanitise_threshold}"}
