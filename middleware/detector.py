"""Detector back-ends for the middleware.

The middleware is model-agnostic in two senses. It does not know or care which LLM it is
protecting, and it does not depend on a particular detector: any object exposing
`score(texts) -> list[float]` may be plugged in. Three back-ends are provided.
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODELS = ROOT / "models"

# The saved classical pipelines reference the custom Structural transformer defined in
# ml/common.py, so that module must be importable for joblib to unpickle them.
if str(ROOT / "ml") not in sys.path:
    sys.path.insert(0, str(ROOT / "ml"))


class ClassicalDetector:
    """A scikit-learn pipeline saved by ml/train_classical.py."""

    name = "classical"

    def __init__(self, path: pathlib.Path):
        import joblib
        bundle = joblib.load(path)
        self.features = bundle["features"]
        self.clf = bundle["clf"]
        self.name = f"classical:{path.stem}"

    def score(self, texts: list[str]) -> list[float]:
        X = self.features.transform(texts)
        if hasattr(self.clf, "predict_proba"):
            return self.clf.predict_proba(X)[:, 1].tolist()
        margins = self.clf.decision_function(X)
        return (1.0 / (1.0 + pow(2.718281828, -margins))).tolist()


class TransformerDetector:
    """A fine-tuned sequence-classification checkpoint from ml/train_transformers.py."""

    def __init__(self, path: pathlib.Path, max_len: int = 256):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        self.torch = torch
        self.tok = AutoTokenizer.from_pretrained(str(path))
        self.model = AutoModelForSequenceClassification.from_pretrained(str(path))
        self.model.eval()
        self.max_len = max_len
        self.name = f"transformer:{path.name}"

    def score(self, texts: list[str]) -> list[float]:
        with self.torch.no_grad():
            enc = self.tok(texts, truncation=True, padding=True,
                           max_length=self.max_len, return_tensors="pt")
            logits = self.model(**enc).logits
            return self.torch.softmax(logits.float(), dim=-1)[:, 1].tolist()


class KeywordDetector:
    """The rule-based lower bound, reusing the lab's own TRICK_PATTERNS.

    Included as the Chapter Three comparison baseline representing the rudimentary
    defences still common in practice, and as a zero-dependency fallback.
    """

    name = "keyword-baseline"
    PATTERNS = [
        r"ignore (all|the|your|previous|prior|above)",
        r"disregard (all|the|your|previous|prior|above)",
        r"system prompt",
        r"initial (instructions|prompt)",
        r"reveal|disclose|leak|print|repeat|show me",
        r"role[\s-]?play|pretend|act as|you are now|simulate|developer mode|\bdan\b",
        r"translate|encode|decode|base64|rot13|reverse|spell|acrostic|cipher|morse",
        r"secret|access code|api key|credential",
    ]

    def __init__(self):
        self._re = re.compile("|".join(self.PATTERNS), re.IGNORECASE)

    def score(self, texts: list[str]) -> list[float]:
        return [1.0 if self._re.search(t or "") else 0.0 for t in texts]


def load_detector(kind: str = "auto"):
    """Resolve a detector by name, preferring the strongest available."""
    if kind in ("auto", "transformer"):
        for cand in ("distilbert", "bert"):
            p = MODELS / cand
            if (p / "config.json").exists():
                try:
                    return TransformerDetector(p)
                except Exception as exc:
                    print(f"  ! could not load {cand}: {exc}")
        if kind == "transformer":
            raise SystemExit("no transformer checkpoint found - run ml/train_transformers.py")

    if kind in ("auto", "classical"):
        for cand in ("svm", "logisticregression", "randomforest"):
            p = MODELS / f"{cand}.joblib"
            if p.exists():
                try:
                    return ClassicalDetector(p)
                except Exception as exc:
                    print(f"  ! could not load {cand}: {exc}")
        if kind == "classical":
            raise SystemExit("no classical model found - run ml/train_classical.py")

    return KeywordDetector()
