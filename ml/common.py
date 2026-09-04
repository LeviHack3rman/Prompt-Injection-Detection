"""Shared data loading, feature engineering and metric computation.

Feature design follows Chapter Three, Section 3.4: TF-IDF over both word and character
n-grams, combined with a small set of structural features (instruction-like imperatives,
delimiter abuse, the proportion of non-natural-language characters, and prompt length).
Casing and punctuation are deliberately preserved, because aggressive normalisation
discards evidence of an attack.

Every extractor is fitted on the training partition only.
"""
from __future__ import annotations

import json
import pathlib
import re

import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import MaxAbsScaler

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "dataset.jsonl"
OUT = ROOT / "outputs"
MODELS = ROOT / "models"
for d in (OUT / "figures", OUT / "tables", MODELS):
    d.mkdir(parents=True, exist_ok=True)

SEEDS = [42, 1337, 2024]

IMPERATIVES = re.compile(
    r"\b(ignore|disregard|forget|override|bypass|reveal|disclose|print|repeat|output|"
    r"echo|show|list|dump|pretend|act as|role[\s-]?play|simulate|you are now|"
    r"from now on|instead|do not|must|shall|encode|decode|translate|spell|reverse)\b",
    re.IGNORECASE)
DELIMITERS = re.compile(r"(```|###|---|\*\*\*|</?\s*(system|user|assistant|instructions?)\s*>|\[/?INST\]|\{\{|\}\})",
                        re.IGNORECASE)


def structural_features(texts) -> np.ndarray:
    """Four structural signals, plus their simple derivatives, per Section 3.4."""
    rows = []
    for t in texts:
        t = t or ""
        n = max(len(t), 1)
        words = t.split()
        nonnat = sum(1 for c in t if not (c.isalnum() or c.isspace() or c in ".,!?'\"-:;()"))
        upper = sum(1 for c in t if c.isupper())
        rows.append([
            len(t) / 1000.0,                                   # length
            len(words) / 100.0,                                # token count
            len(IMPERATIVES.findall(t)),                       # instruction-like imperatives
            len(DELIMITERS.findall(t)),                        # delimiter abuse
            nonnat / n,                                        # non-natural-language chars
            upper / n,                                         # shouting / emphasis
            t.count("\n") / 10.0,                              # structural breaks
            sum(1 for w in words if len(w) > 20) / max(len(words), 1),  # encoded blobs
        ])
    return np.asarray(rows, dtype=np.float64)


class Structural(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return csr_matrix(structural_features(X))


def build_features() -> Pipeline:
    return Pipeline([
        ("union", FeatureUnion([
            ("word", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=2,
                                     max_features=60000, sublinear_tf=True, lowercase=True)),
            ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                                     max_features=80000, sublinear_tf=True, lowercase=False)),
            ("struct", Structural()),
        ])),
        ("scale", MaxAbsScaler()),
    ])


def load() -> pd.DataFrame:
    if not DATA.exists():
        raise SystemExit("data/dataset.jsonl missing - run: python ml/build_dataset.py")
    return pd.read_json(DATA, lines=True)


def splits(df: pd.DataFrame):
    return (df[df.split == "train"].reset_index(drop=True),
            df[df.split == "val"].reset_index(drop=True),
            df[df.split == "test"].reset_index(drop=True))


def metrics(y_true, y_pred, y_score=None) -> dict:
    """The five metrics named in Chapter Three, Table 3.2, plus the confusion matrix.

    The false-positive rate is computed explicitly rather than inferred, because
    Chapter Three declares it a primary outcome rather than an afterthought.
    """
    y_true = np.asarray(y_true).astype(int)
    y_pred = np.asarray(y_pred).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    out = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "fpr": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
    }
    out["detection_rate"] = out["recall"]  # Chapter Three's terminology
    if y_score is not None and len(set(y_true)) > 1:
        out["roc_auc"] = float(roc_auc_score(y_true, y_score))
    return out


def aggregate(runs: list[dict]) -> dict:
    """Mean and standard deviation across seeds, as Section 3.7 requires."""
    keys = [k for k in runs[0] if isinstance(runs[0][k], (int, float))]
    agg = {}
    for k in keys:
        vals = [r[k] for r in runs if k in r]
        agg[k] = float(np.mean(vals))
        agg[k + "_sd"] = float(np.std(vals, ddof=0))
    return agg


def save_json(obj, path: pathlib.Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, default=float))
