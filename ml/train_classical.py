"""Train and evaluate the three classical detectors of Chapter Three, Section 3.5.

Logistic Regression (an interpretable linear reference), Random Forest (non-linear feature
interactions) and a Support Vector Machine (effective in high-dimensional TF-IDF spaces),
all over the shared feature representation defined in ml/common.py.

Every model is trained under an identical protocol on identical partitions, repeated over
three seeds, with class weighting to handle imbalance. Hyperparameters are chosen by
stratified k-fold cross-validation on train+validation, exactly as Section 3.5 specifies.

Usage:  python ml/train_classical.py
"""
from __future__ import annotations

import json
import pathlib
import sys
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GridSearchCV, StratifiedKFold
from sklearn.svm import LinearSVC

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from common import (MODELS, OUT, SEEDS, aggregate, build_features, load,  # noqa: E402
                    metrics, save_json, splits)

EVASION = pathlib.Path(__file__).resolve().parent.parent / "data" / "evasion_set.jsonl"

GRIDS = {
    "LogisticRegression": (
        lambda seed: LogisticRegression(max_iter=2000, class_weight="balanced", random_state=seed),
        {"C": [0.5, 1.0, 4.0]},
    ),
    "RandomForest": (
        lambda seed: RandomForestClassifier(n_estimators=300, class_weight="balanced_subsample",
                                            n_jobs=-1, random_state=seed),
        {"max_depth": [None, 40], "min_samples_leaf": [1, 2]},
    ),
    "SVM": (
        lambda seed: LinearSVC(class_weight="balanced", random_state=seed, max_iter=5000),
        {"C": [0.25, 1.0, 4.0]},
    ),
}


def scores_of(clf, X):
    """A probability where available, otherwise the decision margin, for ROC-AUC."""
    if hasattr(clf, "predict_proba"):
        return clf.predict_proba(X)[:, 1]
    return clf.decision_function(X)


def main():
    df = load()
    train, val, test = splits(df)
    trval = pd.concat([train, val]).reset_index(drop=True)
    print(f"train={len(train)} val={len(val)} test={len(test)}")

    evasion = pd.read_json(EVASION, lines=True) if EVASION.exists() else None
    if evasion is not None:
        print(f"evasion set: {len(evasion)} adaptive variants")

    results: dict = {}
    for name, (make, grid) in GRIDS.items():
        per_seed, per_seed_evasion, per_class = [], [], []
        best_params_seen = None
        for seed in SEEDS:
            t0 = time.perf_counter()
            feats = build_features()
            Xtr = feats.fit_transform(trval["text"])
            ytr = trval["label"].values

            search = GridSearchCV(make(seed), grid, scoring="f1",
                                  cv=StratifiedKFold(4, shuffle=True, random_state=seed),
                                  n_jobs=-1, refit=True)
            search.fit(Xtr, ytr)
            clf = search.best_estimator_
            best_params_seen = search.best_params_

            # LinearSVC has no probability output; calibrate so ROC-AUC is well defined.
            if name == "SVM":
                clf = CalibratedClassifierCV(clf, cv=3, method="sigmoid").fit(Xtr, ytr)

            fit_s = time.perf_counter() - t0

            Xte = feats.transform(test["text"])
            pred = clf.predict(Xte)
            sc = scores_of(clf, Xte)
            m = metrics(test["label"], pred, sc)
            m["fit_seconds"] = round(fit_s, 1)
            per_seed.append(m)

            # Per-attack-class recall on the held-out test set.
            row = {}
            for cls in ("direct_injection", "jailbreak", "indirect_injection"):
                mask = (test.attack_class == cls).values
                if mask.sum():
                    row[cls] = float((pred[mask] == 1).mean())
            per_class.append(row)

            if evasion is not None and len(evasion):
                ev_pred = clf.predict(feats.transform(evasion["text"]))
                e = {"detection_rate": float((ev_pred == 1).mean())}
                for tf, g in evasion.groupby("transform"):
                    gp = clf.predict(feats.transform(g["text"]))
                    e[f"dr_{tf}"] = float((gp == 1).mean())
                per_seed_evasion.append(e)

            print(f"  {name} seed={seed} F1={m['f1']:.4f} FPR={m['fpr']:.4f} "
                  f"AUC={m.get('roc_auc', float('nan')):.4f} ({fit_s:.0f}s)")

            if seed == SEEDS[0]:
                joblib.dump({"features": feats, "clf": clf},
                            MODELS / f"{name.lower()}.joblib")

        results[name] = {
            "test": aggregate(per_seed),
            "test_per_seed": per_seed,
            "per_class_recall": {k: float(np.mean([d.get(k, np.nan) for d in per_class]))
                                 for k in per_class[0]},
            "best_params": best_params_seen,
            "seeds": SEEDS,
        }
        if per_seed_evasion:
            results[name]["evasion"] = aggregate(per_seed_evasion)

    save_json(results, OUT / "metrics_classical.json")
    print(f"\nWrote {(OUT / 'metrics_classical.json')}")


if __name__ == "__main__":
    main()
