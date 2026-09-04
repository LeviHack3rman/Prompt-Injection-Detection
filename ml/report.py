"""Consolidate every metric into the tables and figures used by Chapter Five.

Reads outputs/metrics_*.json (written by the training and baseline scripts) plus the raw
lab probe log, and emits:

  outputs/metrics.json                     single consolidated record
  outputs/tables/*.csv                     the Chapter Five result tables
  outputs/figures/confusion_matrices.png   per-model confusion matrices
  outputs/figures/roc_curves.png           overlaid ROC curves
  outputs/figures/model_comparison.png     model-comparison bar chart
  outputs/figures/evasion_degradation.png  detection rate by evasion transform
  outputs/figures/guardrail_levels.png     lab guardrail effectiveness vs over-blocking

Usage:  python ml/report.py
"""
from __future__ import annotations

import json
import pathlib
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from common import OUT, load, splits  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIG = OUT / "figures"
TAB = OUT / "tables"
for d in (FIG, TAB):
    d.mkdir(parents=True, exist_ok=True)

ORDER = ["LogisticRegression", "RandomForest", "SVM", "DistilBERT", "BERT",
         "KeywordFilter", "OffTheShelfDeBERTa"]
LABELS = {"LogisticRegression": "Logistic Regression", "RandomForest": "Random Forest",
          "SVM": "SVM", "DistilBERT": "DistilBERT", "BERT": "BERT",
          "KeywordFilter": "Keyword filter\n(baseline)",
          "OffTheShelfDeBERTa": "ProtectAI DeBERTa\n(off-the-shelf)"}
plt.rcParams.update({"figure.dpi": 160, "font.size": 9, "axes.grid": True,
                     "grid.alpha": 0.3, "axes.axisbelow": True})


def load_all() -> dict:
    merged = {}
    for f in ("metrics_classical.json", "metrics_transformers.json", "metrics_baselines.json"):
        p = OUT / f
        if p.exists():
            merged.update(json.loads(p.read_text()))
        else:
            print(f"  ! missing {f}")
    return merged


def fmt(v, sd=None, pct=False, dp=3):
    """Format a value, always showing the standard deviation when one exists — including
    an exactly zero deviation, which is itself informative."""
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return "n/a"
    if pct:
        s = f"{100 * v:.2f}"
        return f"{s} ± {100 * sd:.2f}" if sd is not None else s
    s = f"{v:.{dp}f}"
    return f"{s} ± {sd:.{dp}f}" if sd is not None else s


# --------------------------------------------------------------------------------------
# Tables
# --------------------------------------------------------------------------------------
def table_main(M) -> pd.DataFrame:
    rows = []
    for k in ORDER:
        if k not in M or "test" not in M[k]:
            continue
        t = M[k]["test"]
        rows.append({
            "Model": LABELS[k].replace("\n", " "),
            "Precision": fmt(t.get("precision"), t.get("precision_sd")),
            "Recall (detection rate)": fmt(t.get("recall"), t.get("recall_sd")),
            "F1-score": fmt(t.get("f1"), t.get("f1_sd")),
            "False-positive rate": fmt(t.get("fpr"), t.get("fpr_sd")),
            "ROC-AUC": fmt(t.get("roc_auc"), t.get("roc_auc_sd")),
        })
    return pd.DataFrame(rows)


def table_confusion(M) -> pd.DataFrame:
    rows = []
    for k in ORDER:
        if k not in M or "test" not in M[k]:
            continue
        t = M[k]["test"]
        rows.append({"Model": LABELS[k].replace("\n", " "),
                     "True negatives": int(round(t.get("tn", 0))),
                     "False positives": int(round(t.get("fp", 0))),
                     "False negatives": int(round(t.get("fn", 0))),
                     "True positives": int(round(t.get("tp", 0))),
                     "Accuracy": fmt(t.get("accuracy"), t.get("accuracy_sd"))})
    return pd.DataFrame(rows)


def table_per_class(M) -> pd.DataFrame:
    rows = []
    for k in ORDER:
        if k not in M or not M[k].get("per_class_recall"):
            continue
        p = M[k]["per_class_recall"]
        rows.append({"Model": LABELS[k].replace("\n", " "),
                     "Direct injection": fmt(p.get("direct_injection")),
                     "Jailbreak": fmt(p.get("jailbreak")),
                     "Indirect injection (BIPIA)": fmt(p.get("indirect_injection"))})
    return pd.DataFrame(rows)


def table_evasion(M) -> pd.DataFrame:
    rows = []
    for k in ORDER:
        if k not in M or "evasion" not in M[k] or "test" not in M[k]:
            continue
        base = M[k]["test"].get("recall", float("nan"))
        ev = M[k]["evasion"].get("detection_rate", float("nan"))
        # A negative value means the detector scored higher on the adaptive set than on
        # the unmodified one; the header is neutral so that reads correctly.
        rows.append({"Model": LABELS[k].replace("\n", " "),
                     "Detection rate, standard test set": fmt(base),
                     "Detection rate, adaptive set": fmt(ev,
                                                        M[k]["evasion"].get("detection_rate_sd")),
                     "Loss (standard − adaptive)": fmt(base - ev),
                     "Relative loss (%)": fmt(100 * (base - ev) / base if base else np.nan,
                                              dp=1)})
    return pd.DataFrame(rows)


def table_evasion_by_transform(M) -> pd.DataFrame:
    transforms = sorted({k[3:] for m in M.values() if "evasion" in m
                         for k in m["evasion"] if k.startswith("dr_") and not k.endswith("_sd")})
    rows = []
    for t in transforms:
        row = {"Evasion transform": t.replace("_", " ")}
        for k in ORDER:
            if k in M and "evasion" in M[k]:
                row[LABELS[k].replace("\n", " ")] = fmt(M[k]["evasion"].get(f"dr_{t}"))
        rows.append(row)
    return pd.DataFrame(rows)


def table_lab_levels() -> pd.DataFrame | None:
    p = OUT / "lab" / "lab_probe_results.jsonl"
    if not p.exists():
        return None
    rows = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines()]
    df = pd.DataFrame(rows)
    out = []
    names = {1: "1 - weak system prompt only", 2: "2 - + output filter",
             3: "3 - + hardened prompt + input heuristics", 4: "4 - + judge LLM",
             5: "5 - + input sanitisation"}
    for lvl in sorted(df.level.unique()):
        g = df[df.level == lvl]
        atk, ben = g[g.is_attack], g[~g.is_attack]
        blocked = atk.guardrails_triggered.map(bool).sum()
        over = ben.guardrails_triggered.map(bool).sum()
        out.append({
            "Guardrail level": names.get(int(lvl), str(lvl)),
            "Attacks issued": len(atk),
            "Secret leaked": int(atk.secret_leaked.fillna(False).sum()),
            "Attacks blocked by a guardrail": int(blocked),
            "Benign prompts issued": len(ben),
            "Benign prompts over-blocked": int(over),
            "Over-blocking rate (%)": f"{100 * over / max(len(ben), 1):.1f}",
            "Mean latency (s)": f"{g.latency_s.mean():.2f}",
        })
    return pd.DataFrame(out)


# --------------------------------------------------------------------------------------
# Figures
# --------------------------------------------------------------------------------------
def fig_confusion(M):
    keys = [k for k in ORDER if k in M and "test" in M[k]]
    if not keys:
        return
    n = len(keys)
    cols = min(4, n)
    rows = int(np.ceil(n / cols))
    fig, axes = plt.subplots(rows, cols, figsize=(3.0 * cols, 3.0 * rows), squeeze=False)
    for ax, k in zip(axes.ravel(), keys):
        t = M[k]["test"]
        cm = np.array([[t.get("tn", 0), t.get("fp", 0)], [t.get("fn", 0), t.get("tp", 0)]])
        ax.imshow(cm, cmap="Blues")
        for i in range(2):
            for j in range(2):
                ax.text(j, i, f"{int(round(cm[i, j])):,}", ha="center", va="center",
                        color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=10)
        ax.set_title(LABELS[k].replace("\n", " "), fontsize=9)
        ax.set_xticks([0, 1], ["Pred. benign", "Pred. malicious"], fontsize=7)
        ax.set_yticks([0, 1], ["Benign", "Malicious"], fontsize=7)
        ax.grid(False)
    for ax in axes.ravel()[n:]:
        ax.axis("off")
    fig.suptitle("Confusion matrices on the held-out test set", fontsize=11)
    fig.tight_layout()
    fig.savefig(FIG / "confusion_matrices.png", bbox_inches="tight")
    plt.close(fig)


def fig_roc():
    """ROC curves recomputed from the saved first-seed models on the held-out test set."""
    import joblib
    from sklearn.metrics import roc_curve, roc_auc_score
    _, _, test = splits(load())
    y = test.label.values
    curves = {}

    for name, fn in (("Logistic Regression", "logisticregression.joblib"),
                     ("Random Forest", "randomforest.joblib"), ("SVM", "svm.joblib")):
        p = ROOT / "models" / fn
        if not p.exists():
            continue
        b = joblib.load(p)
        X = b["features"].transform(test.text)
        clf = b["clf"]
        s = clf.predict_proba(X)[:, 1] if hasattr(clf, "predict_proba") else clf.decision_function(X)
        curves[name] = s

    for name, d in (("DistilBERT", "distilbert"), ("BERT", "bert")):
        p = ROOT / "models" / d
        if not (p / "config.json").exists():
            continue
        try:
            sys.path.insert(0, str(ROOT))
            from middleware.detector import TransformerDetector
            curves[name] = np.array(TransformerDetector(p).score(test.text.tolist()))
        except Exception as exc:
            print(f"  ! ROC for {name} unavailable: {exc}")

    if not curves:
        return
    fig, ax = plt.subplots(figsize=(5.6, 4.6))
    # All curves hug the top-left corner, so an inset magnifies the region where they
    # actually differ; without it the figure cannot discriminate between detectors.
    inset = ax.inset_axes([0.42, 0.16, 0.54, 0.46])
    for name, s in curves.items():
        fpr, tpr, _ = roc_curve(y, s)
        lbl = f"{name} (AUC = {roc_auc_score(y, s):.4f})"
        ax.plot(fpr, tpr, lw=1.6, label=lbl)
        inset.plot(fpr, tpr, lw=1.4)
    ax.plot([0, 1], [0, 1], "k--", lw=0.8, label="Chance")
    inset.set_xlim(0, 0.10)
    inset.set_ylim(0.88, 1.005)
    inset.tick_params(labelsize=6)
    inset.set_title("detail: low false-positive region", fontsize=6.5)
    ax.set_xlabel("False-positive rate")
    ax.set_ylabel("True-positive rate (detection rate)")
    ax.set_title("ROC curves on the held-out test set")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), fontsize=7.5,
              frameon=False, ncol=2)
    fig.tight_layout()
    fig.savefig(FIG / "roc_curves.png", bbox_inches="tight")
    plt.close(fig)


def fig_comparison(M):
    keys = [k for k in ORDER if k in M and "test" in M[k]]
    if not keys:
        return
    mets = [("precision", "Precision"), ("recall", "Recall"), ("f1", "F1-score"),
            ("fpr", "False-positive rate")]
    x = np.arange(len(keys))
    w = 0.2
    fig, ax = plt.subplots(figsize=(1.55 * len(keys) + 2.5, 4.2))
    for i, (mk, lbl) in enumerate(mets):
        vals = [M[k]["test"].get(mk, 0) for k in keys]
        errs = [M[k]["test"].get(mk + "_sd", 0) for k in keys]
        ax.bar(x + (i - 1.5) * w, vals, w, yerr=errs, capsize=2, label=lbl)
    ax.set_xticks(x, [LABELS[k] for k in keys], fontsize=7.5)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Score")
    ax.set_title("Detector comparison on the held-out test set (mean of three seeds)")
    ax.legend(fontsize=8, ncol=4, loc="upper center", bbox_to_anchor=(0.5, -0.09),
              frameon=False)
    fig.tight_layout()
    fig.savefig(FIG / "model_comparison.png", bbox_inches="tight")
    plt.close(fig)


def fig_evasion(M):
    keys = [k for k in ORDER if k in M and "evasion" in M[k]]
    if not keys:
        return
    transforms = sorted({kk[3:] for k in keys for kk in M[k]["evasion"]
                         if kk.startswith("dr_") and not kk.endswith("_sd")})
    if not transforms:
        return
    x = np.arange(len(transforms))
    w = min(0.8 / len(keys), 0.16)
    fig, ax = plt.subplots(figsize=(1.05 * len(transforms) + 3.2, 4.4))
    for i, k in enumerate(keys):
        vals = [M[k]["evasion"].get(f"dr_{t}", 0) for t in transforms]
        ax.bar(x + (i - (len(keys) - 1) / 2) * w, vals, w, label=LABELS[k].replace("\n", " "))
    for i, k in enumerate(keys):
        base = M[k]["test"].get("recall")
        if base:
            ax.axhline(base, ls=":", lw=0.7, color=f"C{i}")
    ax.set_xticks(x, [t.replace("_", "\n") for t in transforms], fontsize=7)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Detection rate")
    ax.set_title("Detection rate under adaptive evasion\n"
                 "(dotted lines: each detector's rate on the unmodified test set)", fontsize=10)
    # Placed below the axes so it cannot obscure the leftmost bar groups.
    ax.legend(fontsize=8, ncol=min(len(keys), 4), loc="upper center",
              bbox_to_anchor=(0.5, -0.16), frameon=False)
    fig.tight_layout()
    fig.savefig(FIG / "evasion_degradation.png", bbox_inches="tight")
    plt.close(fig)


def fig_lab_levels(tbl: pd.DataFrame | None):
    if tbl is None or tbl.empty:
        return
    x = np.arange(len(tbl))
    blocked = tbl["Attacks blocked by a guardrail"] / tbl["Attacks issued"]
    over = tbl["Benign prompts over-blocked"] / tbl["Benign prompts issued"]
    fig, ax = plt.subplots(figsize=(7.2, 4.0))
    ax.bar(x - 0.2, blocked, 0.4, label="Attacks blocked by a guardrail")
    ax.bar(x + 0.2, over, 0.4, label="Benign prompts over-blocked")
    ax.set_xticks(x, [f"Level {i + 1}" for i in x])
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Proportion")
    ax.set_title("Guardrail effectiveness against over-defence in the prompt-injection lab")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(FIG / "guardrail_levels.png", bbox_inches="tight")
    plt.close(fig)


def main():
    M = load_all()
    if not M:
        raise SystemExit("no metrics found - run the training scripts first")

    tables = {
        "results_main": table_main(M),
        "results_confusion": table_confusion(M),
        "results_per_class_recall": table_per_class(M),
        "results_evasion": table_evasion(M),
        "results_evasion_by_transform": table_evasion_by_transform(M),
    }
    lab = table_lab_levels()
    if lab is not None:
        tables["results_guardrail_levels"] = lab

    for name, df in tables.items():
        if df is not None and not df.empty:
            df.to_csv(TAB / f"{name}.csv", index=False)
            print(f"  {name}.csv ({len(df)} rows)")

    fig_confusion(M)
    fig_comparison(M)
    fig_evasion(M)
    fig_lab_levels(lab)
    try:
        fig_roc()
    except Exception as exc:
        print(f"  ! ROC figure failed: {type(exc).__name__}: {exc}")

    consolidated = {"models": M}
    for extra in ("dataset_provenance.json",):
        p = TAB / extra
        if p.exists():
            consolidated["dataset"] = json.loads(p.read_text())
    p = OUT / "latency.json"
    if p.exists():
        consolidated["latency"] = json.loads(p.read_text())
    (OUT / "metrics.json").write_text(json.dumps(consolidated, indent=2, default=float))

    print(f"\nWrote outputs/metrics.json and {len(list(FIG.glob('*.png')))} figures")
    print(tables["results_main"].to_string(index=False))


if __name__ == "__main__":
    main()
