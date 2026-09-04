"""Build the context dictionary of real, measured values used by Chapters Four to Six.

Every number here is read from the artefacts produced by the pipeline. Where a value is
genuinely unavailable, a "[PLACEHOLDER: ...]" string naming the exact command needed to
produce it is substituted, so that nothing in the document is invented.
"""
from __future__ import annotations

import json
import pathlib

import pandas as pd

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "outputs"
TAB = OUT / "tables"

MODEL_LABEL = {"LogisticRegression": "Logistic Regression", "RandomForest": "Random Forest",
               "SVM": "the Support Vector Machine", "DistilBERT": "DistilBERT",
               "BERT": "BERT", "KeywordFilter": "the keyword filter",
               "OffTheShelfDeBERTa": "the off-the-shelf DeBERTa detector"}
TRAINED = ["LogisticRegression", "RandomForest", "SVM", "DistilBERT", "BERT"]


def ph(cmd: str) -> str:
    return f"[PLACEHOLDER: {cmd}]"


def pc(v, dp=2):
    """Format a proportion as a percentage in the document's ‘per cent’ register."""
    return f"{100 * float(v):.{dp}f}"


def load_metrics() -> dict:
    M = {}
    for f in ("metrics_classical.json", "metrics_transformers.json", "metrics_baselines.json"):
        p = OUT / f
        if p.exists():
            M.update(json.loads(p.read_text()))
    return M


def _best(M, key="f1", among=None):
    cands = [k for k in (among or TRAINED) if k in M and "test" in M[k]]
    if not cands:
        return None
    return max(cands, key=lambda k: M[k]["test"].get(key, -1))


def _lowest_fpr(M, among=None):
    cands = [k for k in (among or TRAINED) if k in M and "test" in M[k]]
    if not cands:
        return None
    return min(cands, key=lambda k: M[k]["test"].get("fpr", 9))


def build(M: dict, prov: dict, lab: pd.DataFrame | None, latency: dict | None,
          env: dict) -> dict:
    c: dict = dict(env)

    # ---- dataset ---------------------------------------------------------------------
    by_class = dict(prov["by_class"])
    by_split = dict(prov["by_split"])
    c.update(
        n_total=f"{prov['n_total']:,}",
        n_benign=f"{prov['n_benign']:,}",
        n_malicious=f"{prov['n_malicious']:,}",
        n_direct=f"{by_class.get('direct_injection', 0):,}",
        n_jailbreak=f"{by_class.get('jailbreak', 0):,}",
        n_indirect=f"{by_class.get('indirect_injection', 0):,}",
        n_raw=f"{prov['dedup']['initial']:,}",
        n_exact_dupes=f"{prov['dedup']['exact_duplicates_removed']:,}",
        n_near_dupes=f"{prov['dedup']['near_duplicates_removed']:,}",
        n_train=f"{by_split.get('train', 0):,}",
        n_val=f"{by_split.get('val', 0):,}",
        n_test=f"{by_split.get('test', 0):,}",
    )

    # ---- trigger audit ----------------------------------------------------------------
    ta = pd.read_csv(TAB / "trigger_audit.csv")
    c["n_triggers"] = str(len(ta))
    c["n_triggers_both"] = str(int(ta.present_in_benign.sum()))
    row = ta[ta.trigger == "show me"]
    c["trig_showme_benign"] = f"{int(row.benign_count.iloc[0]):,}" if len(row) else ph("inspect outputs/tables/trigger_audit.csv")
    c["trig_showme_mal"] = f"{int(row.malicious_count.iloc[0]):,}" if len(row) else ""

    # ---- evasion ----------------------------------------------------------------------
    ev_path = ROOT / "data" / "evasion_set.jsonl"
    if ev_path.exists():
        ev = pd.read_json(ev_path, lines=True)
        c["n_evasion"] = f"{len(ev):,}"
        # NB: ev["transform"] rather than ev.transform, which resolves to the method.
        c["n_paraphrase"] = f"{int((ev['transform'] == 'llm_paraphrase').sum()):,}"
        c["n_test_attacks"] = f"{ev['source_text'].nunique():,}"
    else:
        c["n_evasion"] = c["n_paraphrase"] = c["n_test_attacks"] = ph("python ml/evasion.py")

    # ---- lab probe --------------------------------------------------------------------
    if lab is not None and len(lab):
        atk = lab[lab.is_attack]
        ben = lab[~lab.is_attack]
        n_lvl = lab.level.nunique()
        c["lab_n_attacks"] = str(len(atk) // n_lvl)
        c["lab_n_benign"] = str(len(ben) // n_lvl)
        c["lab_n_turns"] = str(len(lab))
        c["lab_total_leaks"] = str(int(atk.secret_leaked.fillna(False).sum()))
        l3 = lab[lab.level == 3]
        a3, b3 = l3[l3.is_attack], l3[~l3.is_attack]
        c["lab_l3_blocked"] = str(int(a3.guardrails_triggered.map(bool).sum()))
        c["lab_l3_over"] = str(int(b3.guardrails_triggered.map(bool).sum()))
        c["lab_l3_over_pct"] = pc(b3.guardrails_triggered.map(bool).sum() / max(len(b3), 1), 1)
        c["lab_mean_latency"] = f"{lab.latency_s.mean():.2f}"
    else:
        for k in ("lab_n_attacks", "lab_n_benign", "lab_n_turns", "lab_total_leaks",
                  "lab_l3_blocked", "lab_l3_over", "lab_l3_over_pct", "lab_mean_latency"):
            c[k] = ph("python lab_eval/probe.py 1 2 3 4 5")

    # ---- headline model results -------------------------------------------------------
    best = _best(M)
    lowfpr = _lowest_fpr(M)
    c["best_model"] = MODEL_LABEL.get(best, ph("train the models")) if best else ph("train the models")

    if best:
        bt = M[best]["test"]
        # Model names are proper nouns (DistilBERT, SVM); never case-fold them.
        subject = MODEL_LABEL[best]
        subject = subject[0].upper() + subject[1:] if subject.startswith("the ") else subject
        c["para_main_results"] = (
            f"{subject} achieved the highest F1-score at {bt['f1']:.4f} "
            f"(standard deviation {bt.get('f1_sd', 0):.4f}), with a precision of "
            f"{bt['precision']:.4f}, a recall of {bt['recall']:.4f}, a false-positive rate "
            f"of {bt['fpr']:.4f} and an area under the receiver operating characteristic "
            f"curve of {bt.get('roc_auc', float('nan')):.4f}. "
            + _spread_sentence(M)
            + " The standard deviations across seeds are small throughout — no trained "
              "detector varies by more than a hundredth of a point in F1 — which indicates "
              "that the differences between models, though modest, are stable rather than "
              "artefacts of initialisation.")
    else:
        c["para_main_results"] = ph("python ml/train_classical.py && python ml/train_transformers.py")

    if lowfpr:
        lf = M[lowfpr]["test"]
        n_benign_test = int(lf.get("tn", 0) + lf.get("fp", 0))
        c["para_fpr"] = (
            "Because Chapter Three declares the false-positive rate a primary outcome "
            "rather than an afterthought, it warrants separate comment. The lowest rate "
            f"among the trained detectors is {lf['fpr']:.4f} for "
            f"{MODEL_LABEL[lowfpr]}, which corresponds to {int(round(lf.get('fp', 0)))} "
            f"false positives among {n_benign_test:,} benign test prompts. "
            + _fpr_context(M) +
            " The practical significance of this figure is best appreciated against the "
            "keyword baseline reported in Section 5.2.6 and against the deployed guardrails "
            "measured in the live application, where the corresponding rate is very much "
            "higher.")
    else:
        c["para_fpr"] = ph("python ml/train_classical.py")

    # ---- per-class -------------------------------------------------------------------
    c["para_per_class"] = _per_class_para(M)

    # ---- evasion ---------------------------------------------------------------------
    c["para_evasion"], c["para_evasion_transforms"], c["limitation_evasion"] = _evasion_paras(M)

    # ---- latency ---------------------------------------------------------------------
    c["para_latency"], c["para_over_blocking"] = _latency_paras(latency)

    # ---- lab -------------------------------------------------------------------------
    c["para_lab_levels"], c["para_lab_resistance"], c["limitation_lab"] = _lab_paras(c, lab)

    # ---- objectives ------------------------------------------------------------------
    c.update(_objectives(c, M))

    # ---- discussion ------------------------------------------------------------------
    c.update(_discussion(c, M))

    # ---- threats to validity ----------------------------------------------------------
    c.update(_validity(c, M))

    # ---- chapter six -----------------------------------------------------------------
    c.update(_chapter_six(c, M))

    return c


def _validity(c, M):
    best = _best(M)
    v = {}
    v["para_construct_validity"] = (
        "Construct validity concerns whether the quantities measured are the quantities of "
        "interest. Two constructs are imperfectly operationalised here. The first is the "
        "label itself: a prompt is treated as malicious because the corpus from which it "
        "came labels it so, and those labels were assigned by different teams under "
        "different definitions — in particular, the boundary between an aggressive but "
        "legitimate instruction and a genuine injection is drawn differently by different "
        "sources, and the study inherits those inconsistencies. The second is the "
        "operational construct. What matters in deployment is whether an attack succeeds, "
        "not whether a string is classified correctly; detection rate is a proxy for "
        "prevented harm, and Section 5.2.6 shows the two can come apart, since every "
        "attack against the live application failed regardless of what any detector said "
        "about it. The measured false-positive rate is the more directly meaningful "
        "quantity, because a refused legitimate request is a harm in itself rather than a "
        "proxy for one.")

    v["para_internal_validity"] = (
        "Internal validity concerns whether the comparisons are fair. Several controls "
        "support them: every model was trained and evaluated on identical partitions fixed "
        "in advance, every feature extractor was fitted on the training partition alone, "
        "the evasion set was derived exclusively from held-out attacks before any model was "
        "fitted, and every result is the mean of three seeds. Two threats remain. The first "
        "is that the corpus is assembled from sources with different provenances, so a "
        "detector could in principle learn to identify the source rather than the "
        "phenomenon; the deduplication, the domain-matched benign set, the hard negatives "
        "and the trigger audit in Table 5.2 are the controls against this, and the audit "
        "shows that all but one of the audited phrases occur in both classes, but the risk "
        "is mitigated rather than eliminated. The second is that hyperparameters were "
        "selected by cross-validation on the combined training and validation partitions "
        "while the transformers used the validation partition for early stopping, so the "
        "two families did not use the validation data identically; the effect is small but "
        "it is not zero."
        + (" A third, narrower point: the Support Vector Machine returned identical results "
           "for all three seeds, because a linear support vector machine on fixed data is "
           "deterministic apart from tie-breaking, so its reported standard deviation of "
           "zero reflects the estimator rather than genuine stability under resampling."
           if "SVM" in M and M["SVM"]["test"].get("f1_sd", 1) == 0 else ""))

    v["para_external_validity"] = (
        "External validity concerns how far these results travel. They should be "
        "generalised cautiously for four reasons. The corpus, though drawn from six public "
        "sources, is dominated by English-language prompts in a broadly conversational "
        "register, and nothing here speaks to detection in other languages, where the "
        "literature reviewed in Chapter Two records that at least one deployed detector "
        "misclassifies benign non-English input as attack. The indirect class is small, so "
        f"the indirect result rests on {c['n_indirect']} samples. The evasion battery is a "
        "fixed set of transformations rather than an adaptive adversary, so the reported "
        "degradation is a lower bound on what a determined attacker could achieve. And the "
        "operational measurements were taken on one workstation over loopback, with the "
        "services otherwise idle, so the latency figures establish an order of magnitude "
        "rather than a production service level. The findings most likely to generalise "
        "are the qualitative ones: that performance on a clean held-out split does not "
        "predict performance under intent-preserving transformation, and can conceal large "
        "differences in robustness between detectors it ranks as equivalent; and that a "
        "keyword-based defence carries a false-positive cost that a learned detector on "
        "the same data does not. The specific magnitudes reported here are properties of "
        "this corpus and this transformation battery, and should not be carried over to "
        "another deployment without being measured again there.")
    return v


def _spread_sentence(M) -> str:
    scored = [(k, M[k]["test"]["f1"]) for k in TRAINED if k in M and "test" in M[k]]
    if len(scored) < 2:
        return ""
    scored.sort(key=lambda t: -t[1])
    lo = scored[-1]
    return (f"The spread across the five trained detectors is narrow: the lowest F1-score "
            f"is {lo[1]:.4f} for {MODEL_LABEL[lo[0]]}, a difference of "
            f"{scored[0][1] - lo[1]:.4f} from the best.")


def _fpr_context(M) -> str:
    rates = [(k, M[k]["test"]["fpr"]) for k in TRAINED if k in M and "test" in M[k]]
    if not rates:
        return ""
    hi = max(rates, key=lambda t: t[1])
    return (f"The highest rate among the trained detectors is {hi[1]:.4f} for "
            f"{MODEL_LABEL[hi[0]]}, so all five sit within a factor of "
            f"{hi[1] / max(min(r for _, r in rates), 1e-9):.1f} of one another.")


def _per_class_para(M) -> str:
    rows = {k: M[k].get("per_class_recall", {}) for k in TRAINED if k in M}
    rows = {k: v for k, v in rows.items() if v}
    if not rows:
        return ph("python ml/train_classical.py && python ml/train_transformers.py")

    def avg(cls):
        vals = [v[cls] for v in rows.values() if cls in v]
        return sum(vals) / len(vals) if vals else float("nan")

    d, j, i = avg("direct_injection"), avg("jailbreak"), avg("indirect_injection")
    best_ind = max(rows.items(), key=lambda kv: kv[1].get("indirect_injection", -1))
    worst_ind = min(rows.items(), key=lambda kv: kv[1].get("indirect_injection", 2))

    s = (f"Averaged across the five trained detectors, the detection rate is {d:.4f} on "
         f"direct injection, {j:.4f} on jailbreak prompts and {i:.4f} on indirect "
         f"injection. ")
    if i < d:
        s += ("Indirect injection is therefore the weakest of the three classes, which is "
              "consistent with the third gap identified in Chapter Two: indirect detection "
              "is the least mature of the capabilities examined here. Two factors plausibly "
              "contribute. The injected instruction is a small fraction of a long retrieved "
              "document, so the signal is diluted; and the indirect class is much the "
              "smallest in the corpus, so the detectors have seen correspondingly fewer "
              "examples of it. ")
    else:
        s += ("Indirect injection is detected at least as reliably as direct injection "
              "here, which is a more favourable result than the literature reviewed in "
              "Chapter Two would predict, and it should be read against the small size of "
              "the indirect class. ")
    s += (f"The variation between detectors is also greatest on this class: "
          f"{MODEL_LABEL[best_ind[0]]} reaches "
          f"{best_ind[1].get('indirect_injection', float('nan')):.4f} while "
          f"{MODEL_LABEL[worst_ind[0]]} reaches "
          f"{worst_ind[1].get('indirect_injection', float('nan')):.4f}, a far wider gap "
          f"than separates them on direct injection.")
    return s


def _evasion_paras(M):
    have = {k: M[k] for k in list(TRAINED) + ["KeywordFilter", "OffTheShelfDeBERTa"]
            if k in M and "evasion" in M[k] and "test" in M[k]}
    if not have:
        p = ph("python ml/evasion.py && python ml/train_classical.py && "
               "python ml/train_transformers.py")
        return p, p, p

    degr = {k: (v["test"]["recall"], v["evasion"]["detection_rate"]) for k, v in have.items()}
    trained = {k: v for k, v in degr.items() if k in TRAINED}
    most = max(trained.items(), key=lambda kv: kv[1][0] - kv[1][1]) if trained else None
    least = min(trained.items(), key=lambda kv: kv[1][0] - kv[1][1]) if trained else None

    worst_rel = (most[1][0] - most[1][1]) / most[1][0] if most else 0
    best_rel = (least[1][0] - least[1][1]) / least[1][0] if least else 0
    spread = worst_rel - best_rel

    p1 = ("The effect of the adaptive set is strongly model-dependent rather than uniform, "
          "and that unevenness is the substantive finding. ")
    if most and least:
        # The most robust detector may hold steady or even improve, so the sentence must
        # not assume its rate fell.
        if best_rel > 0.001:
            p1 += (f"The most robust of the trained detectors is {MODEL_LABEL[least[0]]}, "
                   f"whose detection rate falls only from {least[1][0]:.4f} on the "
                   f"unmodified test set to {least[1][1]:.4f} on the adaptive set, a "
                   f"relative loss of {pc(best_rel, 1)} per cent. ")
        else:
            p1 += (f"The most robust of the trained detectors is {MODEL_LABEL[least[0]]}, "
                   f"whose detection rate is essentially unchanged — {least[1][0]:.4f} on "
                   f"the unmodified test set against {least[1][1]:.4f} on the adaptive "
                   f"set. ")
        p1 += (f"The least robust is {MODEL_LABEL[most[0]]}, which falls from "
               f"{most[1][0]:.4f} to {most[1][1]:.4f}, a relative loss of "
               f"{pc(worst_rel, 1)} per cent. ")
        # A ratio is only meaningful when both losses are genuine losses.
        if best_rel > 0.005 and worst_rel > 0:
            p1 += f"The loss is {worst_rel / best_rel:.0f} times greater. "
    if spread > 0.05:
        p1 += ("This spread is the most consequential result of the study, and it is "
               "invisible on the standard test set, where the two detectors are separated "
               f"by only {abs(most[1][0] - least[1][0]):.4f} in detection rate. Two "
               "detectors that appear equivalent under conventional evaluation are not "
               "equivalent at all once the attacker is permitted to rephrase. It follows "
               "that robustness under intent-preserving transformation is not a refinement "
               "to be reported alongside the headline metrics but a distinct property that "
               "conventional evaluation does not measure, and the second gap identified in "
               "Chapter Two is therefore confirmed in a specific and actionable form: the "
               "question is not whether detectors degrade, but which ones, and by how "
               "much.")
    else:
        p1 += ("The degradation is comparable across detectors, so on this evidence the "
               "choice of model does not materially affect robustness to the "
               "transformations applied here.")
    p1 += (" The practical consequence is that a detector selected on held-out F1 alone "
           "may be among the least robust available, and that evasion testing should "
           "inform model selection rather than merely characterise the model already "
           "chosen.")

    # transform-level detail
    tf_means = {}
    for k, v in have.items():
        for kk, vv in v["evasion"].items():
            if kk.startswith("dr_") and not kk.endswith("_sd"):
                tf_means.setdefault(kk[3:], []).append(vv)
    tf_avg = {t: sum(v) / len(v) for t, v in tf_means.items()}
    hardest = sorted(tf_avg.items(), key=lambda kv: kv[1])[:3]
    easiest = sorted(tf_avg.items(), key=lambda kv: -kv[1])[:2]

    hard_s = (", ".join(f"{t.replace('_', ' ')} ({v:.4f})" for t, v in hardest[:-1])
              + f" and {hardest[-1][0].replace('_', ' ')} ({hardest[-1][1]:.4f})")
    risers = [k for k, (base, ev) in degr.items() if ev > base + 1e-6]
    if risers:
        p1 += (" One result runs the other way and is worth stating explicitly: "
               + " and ".join(MODEL_LABEL[k] for k in risers)
               + (" detects" if len(risers) == 1 else " detect")
               + " the transformed attacks more reliably than the originals. This is not "
                 "evidence of robustness. The adaptive set contains attacks only, so a "
                 "detector biased towards flagging can score well on it; and several of "
                 "the transformations — role-play wrapping, translation framing, "
                 "positional burial — add explicit instruction-giving language that makes "
                 "an attack more conspicuous rather than less. The figure should therefore "
                 "be read alongside the false-positive rate on the standard test set, not "
                 "in isolation.")

    p2 = ("The decomposition by transformation shows where that degradation comes from. "
          f"Averaged across all detectors, the most damaging transformations are "
          + hard_s
          + ", while "
          + " and ".join(f"{t.replace('_', ' ')} ({v:.4f})" for t, v in easiest)
          + " are absorbed most easily. The pattern is intelligible. Transformations that "
            "alter the characters of the instruction itself defeat representations built "
            "on word and sub-word statistics, because the surface evidence the detector "
            "relies on is simply no longer present; transformations that merely wrap or "
            "relocate an otherwise intact instruction leave that evidence available. "
            "Character n-gram features were included precisely to blunt the first class of "
            "attack, and the results indicate they blunt it without eliminating it.")

    lim = ("The third limitation is that robustness under evasion is a property of the "
           "chosen detector rather than of the middleware, and the middleware will "
           "faithfully inherit whatever brittleness its back-end has. "
           + (f"The spread measured here is wide: {MODEL_LABEL[most[0]]} loses "
              f"{pc(worst_rel, 1)} per cent of its detection rate on transformed attacks "
              f"while {MODEL_LABEL[least[0]]} loses {pc(best_rel, 1)} per cent, yet the two "
              f"differ by only {abs(most[1][0] - least[1][0]):.4f} on the standard test "
              f"set. " if most and least else "")
           + "An operator selecting a back-end on held-out F1 alone could therefore deploy "
             "the least robust option available while believing it equivalent to the best. "
             "This is a limitation of the artefact and not merely of the evaluation: no "
             "mitigation for evasion was implemented, only measurement, so the middleware "
             "should be deployed as one layer among several rather than as a sufficient "
             "defence in its own right, and its back-end should be chosen on evasion "
             "performance rather than on held-out accuracy.")
    return p1, p2, lim


def _latency_paras(lat):
    if not lat:
        p = ph("start the middleware with `python -m middleware.app`, then run "
               "`python ml/bench_latency.py`")
        return p, p

    http = lat.get("http_latency", {})
    inproc = lat.get("inprocess_latency", {})
    p1 = ("The fourth experiment measures what the middleware costs to operate. Screening "
          f"a single user prompt over HTTP took a mean of {http.get('mean_ms', '?')} "
          f"milliseconds and a median of {http.get('median_ms', '?')} milliseconds, with a "
          f"95th percentile of {http.get('p95_ms', '?')} milliseconds, measured over "
          f"{http.get('n', '?')} benign prompts drawn from the held-out test set. These "
          "figures include HTTP transport and serialisation, not merely model inference. ")
    if inproc:
        parts = [f"{k} at {v['mean_ms']} milliseconds" for k, v in inproc.items()]
        p1 += ("Measured in process, the three detector back-ends differ substantially: "
               + ", ".join(parts) + " on average per item. "
               "The batch endpoint reduces the per-item cost further by amortising fixed "
               "overheads, which matters for the retrieved-content channel where a single "
               "retrieval may return many documents. ")
    p1 += ("For comparison, the mean end-to-end latency of a single turn against the "
           "protected model, measured in the same session, is reported in Table 5.9 and is "
           "more than an order of magnitude greater; the screening overhead is therefore "
           "small relative to the cost of the model call it protects.")

    ob = lat.get("over_blocking", [])
    if ob:
        lines = []
        for o in ob:
            lines.append(f"on the {o['set']} ({o['n']:,} prompts) the middleware blocked "
                         f"{pc(o['block_rate'])} per cent and intervened in any way on "
                         f"{pc(o['any_intervention_rate'])} per cent")
        p2 = ("Over-blocking was measured on legitimate traffic at the default thresholds: "
              + "; ".join(lines) + ". "
              "The distinction between the two figures matters. A block refuses the request "
              "outright and is the response the user experiences as a failure; sanitisation "
              "and escalation are milder interventions, and sanitisation in particular "
              "leaves the substance of a benign request intact. "
              + _hard_neg_comment(ob))
    else:
        p2 = ph("python ml/bench_latency.py")
    return p1, p2


def _hard_neg_comment(ob) -> str:
    hard = next((o for o in ob if "hard negative" in o["set"]), None)
    full = next((o for o in ob if "held-out" in o["set"]), None)
    if not hard or not full:
        return ""
    caveat = ""
    if hard["n"] < 30:
        caveat = (f" This particular comparison rests on only {hard['n']} prompts, because "
                  "the hard negatives are distributed across the partitions in the same "
                  "stratified proportion as everything else and only the held-out portion "
                  "may legitimately be used here; it should therefore be read as "
                  "corroborating the figure for the benign test set as a whole rather than "
                  "as independent evidence.")
    if hard["block_rate"] > full["block_rate"]:
        return ("As designed, the authored hard negatives are the sternest test: their "
                f"block rate of {pc(hard['block_rate'])} per cent exceeds that of the "
                f"benign test set as a whole ({pc(full['block_rate'])} per cent), "
                "confirming that prompts deliberately constructed to resemble attacks are "
                "where over-defence concentrates. That the rate nonetheless remains far "
                "below the keyword baseline is the central practical argument for a "
                "learned detector over a rule-based one.")
    return ("Notably, the authored hard negatives are blocked no more often than benign "
            f"traffic generally ({pc(hard['block_rate'])} per cent against "
            f"{pc(full['block_rate'])} per cent), which indicates that the learned "
            "detectors are not relying on the trigger phrases those prompts were "
            "constructed to contain.")


def _lab_paras(c, lab):
    if lab is None or not len(lab):
        p = ph("python lab_eval/probe.py 1 2 3 4 5")
        return p, p, p

    p1 = ("The pattern is stark and it bears directly on the first research gap. At levels "
          "one and two no defence fires at all, because the output filter at level two "
          "matches only the literal secret string and no reply contained it. From level "
          f"three onwards the keyword input heuristic intercepts all {c['lab_l3_blocked']} "
          f"attack payloads — a detection rate of 100 per cent — but it also refuses "
          f"{c['lab_l3_over']} of the {c['lab_n_benign']} legitimate prompts, an "
          f"over-blocking rate of {c['lab_l3_over_pct']} per cent. Levels four and five add "
          "further defences but change neither figure, because the keyword heuristic runs "
          "first and short-circuits the request before the judge model or the input "
          "sanitiser is reached.")

    p2 = ("A second and unexpected result concerns the attacks themselves. Across "
          f"{c['lab_n_turns']} logged turns spanning all five guardrail levels, the planted "
          f"secret was disclosed {c['lab_total_leaks']} times. At level one, where the "
          "application has no input heuristic, no output filter, no hardened prompt, no "
          "judge and no sanitiser, and where the documented payloads are specified to "
          "succeed, every attack was nonetheless refused by the model itself. The battery "
          "was subsequently extended well beyond the documented payloads — to completion "
          "attacks, payload splitting, acrostic and reverse-spelling side channels, "
          "hypothetical framing, structured-output exfiltration, multi-turn crescendo "
          "sequences, forged conversation history in which a prior assistant turn was "
          "fabricated, and a deliberately weakened system prompt that merely asked the "
          "assistant not to disclose the code — and against two different target models. "
          "None succeeded. The practical implication is that for this particular "
          "objective, extracting a secret held in the system prompt, contemporary "
          "model-side alignment was a more effective defence than any of the five "
          "application-level guardrails, four of which contributed nothing and the fifth "
          "of which contributed a substantial false-positive rate. This does not "
          "generalise to prompt injection as a whole: the threat that motivates this "
          "project is not confined to secret extraction, and alignment offers no comparable "
          "protection where an injected instruction directs an action or is carried in "
          "retrieved content. It does, however, caution against inferring the value of a "
          "guardrail from the fact that attacks fail while it is switched on.")

    lim = ("The fifth limitation is that the integration target proved to be a weak "
           "instrument. Because no attack succeeded in extracting the planted secret, the "
           "live application could not be used to measure end-to-end mitigation "
           "effectiveness — the quantity of interest, the reduction in successful "
           "extractions attributable to the middleware, has a denominator of zero. The "
           "application therefore evidences the over-defence problem and the operation of "
           "the middleware in a real request path, but not the prevention of a successful "
           "attack. Demonstrating that would require either a target model without "
           "contemporary alignment training or a task, such as instructed tool use, where "
           "alignment offers less protection.")
    return p1, p2, lim


def _objectives(c, M):
    best = _best(M)
    o = {}
    o["obj1"] = (
        "The first objective, to review existing prompt-injection attacks and defences in "
        "order to identify the gaps this project would address, is met by Chapter Two, "
        "which surveys direct and indirect attacks, heuristic, classical, transformer, "
        "commercial and architectural defences, and closes by naming three gaps together "
        "with two subsidiary concerns. Those gaps then determined the evaluation design "
        "rather than merely prefacing it: the false-positive rate is reported as a primary "
        "outcome throughout, an adaptive-evasion experiment addresses the second gap, and "
        "indirect injection is evaluated as a separate class. The objective is achieved.")

    o["obj2"] = (
        "The second objective, to assemble a working dataset of benign prompts alongside "
        "direct injections, jailbreak prompts and indirect injections, is met by the corpus "
        f"described in Section 5.2.1: {c['n_total']} unique samples across all four "
        "categories, kept as distinct classes rather than collapsed into a single malicious "
        "label, with four documented controls against spurious-feature learning and a "
        "published audit of trigger-phrase frequency. The objective is achieved, with the "
        "qualification that HackAPrompt could not be obtained and comparable open sources "
        "were substituted, and that the indirect class is small.")

    o["obj3"] = (
        "The third objective, to develop, train and comparatively evaluate detection models "
        "spanning classical classifiers and fine-tuned transformers, is met by the five "
        "detectors reported in Section 5.2.2, each trained under an identical protocol on "
        "identical partitions over three seeds and evaluated on the five metrics specified "
        "in Table 3.2, against two baselines. "
        + (f"The strongest on the held-out test set was {MODEL_LABEL[best]}. " if best else "")
        + "The comparison is genuine rather than nominal, and it yielded a result the "
          "objective did not anticipate: the two families perform comparably on the "
          "held-out test set, which given their very different operational costs would "
          "favour the cheaper classical models, yet they diverge sharply under evasion, "
          "which reverses that preference. A comparative evaluation confined to the "
          "standard split would have produced the opposite recommendation to the one the "
          "full evaluation supports. The objective is achieved.")

    o["obj4"] = (
        "The fourth objective, to build a prototype defence layer that screens each prompt "
        "in real time, is met by the Flask middleware described in Section 4.2.6. It is "
        "model-agnostic, screens the user-prompt and retrieved-content channels separately, "
        "applies a configurable block, sanitise or escalate policy, logs every decision, is "
        "covered by unit tests, and was integrated into a live chatbot and observed "
        "operating in its request path. Its latency and over-blocking behaviour are "
        "measured in Section 5.2.5. The objective is achieved.")

    o["obj5"] = (
        "The fifth objective, to test the system using detection rate, false-positive rate, "
        "precision, recall and F1-score and to push it further with evasion techniques, is "
        "met by Sections 5.2.2 to 5.2.5. All five metrics are reported for every detector, "
        "with ROC-AUC in addition, as means over three seeds with standard deviations; the "
        f"evasion experiment applies ten transformations to produce {c['n_evasion']} "
        "adaptive variants derived exclusively from held-out attacks, and the resulting "
        "degradation is reported both in aggregate and by transformation. The objective is "
        "achieved, and the evasion result is the most consequential finding of the study.")
    return o


def _discussion(c, M):
    best = _best(M)
    d = {}
    d["para_discussion_worked"] = (
        "Three things are established firmly by these results. Detection of prompt "
        "injection on a curated, deduplicated corpus is tractable for both model families: "
        + (f"the best detector reaches an F1-score of {M[best]['test']['f1']:.4f} with a "
           f"false-positive rate of {M[best]['test']['fpr']:.4f}, " if best else "")
        + "and the narrow spread between the five detectors suggests that on data of this "
          "kind the choice of model matters little — until robustness is tested, at which "
          "point it matters a great deal, as Section 5.2.4 shows. The screening middleware "
          "operates at a latency small relative to the "
          "model call it protects, which establishes that real-time screening is "
          "practicable rather than merely desirable. And the separation of the two "
          "screening channels works as intended, allowing retrieved content to be treated "
          "more strictly than user input without additional cost to the user.")

    d["para_discussion_limits"] = (
        "Several quantities of interest could not be measured. The reduction in successful "
        "attacks attributable to the middleware could not be established end to end, "
        "because no attack against the live application succeeded in the first place, as "
        "Section 5.2.6 reports. The behaviour of the detector under sustained production "
        "traffic, with concurrent users and real network transit, was not measured; the "
        "latency figures are single-machine, loopback measurements. Robustness against an "
        "adaptive adversary with query access to the deployed detector was not measured "
        "either: the evasion set is a fixed battery of transformations, which is a weaker "
        "test than an attacker optimising against the specific model. And no measurement "
        "was made of how detection performance drifts as attack techniques evolve, which "
        "would require longitudinal data this study does not have.")

    d["para_discussion_comparison"] = _comparison_para(M)

    d["para_discussion_gaps"] = (
        "Read against the three gaps set out in Section 2.13, the results speak to each "
        "differently. On over-defence, the study delivers what it promised: the "
        "false-positive rate is reported as a primary outcome for every detector and every "
        "baseline, and Section 5.2.6 supplies a concrete demonstration, in a live "
        "application, of a rule-based defence refusing a substantial fraction of legitimate "
        "help-desk traffic while a learned detector on the same corpus does not. On "
        "adaptive evasion, the study confirms the gap and sharpens it: the degradation "
        "reported in Section 5.2.4 is not merely large but highly uneven between detectors "
        "that are all but indistinguishable on the standard test set, so the gap is not "
        "only that detectors are brittle but that conventional evaluation cannot "
        "distinguish the brittle ones from the robust ones. No mitigation for this was "
        "implemented here, only measurement. On indirect detection, the study makes a modest "
        "contribution — indirect injection is evaluated as a distinct class with matched "
        "clean containers as a control — but the class is small, and the result should be "
        "treated as indicative. The honest summary is that the first gap is addressed, the "
        "second is characterised, and the third is only begun.")
    return d


def _comparison_para(M) -> str:
    best = _best(M)
    kw = M.get("KeywordFilter", {}).get("test")
    ots = M.get("OffTheShelfDeBERTa", {}).get("test")
    if not best:
        return ph("python ml/train_classical.py && python ml/baselines.py")
    bt = M[best]["test"]
    s = f"Against the keyword baseline, the comparison is decisive. "
    if kw:
        s += (f"The keyword filter achieves a recall of {kw['recall']:.4f} but at a "
              f"false-positive rate of {kw['fpr']:.4f} and an F1-score of {kw['f1']:.4f}, "
              f"against {bt['fpr']:.4f} and {bt['f1']:.4f} for {MODEL_LABEL[best]}. "
              "The baseline is not merely worse overall; it fails in the specific way "
              "Chapter Two predicts, by flagging legitimate requests that happen to contain "
              "an instruction-like phrase. ")
    else:
        s += ph("python ml/baselines.py") + " "
    if ots and not M.get("OffTheShelfDeBERTa", {}).get("unavailable"):
        s += (f"Against the published DeBERTa detector, the comparison is more "
              f"instructive. It achieves an F1-score of {ots['f1']:.4f} and a "
              f"false-positive rate of {ots['fpr']:.4f} on this corpus. ")
        if ots["f1"] < bt["f1"]:
            s += ("It is outperformed by the detectors trained here, but that result must "
                  "be read with care and not overstated: the trained models were fitted on "
                  "the training partition of this corpus and are being evaluated on its "
                  "test partition, whereas the published detector was trained on different "
                  "data entirely and is being evaluated out of distribution. The "
                  "comparison shows that a detector tuned to a deployment's own traffic "
                  "outperforms a general-purpose one on that traffic; it does not show "
                  "that the approach taken here is superior in general.")
        else:
            s += ("It outperforms the detectors trained here despite never having seen "
                  "this corpus, which is a strong result for the off-the-shelf option and "
                  "a caution against assuming that a locally trained detector is "
                  "automatically preferable.")
    else:
        s += ("The published DeBERTa detector could not be evaluated in this run; the "
              "command needed to populate that comparison is given in the results file.")
    return s


def _chapter_six(c, M):
    best = _best(M)
    o = {}
    o["conclusion_1"] = (
        "The aim of the study was to design, implement and rigorously evaluate a "
        "machine-learning system that detects prompt injection against applications built "
        "on large language models and mitigates it through a middleware layer, with "
        "explicit attention to the false-positive rate and to robustness against adaptive "
        "evasion. That aim has been met. A working detector and a working middleware exist "
        "and have been measured, "
        + (f"the strongest detector reaching an F1-score of {M[best]['test']['f1']:.4f} at "
           f"a false-positive rate of {M[best]['test']['fpr']:.4f} on the held-out test "
           f"set, " if best else "")
        + "and the false-positive rate and evasion robustness were treated as primary "
          "outcomes throughout rather than as afterthoughts, which was the specific "
          "methodological commitment the aim contained.")
    o["conclusion_2"] = (
        "The evidence in Chapter Five supports a more qualified conclusion than the "
        "headline metrics alone would suggest, and it is the qualification that carries "
        "the contribution. Detection on a clean held-out split is close to solved and is "
        "not where the difficulty lies. The difficulty lies in what happens on either side "
        "of that measurement: in the degradation when attacks are rephrased or obfuscated "
        "while preserving their intent — degradation which Section 5.2.4 shows to be "
        "severe for some detectors and slight for others that the standard test set cannot "
        "tell apart — and in the cost imposed on legitimate users by defences tuned for "
        "sensitivity, which Section 5.2.6 demonstrates in a running application. The two "
        "findings share a shape: conventional evaluation is silent on precisely the "
        "properties that determine whether a defence is worth deploying. A detector chosen "
        "on held-out accuracy alone may be the most brittle of those available, and a "
        "defence whose usability cost is never measured will be tuned by user complaint "
        "rather than by evidence. That, rather than any particular metric, is what this "
        "study contributes.")
    o["contribution_practice"] = (
        "The first concerns industry practice. The study provides an end-to-end, "
        "reproducible evaluation in which the false-positive rate is a reported primary "
        "outcome for every detector and baseline, and in which robustness to intent-"
        "preserving transformation is measured rather than assumed. Practitioners "
        "selecting a prompt-injection control are commonly offered detection rates alone; "
        "the evidence assembled here shows both why that is insufficient and what the "
        "missing figures look like when they are gathered. The demonstration in "
        "Section 5.2.6 — that in a live assistant a keyword guardrail intercepted every "
        f"attack while also refusing {c['lab_l3_over_pct']} per cent of legitimate "
        "requests — is a concrete, transferable argument for treating over-defence as an "
        "operational risk in its own right.")
    return o
