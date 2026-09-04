"""Chapter Five: Testing, Results and Evaluation.

Every quantity referenced here is drawn from the context dictionary, which build_document.py
populates from outputs/metrics.json. No figure is written by hand.
"""
from __future__ import annotations


def build(c: dict) -> list:
    B = []
    add = B.append

    add(("chapter_heading", "CHAPTER FIVE"))
    add(("chapter_subtitle", "TESTING, RESULTS AND EVALUATION"))

    add(("body",
         "This chapter reports what the implemented system was measured to do. It sets "
         "out the testing strategy, presents the composition of the dataset and the "
         "controls applied to it, gives detection performance on the held-out test set, "
         "reports robustness under adaptive evasion and performance on indirect injection "
         "specifically, measures the operational cost and the over-blocking rate of the "
         "middleware, compares the trained detectors against two baselines, evaluates each "
         "objective against its evidence, and closes with a discussion of the results and "
         "the threats to their validity."))

    # ---------------------------------------------------------------- 5.1
    add(("heading2", "5.1", "Testing Strategy"))
    add(("body",
         "Testing proceeded at four levels. At the unit level, the decision policy of the "
         f"middleware is covered by {c['n_tests']} tests that fix its behaviour at each "
         "threshold boundary, confirm that blocked content is withheld from the response "
         "rather than echoed, confirm that the retrieved channel is screened more strictly "
         "than the user channel, confirm that thresholds are genuinely configurable, and "
         "confirm that sanitisation removes known injection markers while leaving benign "
         f"text untouched. All {c['n_tests']} pass."))
    add(("body",
         "At the integration level, the middleware was exercised over HTTP as a running "
         "service, both singly and in batch, and then wired into the vulnerable chatbot so "
         "that screening decisions could be observed inside a real request path and a real "
         "browser session. At the experimental level, the four experiments specified in "
         "Section 3.7 were carried out: detection performance on the held-out test set, "
         "robustness on the reserved adaptive-attack set, indirect-injection performance "
         "on BIPIA, and the operational characteristics of the middleware. At the system "
         "level, the vulnerable application itself was probed with a battery of documented "
         "attack payloads across all five guardrail levels, which produced the evidence on "
         "over-defence reported in Section 5.2.6."))
    add(("body",
         "Two methodological caveats govern how these numbers should be read. First, all "
         "detection results are reported as the mean of three seeds with the standard "
         f"deviation alongside; the seeds are {c['seeds_str']} and the partitions are "
         "identical across every model, so differences between models are not attributable "
         "to differences in data. Second, the adaptive-evasion set is derived exclusively "
         "from attacks in the held-out test partition and was generated before any model "
         "was fitted, so no evasion variant corresponds to material that any model saw in "
         "training."))

    # ---------------------------------------------------------------- 5.2
    add(("heading2", "5.2", "Test Results"))

    add(("heading3", "5.2.1", "Dataset composition and the controls applied"))
    add(("body",
         f"The assembled corpus contains {c['n_total']} unique samples: {c['n_benign']} "
         f"benign and {c['n_malicious']} malicious, the latter comprising "
         f"{c['n_direct']} direct injections, {c['n_jailbreak']} jailbreak prompts and "
         f"{c['n_indirect']} indirect injections. Deduplication removed "
         f"{c['n_exact_dupes']} exact duplicates and {c['n_near_dupes']} near-duplicates "
         f"from an initial {c['n_raw']} records. The stratified partitions contain "
         f"{c['n_train']} training, {c['n_val']} validation and {c['n_test']} test "
         "samples. Table 5.1 gives the composition by class and partition."))
    add(("caption", "Table 5.1: ",
         "Composition of the assembled dataset by attack class and partition.",
         "table_dataset"))
    add(("body",
         "Two features of the composition should be noted because they bear on the "
         "interpretation of every later result. The indirect class is much the smallest, "
         f"at {c['n_indirect']} samples, because BIPIA distributes a fixed and modest "
         "number of attack strings; conclusions about indirect detection therefore rest on "
         "a narrower evidential base than those about direct injection. The jailbreak "
         "class is likewise smaller than the direct class, which is a deliberate "
         "consequence of keeping the two distinct rather than merging them into a single "
         "malicious category."))
    add(("body",
         "The trigger-phrase audit required by Section 3.3 is reported in Table 5.2. Of "
         f"the {c['n_triggers']} phrases audited, {c['n_triggers_both']} occur in both the "
         "benign and the malicious classes, which is the intended outcome: a classifier "
         "cannot use them as a shortcut to the label. The audit is also the clearest "
         "statement of why the hard negatives matter. The phrase ‘show me’, for example, "
         f"appears in {c['trig_showme_benign']} benign samples as well as "
         f"{c['trig_showme_mal']} malicious ones, and the keyword baseline evaluated in "
         "Section 5.2.6 flags every one of them."))
    add(("caption", "Table 5.2: ",
         "Trigger-phrase frequency audit across the benign and malicious classes.",
         "table_triggers"))

    add(("heading3", "5.2.2", "Detection performance on the held-out test set"))
    add(("body",
         "Table 5.3 reports the five metrics specified in Table 3.2 for all five detectors "
         "and both baselines, each as a mean over three seeds with its standard deviation. "
         "Figure 5.1 presents the same comparison graphically, Figure 5.2 the confusion "
         "matrices, and Figure 5.3 the receiver operating characteristic curves."))
    add(("caption", "Table 5.3: ",
         "Detection performance on the held-out test set, as the mean of three seeds with "
         "standard deviation.", "table_main"))
    add(("figure", "fig_comparison", "Figure 5.1: "))
    add(("figure", "fig_confusion", "Figure 5.2: "))
    add(("figure", "fig_roc", "Figure 5.3: "))
    add(("body", c["para_main_results"]))
    add(("caption", "Table 5.4: ",
         "Confusion-matrix counts on the held-out test set, as the mean of three seeds.",
         "table_confusion"))
    add(("body", c["para_fpr"]))

    add(("heading3", "5.2.3", "Performance by attack class"))
    add(("body",
         "Because the corpus distinguishes direct injection, jailbreak and indirect "
         "injection, detection rate can be decomposed by class. Table 5.5 reports it, and "
         "the decomposition is more informative than the aggregate figures, since the "
         "three classes are not equally difficult."))
    add(("caption", "Table 5.5: ",
         "Detection rate by attack class on the held-out test set.", "table_per_class"))
    add(("body", c["para_per_class"]))

    add(("heading3", "5.2.4", "Robustness under adaptive evasion"))
    add(("body",
         f"The reserved adaptive-attack set contains {c['n_evasion']} variants derived "
         f"from the {c['n_test_attacks']} attacks in the held-out test partition by ten "
         "transformations. Nine are deterministic and seeded — leetspeak substitution, "
         "Cyrillic homoglyph substitution, zero-width character insertion, letter spacing, "
         "payload splitting, Base64 wrapping, role-play wrapping, translation framing and "
         "positional burial inside innocuous text — and the tenth is genuine paraphrase by "
         f"a large language model, applied to a stratified sample of {c['n_paraphrase']} "
         "attacks and cached so that the set is reproducible. Table 5.6 reports the "
         "degradation for each detector and Table 5.7 decomposes it by transformation; "
         "Figure 5.4 presents the decomposition graphically."))
    add(("caption", "Table 5.6: ",
         "Detection-rate degradation on the reserved adaptive-attack set.",
         "table_evasion"))
    add(("figure", "fig_evasion", "Figure 5.4: "))
    add(("body", c["para_evasion"]))
    add(("caption", "Table 5.7: ",
         "Detection rate by evasion transformation.", "table_evasion_by_transform"))
    add(("body", c["para_evasion_transforms"]))

    add(("heading3", "5.2.5", "Operational characteristics of the middleware"))
    add(("body", c["para_latency"]))
    add(("caption", "Table 5.8: ",
         "Measured screening latency and over-blocking rate of the middleware.",
         "table_latency"))
    add(("body", c["para_over_blocking"]))

    add(("heading3", "5.2.6", "The deployed guardrails and the over-defence problem"))
    add(("body",
         f"The vulnerable application was probed with {c['lab_n_attacks']} documented "
         f"attack payloads and {c['lab_n_benign']} legitimate prompts at each of the five "
         f"guardrail levels, producing {c['lab_n_turns']} logged turns against the live "
         "model. Table 5.9 reports the outcome and Figure 5.5 presents it graphically."))
    add(("caption", "Table 5.9: ",
         "Guardrail effectiveness and over-blocking in the vulnerable application.",
         "table_levels"))
    add(("figure", "fig_levels", "Figure 5.5: "))
    add(("body", c["para_lab_levels"]))
    add(("body", c["para_lab_resistance"]))

    # ---------------------------------------------------------------- 5.3
    add(("heading2", "5.3", "Evaluation of Objectives"))
    add(("body",
         "Each of the five objectives stated in Section 1.4 is assessed below against the "
         "evidence presented in this chapter, and Table 5.10 summarises the assessment."))
    add(("body", c["obj1"]))
    add(("body", c["obj2"]))
    add(("body", c["obj3"]))
    add(("body", c["obj4"]))
    add(("body", c["obj5"]))
    add(("caption", "Table 5.10: ", "Objective against outcome.", "table_objectives"))

    # ---------------------------------------------------------------- 5.4
    add(("heading2", "5.4", "Discussion of Results"))

    add(("heading3", "5.4.1", "What the results establish"))
    add(("body", c["para_discussion_worked"]))

    add(("heading3", "5.4.2", "What could not be measured, and the limits of the approach"))
    add(("body", c["para_discussion_limits"]))

    add(("heading3", "5.4.3", "Comparison with existing systems"))
    add(("body", c["para_discussion_comparison"]))

    add(("heading3", "5.4.4", "Relation to the gaps identified in Chapter Two"))
    add(("body", c["para_discussion_gaps"]))

    # ---------------------------------------------------------------- 5.5
    add(("heading2", "5.5", "Threats to Validity"))
    add(("body", c["para_construct_validity"]))
    add(("body", c["para_internal_validity"]))
    add(("body", c["para_external_validity"]))

    return B
