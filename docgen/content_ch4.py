"""Chapter Four: System Implementation.

Structure mirrors the AutoASM-NG format template; subject matter is this project's.
Blocks are (builder_name, args) tuples resolved by build_document.py.
"""
from __future__ import annotations


def build(c: dict) -> list:
    """c is the context dictionary of real, measured values."""
    B = []
    add = B.append

    add(("chapter_heading", "CHAPTER FOUR"))
    add(("chapter_subtitle", "SYSTEM IMPLEMENTATION"))

    add(("body",
         "This chapter describes how the design set out in Chapter Three was realised as "
         "working software. It covers the development environment, the structure of the "
         "code base, the construction of the labelled dataset, the detection models, the "
         "model-agnostic screening middleware and its integration with a deliberately "
         "vulnerable chatbot application, together with the security, performance and "
         "scalability considerations that shaped the implementation, the challenges "
         "encountered and the way the artefact is deployed and made available."))

    # ---------------------------------------------------------------- 4.1
    add(("heading2", "4.1", "Development Environment"))
    add(("body",
         f"The system was implemented in Python {c['python_version']}, chosen for the "
         "maturity of its machine-learning ecosystem and because Chapter Three specifies "
         "both scikit-learn and the Hugging Face Transformers library, each of which is "
         "distributed primarily for Python. Development and all experimental runs were "
         f"carried out on a single {c['machine']} workstation with {c['ram']} of unified "
         "memory running macOS. Transformer fine-tuning used the Metal Performance "
         "Shaders backend of PyTorch, which exposes the integrated graphics processor to "
         "the training loop; the classical models were trained on the central processor "
         "across all available cores."))
    add(("body",
         "Dependencies were isolated in a virtual environment so that the experimental "
         f"environment is reproducible from a single manifest. The principal versions "
         f"were scikit-learn {c['sklearn_version']}, PyTorch {c['torch_version']}, "
         f"Transformers {c['transformers_version']}, pandas {c['pandas_version']} and "
         f"Flask {c['flask_version']}. Playwright {c['playwright_version']} driving "
         "headless Chromium was used to exercise the chatbot interface and to capture the "
         "figures reproduced later in this chapter. The vulnerable chatbot that serves as "
         "the integration target is a FastAPI service; the detection middleware itself is "
         "a separate Flask service, as Chapter Three specifies. All code is held under "
         "version control, and every experiment is driven by a script rather than by "
         "interactive commands, so that results can be regenerated end to end."))
    add(("caption", "Table 4.1: ",
         "Development and experimental environment.", "table_env"))

    # ---------------------------------------------------------------- 4.2
    add(("heading2", "4.2", "Implementation Details"))

    add(("heading3", "4.2.1", "Code structure"))
    add(("body",
         "The code base is organised so that each stage of the methodology occupies its "
         "own module and can be executed and tested independently, as Table 4.2 sets out. "
         "Six packages carry the implementation. The <ml> package contains dataset "
         "construction, feature engineering, model training, the adaptive-evasion "
         "generator, the comparison baselines, the latency benchmark and the reporting "
         "script that renders every table and figure. The <middleware> package contains "
         "the Flask service, the detector back-ends and the decision policy. The "
         "<backend> and <frontend> packages are the vulnerable chatbot application that "
         "the middleware protects, and <lab_eval> holds the attack payloads and the "
         "harness that probes it at every guardrail level. The <capture> package drives "
         "the browser and produces the interface figures, and <docgen> generates the "
         "present chapters from the saved metrics, so that no reported figure is "
         "transcribed by hand."
         .replace("<", "‘").replace(">", "’")))
    add(("body",
         "Separating the decision policy from both the web layer and the detector was the "
         "single most consequential structural decision. Because the policy is a pure "
         "function of a score, a channel and a configuration object, it can be unit-tested "
         "exhaustively without loading a model or starting a server, and the middleware "
         "remains genuinely model-agnostic: any object exposing a scoring method over a "
         "list of strings can be substituted for the detector without touching the "
         "service. Three such back-ends are provided, and the service selects the "
         "strongest one available at start-up."))
    add(("caption", "Table 4.2: ", "Code structure of the implemented system.", "table_code"))

    add(("heading3", "4.2.2", "Dataset construction"))
    add(("body",
         "Dataset construction is implemented as a single reproducible script that "
         "retrieves every source over the network, normalises it into a common schema, "
         "applies the controls described in Chapter Three and writes both the corpus and "
         "an audit trail. Each record carries the binary label required for detection and "
         "a four-way class label distinguishing benign content, direct injection, "
         "jailbreak and indirect injection, because Chapter Two argues that prompt "
         "injection and jailbreaking are distinct phenomena that should not be merged. "
         "Each record also carries a channel label identifying whether it belongs to the "
         "user-prompt path or the retrieved-content path of the middleware."))
    add(("body",
         "Indirect-injection samples required composition rather than simple retrieval. "
         "The BIPIA benchmark distributes its attack strings separately from the "
         "retrieved contexts into which they are injected, so the script pairs each "
         "attack string with a genuine context — an email, a table or a code excerpt — and "
         "appends the attack, the position that Yi et al. (2025) report to be the most "
         "effective. The same contexts are also emitted unmodified as benign retrieved "
         "content. This is a deliberate control: because the injected and clean examples "
         "share the same containers, a detector cannot separate them on surface properties "
         "of the container and must attend to the injected instruction itself."))
    add(("body",
         "The four controls against spurious-feature learning specified in Chapter Three "
         "are implemented explicitly and each emits an artefact. Benign prompts are matched "
         "to the domain and register of the attacks by including an authored set of "
         f"{c['n_domain_benign']} Acme Learn help-desk prompts. The benign set includes "
         f"{c['n_hard_negatives']} hard negatives — legitimate requests that contain the "
         "very tokens a keyword filter keys on, such as a request to show the "
         "password-reset steps, to translate course instructions, or to enter an "
         "employer-issued access code. Trigger-phrase frequency is audited across the "
         "classes and written to a table. Exact duplicates are removed on a normalised "
         "form of the text, and near-duplicates are removed by character-shingle Jaccard "
         "similarity at a threshold of 0.9, bucketed by class and length band, which "
         "prevents leakage between partitions."))
    add(("body",
         "The partitions are stratified jointly by label, attack class and channel, fixed "
         "in advance with a recorded seed and written to disk, so that every model in "
         "Chapter Five is trained and evaluated on exactly the same data."))

    add(("heading3", "4.2.3", "Preprocessing and feature engineering"))
    add(("body",
         "Preprocessing is deliberately conservative. Text is normalised only to the "
         "extent of trimming surrounding whitespace and bounding length; casing and "
         "punctuation are preserved, because Chapter Three argues that aggressive "
         "normalisation discards precisely the evidence that distinguishes an injected "
         "instruction from ordinary prose. Capitalisation, delimiter characters and "
         "unusual character distributions are signals, not noise."))
    add(("body",
         "The classical models share a single feature representation assembled as a "
         "union of three components: term-frequency–inverse-document-frequency vectors "
         "over word unigrams and bigrams; the same over character n-grams of length three "
         "to five, computed within word boundaries so that obfuscated and misspelled "
         "variants still share sub-word evidence with their originals; and a small block "
         "of structural features. The structural block implements the four signals "
         "Chapter Three names — instruction-like imperatives, delimiter abuse, the "
         "proportion of characters that are not ordinary natural language, and prompt "
         "length — together with four simple derivatives: token count, the proportion of "
         "upper-case characters, the density of line breaks, and the proportion of tokens "
         "longer than twenty characters, which detects encoded payloads. Every extractor "
         "is fitted on the training partition alone and merely applied to validation and "
         "test data, so no information crosses the partition boundary. Transformer models "
         "bypass this representation entirely and use their own sub-word tokenisers, with "
         f"truncation and padding to a fixed length of {c['max_len']} tokens."))

    add(("heading3", "4.2.4", "Classical detectors"))
    add(("body",
         "Logistic Regression, Random Forest and a Support Vector Machine were "
         "implemented over the shared representation, each for the reason Chapter Three "
         "gives: an interpretable linear reference, a model that captures non-linear "
         "feature interactions, and a model that performs well in the high-dimensional "
         "sparse spaces that term-frequency representations produce. All three are "
         "trained under an identical protocol. Hyperparameters are selected by grid "
         "search under four-fold stratified cross-validation on the combined training and "
         "validation partitions, optimising F1; class weighting compensates for the "
         "imbalance between benign and malicious samples; and the whole procedure is "
         "repeated for three seeds so that results can be reported as a mean with a "
         "standard deviation. The Support Vector Machine is a linear model without a "
         "native probability output, so it is wrapped in a sigmoid calibration step, "
         "which allows the area under the receiver operating characteristic curve to be "
         "computed on the same basis as for the other models and gives the middleware a "
         "calibrated score to threshold."))

    add(("heading3", "4.2.5", "Transformer detectors"))
    add(("body",
         "BERT and DistilBERT were fine-tuned for binary classification with a "
         "classification head on top of the pooled representation. A plain PyTorch "
         "training loop was written in preference to the high-level trainer abstraction, "
         "so that the protocol is explicit and auditable and does not depend on the "
         "behaviour of a particular library release. Training uses the AdamW optimiser at "
         f"a learning rate of {c['lr']}, a batch size of {c['batch']}, a maximum of "
         f"{c['epochs']} epochs, and early stopping on validation loss with a patience of "
         "one epoch; the parameters of the best epoch are restored before evaluation. "
         "Seeds are fixed for both PyTorch and NumPy, and the same three seeds are used as "
         "for the classical models. DistilBERT was included specifically because the "
         "detector is invoked in front of every request, so inference cost is an "
         "operational constraint and not merely an efficiency preference."))

    add(("heading3", "4.2.6", "The screening middleware and the decision policy"))
    add(("body",
         "The middleware is a Flask service that mediates between the sources of input "
         "and the protected model. It exposes a screening endpoint that accepts a single "
         "item of content together with the channel it arrived on, a batch endpoint used "
         "by the evaluation harness, a configuration endpoint that adjusts thresholds at "
         "run time, and a health endpoint that reports which detector is loaded. Two "
         "channels are screened separately, as Chapter Three requires: the user channel "
         "carries the user's own prompt and is the route for direct injection and "
         "jailbreak attempts, while the retrieved channel carries content fetched from "
         "external sources and is the route for indirect injection. The separation matters "
         "because retrieved content carries no legitimate authority to issue instructions, "
         "so it can be screened more strictly at a lower cost to the user; the default "
         "configuration therefore applies lower thresholds on the retrieved channel."))
    add(("body",
         "The decision policy maps a detector score onto one of four responses. Content "
         "scoring at or above the block threshold is refused outright and never reaches "
         "the model, and the content itself is withheld from the response. Content above "
         "the escalation threshold is held for human review. Content above the sanitisation "
         "threshold has its injection scaffolding neutralised — instruction-override "
         "phrasings, role-assumption phrasings and pseudo-markup delimiters are stripped — "
         "and the remainder proceeds. Content below all three thresholds passes unchanged. "
         "One refinement was added during implementation: if sanitisation finds nothing to "
         "remove, the content is escalated rather than passed through, because a "
         "suspicious score with no removable marker indicates an attack the sanitiser does "
         "not recognise, and silently forwarding it would be the least safe of the "
         "available actions. Every decision, score, channel, detector and latency "
         "measurement is appended to a JSON Lines audit log, satisfying the logging "
         "requirement of Section 3.6."))
    add(("caption", "Table 4.3: ",
         "The decision policy and its default thresholds.", "table_policy"))

    add(("heading3", "4.2.7", "Integration with the vulnerable chatbot"))
    add(("body",
         "To evaluate the middleware in a realistic setting rather than in the abstract, "
         "it was integrated with a purpose-built vulnerable application: a help-centre web "
         "page with an embedded support assistant that guards a planted, fictitious secret "
         "in its system prompt. The application implements five stacked guardrail levels, "
         "summarised in Table 4.4, ranging from a weak system prompt alone to a "
         "configuration combining a hardened prompt, keyword input heuristics, an output "
         "filter, a second model acting as a judge, and input sanitisation. The "
         "application logs every turn, including whether the secret was produced by the "
         "model and whether it reached the user."))
    add(("body",
         "Integration is deliberately opt-in. The chatbot consults the middleware only "
         "when an environment variable naming its address is set, and the call fails open: "
         "if the middleware is unreachable or errors, the request proceeds to the "
         "application's own defences rather than the assistant becoming unavailable. When "
         "the middleware returns a block or escalate decision the turn is refused before "
         "the model is called, and the interface attributes the refusal to the "
         "machine-learning detector alongside the application's native defences. This "
         "arrangement allows the detector to be observed operating at guardrail level one, "
         "where none of the application's own defences are active, which isolates the "
         "middleware's contribution."))
    add(("body",
         "The two layers compose additively rather than exclusively, and testing the "
         "combination exposed a consequence worth recording. At guardrail level three, an "
         "attack is intercepted by the middleware and attributed to the machine-learning "
         "detector, because the middleware runs first; but a legitimate request that the "
         "middleware correctly allows is then passed to the application's own keyword "
         "heuristic, which refuses it. Adding an accurate detector in front of an "
         "over-defensive one therefore does nothing to reduce over-blocking: the "
         "false-positive rate of a layered defence is governed by its most aggressive "
         "layer, not its most accurate. Reducing it requires retiring the keyword "
         "heuristic rather than supplementing it, which is why the comparison in "
         "Chapter Five is drawn between the two defences rather than between the "
         "application with and without the middleware."))
    add(("caption", "Table 4.4: ",
         "Guardrail levels implemented in the vulnerable chatbot application.",
         "table_levels"))

    add(("figure", "fig_help_centre", "Figure 4.1: "))
    add(("figure", "fig_chat_widget", "Figure 4.2: "))
    add(("body",
         "Figure 4.3 shows a documented instruction-override payload issued at guardrail "
         "level one, and Figure 4.4 the same payload at level three, where the keyword "
         "input heuristic intercepts it before the model is reached and the interface "
         "names the defence that fired. Figure 4.5 shows that indicator in detail."))
    add(("figure", "fig_level1", "Figure 4.3: "))
    add(("figure", "fig_level3", "Figure 4.4: "))
    add(("figure", "fig_indicator", "Figure 4.5: "))
    add(("body",
         "Figure 4.6 records an outcome that bears directly on the first research gap. A "
         "wholly legitimate request to list the password-reset steps is refused at "
         "guardrail level three, because the phrase it contains matches the keyword "
         "heuristic. The over-defence that Chapter Two identifies in the literature is "
         "thus reproducible in the deployed artefact, and is quantified in Chapter Five."))
    add(("figure", "fig_over_defence", "Figure 4.6: "))
    add(("figure", "fig_middleware", "Figure 4.7: "))

    # ---------------------------------------------------------------- 4.3
    add(("heading2", "4.3", "Security, Performance and Scalability Considerations"))

    add(("heading3", "4.3.1", "Security and safe operation"))
    add(("body",
         "The vulnerable application is intentionally insecure and was treated "
         "accordingly. The secret it guards is a fictitious string with no value and no "
         "relationship to any real credential; it is configured through an environment "
         "file that is excluded from version control, as is the API key used to reach the "
         "model provider. Both the application and the middleware were bound to the "
         "loopback interface throughout and were never exposed to a network. No attack was "
         "directed at any third-party system: every adversarial prompt in this project was "
         "issued either against the researcher's own application or against a locally held "
         "corpus, and the published datasets used were retrieved under their own licences."))
    add(("body",
         "Two properties of the middleware are security-relevant in their own right. "
         "First, blocked content is withheld from the response rather than echoed back, so "
         "the service does not become a reflector for the payload it just refused. Second, "
         "the screening call fails open by design. This is a deliberate availability "
         "trade-off and it is stated plainly because it is also a limitation: an attacker "
         "able to make the middleware unreachable can remove the machine-learning layer, "
         "though the application's own guardrails remain in force. A deployment in which "
         "confidentiality outweighed availability should fail closed instead, and the "
         "behaviour is isolated in a single function so that this is a one-line change."))

    add(("heading3", "4.3.2", "Performance"))
    add(("body",
         "Because the detector is invoked in front of every request, its cost is added to "
         "every user interaction, and performance was therefore treated as a design "
         "constraint rather than an afterthought. Three measures keep the cost low. The "
         "feature extractors and the model are loaded once at start-up and held in memory, "
         "so no per-request initialisation occurs. A batch endpoint amortises fixed "
         "overheads across many items, which matters for retrieved content, where a single "
         "retrieval may return many documents. And the choice of detector is configurable, "
         "so an operator can trade accuracy against latency by selecting the classical "
         "model instead of the transformer. Measured latency is reported in Chapter Five."))

    add(("heading3", "4.3.3", "Scalability"))
    add(("body",
         "The middleware holds no state between requests: each screening decision depends "
         "only on the content, the channel and the current configuration. It can therefore "
         "be replicated horizontally behind a load balancer without coordination, and the "
         "audit log is append-only and can be shipped to a central collector. Because the "
         "service is decoupled from the protected application by an HTTP boundary rather "
         "than by a library import, it can screen for several applications written in "
         "different languages at once, which is the practical expression of the "
         "model-agnostic requirement in Chapter Three."))

    # ---------------------------------------------------------------- 4.4
    add(("heading2", "4.4", "Challenges Encountered"))
    add(("body",
         "Five substantive difficulties arose during implementation, each of which "
         "changed the design or the evaluation."))
    add(("body",
         "The first was access to the corpus named in Chapter Three. HackAPrompt is "
         "distributed under gated access on its hosting platform and requires an "
         "authenticated account with the dataset terms accepted, which was not available "
         "for this work. Rather than substitute silently, the direct-injection class was "
         "rebuilt from sources that are comparable in kind and openly available: the "
         "Gandalf corpus of genuine injection attempts submitted against a public "
         "challenge, the deepset prompt-injection set, and the injection portion of a "
         "large open safety-guard corpus. The substitution is recorded as a limitation in "
         "Chapter Six, and the loader is written so that HackAPrompt can be added by "
         "supplying an access token without any other change."))
    add(("body",
         "The second was the composition of indirect samples. BIPIA distributes attack "
         "strings and retrieved contexts as separate artefacts, and a naive pairing would "
         "have produced a corpus in which every injected example was long and structured "
         "and every benign example short and conversational — a spurious feature of exactly "
         "the kind Chapter Three warns against. Emitting the same contexts in both classes, "
         "with and without an appended attack, removed the shortcut at the cost of a "
         "smaller indirect class than the other two."))
    add(("body",
         "The third concerned the sanitisation action. An early implementation applied the "
         "sanitiser whenever the score fell in the middle band and forwarded whatever "
         "remained. Testing revealed that when the sanitiser matched nothing, this "
         "silently forwarded a suspicious prompt unaltered — the worst available outcome. "
         "The policy was amended to escalate in that case, and a unit test now fixes the "
         "behaviour."))
    add(("body",
         "The fourth was that the application under test proved far more resistant to "
         "attack than its design anticipated. The documented payloads that the application "
         "is specified to be vulnerable to did not succeed against any model available for "
         "this work, so the intended demonstration of a successful extraction could not be "
         "produced. This is reported as a finding in Chapter Five rather than concealed, "
         "and it is the reason the interface figures in this chapter show attempted rather "
         "than successful extraction."))
    add(("body",
         "The fifth was ensuring that the adaptive-evasion set could not contaminate the "
         "training data. Because evasion variants are derived from real attacks, deriving "
         "them from the wrong partition would have leaked test information into training. "
         "The generator therefore draws exclusively from the held-out test partition and "
         "is run before any model is fitted, so that no variant can correspond to anything "
         "a model saw in training."))

    # ---------------------------------------------------------------- 4.5
    add(("heading2", "4.5", "Deployment and Availability"))
    add(("body",
         "The system is deployed as three cooperating local services, reflecting the "
         "architecture rather than a hosting choice: the static help-centre front end, the "
         "FastAPI application that hosts the assistant and its guardrails, and the Flask "
         "screening middleware. Each is started by a single documented command, and the "
         "middleware is wired into the application by setting one environment variable, so "
         "the integrated and unintegrated configurations can be compared directly."))
    add(("body",
         "Deployment is deliberately local. The application is intentionally vulnerable "
         "and hosts a planted secret, and exposing it publicly would be irresponsible "
         "regardless of the fictitious nature of that secret; the project's ethical "
         "position, stated in Chapter Three, is that the artefact exists to study attacks "
         "against a system the researcher owns. The middleware itself carries no such "
         "restriction and is packaged as an ordinary stateless web service that could be "
         "deployed independently."))
    add(("body",
         "Every experimental result reported in Chapter Five is regenerated by running the "
         "pipeline scripts in the order below. The dataset builder retrieves its sources "
         "over the network and caches them, the evasion generator must be run before any "
         "model is trained, and the reporting script renders every table and figure from "
         "the saved metrics."))
    for cmd in c["commands"]:
        add(("code_line", cmd))
    add(("body",
         "The complete source, the experiment scripts, the generated metrics and the "
         "figures reproduced in this dissertation are held in the project repository "
         "described in Appendix A."))

    return B
