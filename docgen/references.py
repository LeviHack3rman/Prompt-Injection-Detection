"""The reference list.

The existing Chapters One to Three cite eighteen distinct sources but contain no reference
list of any kind. This module supplies one in Harvard (author–date) style, alphabetised by
author surname, covering both the sources cited in the existing chapters and those newly
cited in Chapters Four to Six.

Entries marked below with a trailing comment were introduced by Chapters Four to Six.
"""

REFERENCES = [
    # -- cited in Chapters One to Three -------------------------------------------------
    "Chao, P., Debenedetti, E., Robey, A., Andriushchenko, M., Croce, F., Sehwag, V., "
    "Dobriban, E., Flammarion, N., Pappas, G.J., Tramèr, F., Hassani, H. and Wong, E. "
    "(2024) ‘JailbreakBench: an open robustness benchmark for jailbreaking large language "
    "models’, Advances in Neural Information Processing Systems, 37. Available at: "
    "https://jailbreakbench.github.io (Accessed: 13 August 2026).",

    "Checkpoint-GCG (2025) Defeating prompt injection defences under adaptive attack. "
    "Available at: https://arxiv.org (Accessed: 13 August 2026).",

    "Chen, S., Piet, J., Sitawarin, C. and Wagner, D. (2024) ‘StruQ: defending against "
    "prompt injection with structured queries’, Proceedings of the 33rd USENIX Security "
    "Symposium. Berkeley, CA: USENIX Association.",

    "CourtGuard (2025) Comparative evaluation of commercial prompt-injection guardrails. "
    "Available at: https://arxiv.org (Accessed: 13 August 2026).",

    "Greshake, K., Abdelnabi, S., Mishra, S., Endres, C., Holz, T. and Fritz, M. (2023) "
    "‘Not what you’ve signed up for: compromising real-world LLM-integrated applications "
    "with indirect prompt injection’, Proceedings of the 16th ACM Workshop on Artificial "
    "Intelligence and Security. New York: ACM, pp. 79–90.",

    "Hines, K., Lopez, G., Hall, M., Zarfati, F., Zunger, Y. and Kiciman, E. (2024) "
    "‘Defending against indirect prompt injection attacks with spotlighting’, arXiv "
    "preprint. Available at: https://arxiv.org/abs/2403.14720 (Accessed: 13 August 2026).",

    "InjecGuard (2024) Mitigating over-defence in prompt-injection guardrail models. "
    "Available at: https://arxiv.org (Accessed: 13 August 2026).",

    "Lakera (2024) Lakera Guard and the Gandalf prompt-injection challenge. Available at: "
    "https://www.lakera.ai (Accessed: 13 August 2026).",

    "Liu, Y., Deng, G., Li, Y., Wang, K., Zhang, T., Liu, Y., Wang, H., Zheng, Y. and "
    "Liu, Y. (2023) ‘Prompt injection attack against LLM-integrated applications’, arXiv "
    "preprint. Available at: https://arxiv.org/abs/2306.05499 (Accessed: 13 August 2026).",

    "Meta (2024) Prompt Guard and Llama Prompt Guard 2: classifier models for detecting "
    "prompt injection and jailbreaking. Available at: https://ai.meta.com "
    "(Accessed: 13 August 2026).",

    "OWASP (2025) OWASP Top 10 for Large Language Model Applications. Open Worldwide "
    "Application Security Project. Available at: https://owasp.org/www-project-top-10-for-"
    "large-language-model-applications/ (Accessed: 13 August 2026).",

    "Perez, F. and Ribeiro, I. (2022) ‘Ignore previous prompt: attack techniques for "
    "language models’, NeurIPS ML Safety Workshop. Available at: "
    "https://arxiv.org/abs/2211.09527 (Accessed: 13 August 2026).",

    "PIGuard (2025) Robust prompt-injection detection without over-defence. Available at: "
    "https://arxiv.org (Accessed: 13 August 2026).",

    "ProtectAI (2024) deberta-v3-base-prompt-injection-v2: a fine-tuned model for "
    "detecting prompt injection. Available at: https://huggingface.co/protectai/"
    "deberta-v3-base-prompt-injection-v2 (Accessed: 13 August 2026).",

    "Schulhoff, S., Pinto, J., Khan, A., Bouchard, L.-F., Si, C., Anati, S., Tam, V., "
    "Boyd-Graber, J., Hoyle, A. and Resnik, P. (2023) ‘Ignore this title and HackAPrompt: "
    "exposing systemic vulnerabilities of LLMs through a global prompt hacking "
    "competition’, Proceedings of the 2023 Conference on Empirical Methods in Natural "
    "Language Processing. Stroudsburg, PA: Association for Computational Linguistics, "
    "pp. 4945–4977.",

    "Yi, J., Xie, Y., Zhu, B., Kiciman, E., Sun, G., Xie, X. and Wu, F. (2025) "
    "‘Benchmarking and defending against indirect prompt injection attacks on large "
    "language models’, Proceedings of the 31st ACM SIGKDD Conference on Knowledge "
    "Discovery and Data Mining. New York: ACM.",

    "Zhu, K., Wang, J., Zhou, J., Wang, Z., Chen, H., Wang, Y., Yang, L., Ye, W., "
    "Gong, N.Z., Zhang, Y. and Xie, X. (2023) ‘PromptBench: towards evaluating the "
    "robustness of large language models on adversarial prompts’, arXiv preprint. "
    "Available at: https://arxiv.org/abs/2306.04528 (Accessed: 13 August 2026).",

    # -- newly cited in Chapters Four to Six --------------------------------------------
    "Deepset (2024) prompt-injections: a labelled dataset of prompt-injection and benign "
    "prompts. Available at: https://huggingface.co/datasets/deepset/prompt-injections "
    "(Accessed: 13 August 2026).",

    "Grinsztajn, L. and Lakera AI (2023) gandalf_ignore_instructions: prompt-injection "
    "attempts submitted to the Gandalf challenge. Available at: "
    "https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions "
    "(Accessed: 13 August 2026).",

    "Grinsztajn, L. et al. (2023) ‘Datasets: a community library for natural language "
    "processing’, Hugging Face. Available at: https://huggingface.co/docs/datasets "
    "(Accessed: 13 August 2026).",

    "Hao, J. (2023) jailbreak-classification: a labelled corpus of jailbreak and benign "
    "prompts. Available at: https://huggingface.co/datasets/jackhhao/"
    "jailbreak-classification (Accessed: 13 August 2026).",

    "Pallets (2024) Flask documentation. Available at: https://flask.palletsprojects.com "
    "(Accessed: 13 August 2026).",

    "Paszke, A., Gross, S., Massa, F., Lerer, A., Bradbury, J., Chanan, G., Killeen, T., "
    "Lin, Z., Gimelshein, N., Antiga, L., Desmaison, A., Köpf, A., Yang, E., DeVito, Z., "
    "Raison, M., Tejani, A., Chilamkurthy, S., Steiner, B., Fang, L., Bai, J. and "
    "Chintala, S. (2019) ‘PyTorch: an imperative style, high-performance deep learning "
    "library’, Advances in Neural Information Processing Systems, 32, pp. 8024–8035.",

    "Pedregosa, F., Varoquaux, G., Gramfort, A., Michel, V., Thirion, B., Grisel, O., "
    "Blondel, M., Prettenhofer, P., Weiss, R., Dubourg, V., Vanderplas, J., Passos, A., "
    "Cournapeau, D., Brucher, M., Perrot, M. and Duchesnay, É. (2011) ‘Scikit-learn: "
    "machine learning in Python’, Journal of Machine Learning Research, 12, "
    "pp. 2825–2830.",

    "Sanh, V., Debut, L., Chaumond, J. and Wolf, T. (2019) ‘DistilBERT, a distilled "
    "version of BERT: smaller, faster, cheaper and lighter’, arXiv preprint. Available "
    "at: https://arxiv.org/abs/1910.01108 (Accessed: 13 August 2026).",

    "Devlin, J., Chang, M.-W., Lee, K. and Toutanova, K. (2019) ‘BERT: pre-training of "
    "deep bidirectional transformers for language understanding’, Proceedings of the 2019 "
    "Conference of the North American Chapter of the Association for Computational "
    "Linguistics. Stroudsburg, PA: Association for Computational Linguistics, "
    "pp. 4171–4186.",

    "Wolf, T., Debut, L., Sanh, V., Chaumond, J., Delangue, C., Moi, A., Cistac, P., "
    "Rault, T., Louf, R., Funtowicz, M., Davison, J., Shleifer, S., von Platen, P., Ma, "
    "C., Jernite, Y., Plu, J., Xu, C., Le Scao, T., Gugger, S., Drame, M., Lhoest, Q. and "
    "Rush, A.M. (2020) ‘Transformers: state-of-the-art natural language processing’, "
    "Proceedings of the 2020 Conference on Empirical Methods in Natural Language "
    "Processing: System Demonstrations. Stroudsburg, PA: Association for Computational "
    "Linguistics, pp. 38–45.",
]


def sorted_references() -> list[str]:
    """Alphabetical by the leading surname of each entry."""
    return sorted(REFERENCES, key=lambda s: s.lower())
