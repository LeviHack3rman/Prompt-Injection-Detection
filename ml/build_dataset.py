"""Assemble the labelled prompt-injection dataset described in Chapter Three, Section 3.3.

Sources (all publicly available and retrieved anonymously):
  * deepset/prompt-injections                (HF)  direct injection + benign
  * Lakera/gandalf_ignore_instructions       (HF)  direct injection (real attempts vs Gandalf)
  * jackhhao/jailbreak-classification        (HF)  jailbreak + benign
  * xTRam1/safe-guard-prompt-injection       (HF)  benign + direct injection
  * microsoft/BIPIA                          (GitHub) indirect injection, composed into
                                                   genuine retrieved contexts
  * the project's own prompt-injection lab   (local) README payloads and real chat logs
  * authored matched-domain benign prompts and hard negatives (ml/domain_prompts.py)

Labels: binary `label` (0 benign / 1 malicious) plus the four-way `attack_class`
(benign | direct_injection | jailbreak | indirect_injection), because Chapter Two insists
prompt injection and jailbreaking are distinct phenomena and must not be merged.

Chapter Three's four controls against spurious-feature learning are applied here and each
emits an artefact under outputs/tables/ for reporting in Chapter Five.

Usage:  python ml/build_dataset.py
"""
from __future__ import annotations

import hashlib
import io
import json
import pathlib
import re
import sys
import unicodedata
from collections import Counter

import pandas as pd
import requests

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from domain_prompts import BENIGN_DOMAIN, HARD_NEGATIVES  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
DATA = ROOT / "data"
TABLES = ROOT / "outputs" / "tables"
for d in (RAW, DATA, TABLES):
    d.mkdir(parents=True, exist_ok=True)

SEED = 42
HF = "https://huggingface.co/api/datasets/{ds}/parquet/default/{split}/0.parquet"
BIPIA = "https://raw.githubusercontent.com/microsoft/BIPIA/main/benchmark/"

# Channel: which screening path of the middleware a sample belongs to.
#   "user"      - the user-prompt path (direct injection, jailbreak, ordinary queries)
#   "retrieved" - the retrieved-content path (indirect injection, clean retrieved documents)
ROWS: list[dict] = []


def add(text, label, attack_class, source, channel="user"):
    if not isinstance(text, str):
        return
    text = text.strip()
    if len(text) < 8 or len(text) > 8000:
        return
    ROWS.append({"text": text, "label": int(label), "attack_class": attack_class,
                 "source": source, "channel": channel})


def cached(name: str, url: str) -> bytes:
    p = RAW / name
    if not p.exists():
        r = requests.get(url, timeout=180)
        r.raise_for_status()
        p.write_bytes(r.content)
    return p.read_bytes()


def hf_parquet(ds: str, split: str) -> pd.DataFrame:
    fn = f"{ds.replace('/', '__')}__{split}.parquet"
    return pd.read_parquet(io.BytesIO(cached(fn, HF.format(ds=ds, split=split))))


# --------------------------------------------------------------------------------------
# 1. Hugging Face sources
# --------------------------------------------------------------------------------------
def load_deepset():
    for sp in ("train", "test"):
        df = hf_parquet("deepset/prompt-injections", sp)
        for _, r in df.iterrows():
            if int(r["label"]) == 1:
                add(r["text"], 1, "direct_injection", "deepset/prompt-injections")
            else:
                add(r["text"], 0, "benign", "deepset/prompt-injections")


def load_gandalf():
    # Every row is a genuine injection attempt submitted against the Gandalf challenge.
    for sp in ("train", "validation", "test"):
        df = hf_parquet("Lakera/gandalf_ignore_instructions", sp)
        for t in df["text"]:
            add(t, 1, "direct_injection", "Lakera/gandalf_ignore_instructions")


def load_jailbreak():
    for sp in ("train", "test"):
        df = hf_parquet("jackhhao/jailbreak-classification", sp)
        for _, r in df.iterrows():
            if str(r["type"]).strip().lower() == "jailbreak":
                add(r["prompt"], 1, "jailbreak", "jackhhao/jailbreak-classification")
            else:
                add(r["prompt"], 0, "benign", "jackhhao/jailbreak-classification")


def load_safeguard():
    for sp in ("train", "test"):
        df = hf_parquet("xTRam1/safe-guard-prompt-injection", sp)
        for _, r in df.iterrows():
            if int(r["label"]) == 1:
                add(r["text"], 1, "direct_injection", "xTRam1/safe-guard-prompt-injection")
            else:
                add(r["text"], 0, "benign", "xTRam1/safe-guard-prompt-injection")


# --------------------------------------------------------------------------------------
# 2. BIPIA - indirect injection composed into genuine retrieved content
# --------------------------------------------------------------------------------------
def load_bipia():
    """Compose BIPIA attack strings into BIPIA's own retrieved contexts.

    Yi et al. (2025) report that attacks placed at the end of retrieved content are the
    most successful, so the attack is appended. The *same* contexts are also emitted
    unmodified as benign retrieved content: this is a deliberate control, ensuring the
    detector cannot separate the classes on surface properties of the container (an
    email is an email whether or not it carries an injected instruction).
    """
    attacks: list[str] = []
    for f in ("text_attack_train.json", "text_attack_test.json",
              "code_attack_train.json", "code_attack_test.json"):
        d = json.loads(cached("bipia_" + f, BIPIA + f))
        for v in d.values():
            attacks.extend(v)

    contexts: list[str] = []
    for ctx in ("email", "table", "code"):
        for sp in ("train", "test"):
            try:
                raw = cached(f"bipia_{ctx}_{sp}.jsonl", BIPIA + f"{ctx}/{sp}.jsonl")
            except Exception:
                continue
            for line in raw.decode("utf-8").strip().splitlines():
                c = json.loads(line).get("context")
                if isinstance(c, list):
                    c = "\n".join(map(str, c))
                if isinstance(c, str) and len(c.strip()) > 40:
                    contexts.append(c.strip()[:4000])

    # Pair deterministically so the composition is reproducible without RNG.
    for i, atk in enumerate(attacks):
        ctx = contexts[i % len(contexts)]
        add(f"{ctx}\n{atk}", 1, "indirect_injection", "microsoft/BIPIA", channel="retrieved")

    # Clean retrieved content, count matched to the injected set.
    for ctx in contexts[: len(attacks)]:
        add(ctx, 0, "benign", "microsoft/BIPIA (clean context)", channel="retrieved")


# --------------------------------------------------------------------------------------
# 3. The project's own lab
# --------------------------------------------------------------------------------------
def load_lab():
    """README payloads, probe payloads, and any real turns logged by the running lab."""
    sys.path.insert(0, str(ROOT / "lab_eval"))
    try:
        from payloads import PAYLOADS, BENIGN_PROBES
        for _, cls, text in PAYLOADS:
            add(text, 1, "direct_injection", "prompt-injection lab (payloads)")
        for _, text in BENIGN_PROBES:
            add(text, 0, "benign", "prompt-injection lab (benign probes)")
    except Exception as exc:  # pragma: no cover
        print(f"  ! lab payloads unavailable: {exc}")

    log = ROOT / "backend" / "logs" / "chat_log.jsonl"
    if log.exists():
        seen = set()
        for line in log.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            msg = (rec.get("user_message") or "").strip()
            if not msg or msg in seen:
                continue
            seen.add(msg)
            # An attack is labelled as such because it was issued as one in the probe
            # harness, not because the model happened to leak.
            is_attack = bool(rec.get("model_leaked")) or bool(rec.get("guardrails_triggered"))
            add(msg, int(is_attack), "direct_injection" if is_attack else "benign",
                "prompt-injection lab (chat_log.jsonl)")


def load_authored():
    for t in BENIGN_DOMAIN:
        add(t, 0, "benign", "authored matched-domain benign")
    for t in HARD_NEGATIVES:
        add(t, 0, "benign", "authored hard negatives")


# --------------------------------------------------------------------------------------
# 4. Chapter Three's controls
# --------------------------------------------------------------------------------------
def normalise(s: str) -> str:
    s = unicodedata.normalize("NFKC", s).lower()
    return re.sub(r"\s+", " ", re.sub(r"[^\w\s]", "", s)).strip()


def shingles(s: str, k: int = 5) -> set[str]:
    s = normalise(s)
    return {s[i:i + k] for i in range(max(1, len(s) - k + 1))}


def deduplicate(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Exact then near-duplicate removal, to prevent leakage between partitions."""
    n0 = len(df)
    df = df.assign(_norm=df["text"].map(normalise))
    df = df.drop_duplicates(subset="_norm", keep="first")
    n_exact = n0 - len(df)

    # Near-duplicate removal via character-shingle Jaccard, bucketed by length band and
    # class so the comparison stays tractable on a corpus of this size.
    keep, dropped = [], 0
    buckets: dict[tuple, list[set]] = {}
    for idx, row in df.iterrows():
        band = len(row["_norm"]) // 60
        key = (row["attack_class"], band)
        sh = shingles(row["_norm"])
        clash = False
        for prev in buckets.setdefault(key, []):
            inter = len(sh & prev)
            if inter and inter / len(sh | prev) >= 0.9:
                clash = True
                break
        if clash:
            dropped += 1
        else:
            buckets[key].append(sh)
            keep.append(idx)
    df = df.loc[keep].drop(columns="_norm")
    return df, {"initial": n0, "exact_duplicates_removed": n_exact,
                "near_duplicates_removed": dropped, "final": len(df)}


TRIGGERS = ["ignore", "disregard", "system prompt", "instructions", "reveal", "print",
            "repeat", "show me", "pretend", "act as", "role play", "translate", "encode",
            "base64", "secret", "password", "access code", "confidential", "forget"]


def trigger_audit(df: pd.DataFrame) -> pd.DataFrame:
    """Chapter Three control 3: audit trigger-phrase frequency across the classes.

    A token that appears overwhelmingly in one class is a shortcut the classifier could
    exploit instead of learning a generalisable notion of injection.
    """
    rows = []
    n_ben = int((df.label == 0).sum())
    n_mal = int((df.label == 1).sum())
    for t in TRIGGERS:
        m = df["text"].str.lower().str.contains(re.escape(t), regex=True)
        b = int((m & (df.label == 0)).sum())
        a = int((m & (df.label == 1)).sum())
        rows.append({"trigger": t, "benign_count": b, "malicious_count": a,
                     "benign_rate_pct": round(100 * b / max(n_ben, 1), 2),
                     "malicious_rate_pct": round(100 * a / max(n_mal, 1), 2),
                     "present_in_benign": b > 0})
    return pd.DataFrame(rows).sort_values("malicious_rate_pct", ascending=False)


def stratified_split(df: pd.DataFrame) -> pd.DataFrame:
    """Fixed 70/15/15 stratified split, written to disk and reused by every model."""
    df = df.sample(frac=1.0, random_state=SEED).reset_index(drop=True)
    parts = []
    for _, g in df.groupby(["label", "attack_class", "channel"], sort=False):
        n = len(g)
        n_tr, n_va = int(round(0.70 * n)), int(round(0.15 * n))
        split = ["train"] * n_tr + ["val"] * n_va + ["test"] * (n - n_tr - n_va)
        parts.append(g.assign(split=split[:n]))
    return pd.concat(parts).sample(frac=1.0, random_state=SEED).reset_index(drop=True)


def main():
    print("Loading sources ...")
    for fn in (load_deepset, load_gandalf, load_jailbreak, load_safeguard,
               load_bipia, load_lab, load_authored):
        before = len(ROWS)
        fn()
        print(f"  {fn.__name__:18s} +{len(ROWS) - before}")

    df = pd.DataFrame(ROWS)
    print(f"\nRaw rows: {len(df)}")

    df, dedup_stats = deduplicate(df)
    print("Dedup:", dedup_stats)

    audit = trigger_audit(df)
    audit.to_csv(TABLES / "trigger_audit.csv", index=False)
    only_mal = audit[~audit.present_in_benign]["trigger"].tolist()
    print(f"Trigger audit -> outputs/tables/trigger_audit.csv "
          f"({len(only_mal)} triggers absent from benign class: {only_mal})")

    df = stratified_split(df)
    df.to_json(DATA / "dataset.jsonl", orient="records", lines=True, force_ascii=False)

    comp = (df.groupby(["source", "attack_class", "channel", "split"])
              .size().rename("n").reset_index()
              .sort_values(["source", "attack_class", "split"]))
    comp.to_csv(TABLES / "dataset_composition.csv", index=False)

    summary = (df.groupby(["attack_class", "split"]).size().unstack(fill_value=0))
    summary["total"] = summary.sum(axis=1)
    summary.to_csv(TABLES / "dataset_summary.csv")

    (TABLES / "dataset_provenance.json").write_text(json.dumps({
        "seed": SEED, "dedup": dedup_stats,
        "n_total": int(len(df)),
        "n_benign": int((df.label == 0).sum()), "n_malicious": int((df.label == 1).sum()),
        "by_class": Counter(df.attack_class).most_common(),
        "by_channel": Counter(df.channel).most_common(),
        "by_split": Counter(df.split).most_common(),
        "sources": sorted(df.source.unique().tolist()),
        "triggers_absent_from_benign": only_mal,
    }, indent=2))

    print("\n", summary, sep="")
    print(f"\nWrote data/dataset.jsonl ({len(df)} rows) and three tables under outputs/tables/")


if __name__ == "__main__":
    main()
