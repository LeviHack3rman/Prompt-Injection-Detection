"""Fine-tune BERT and DistilBERT for binary prompt-injection detection.

Chapter Three, Section 3.5: both models are fine-tuned with a classification head, using
the model's native sub-word tokeniser, truncation and padding to a fixed maximum sequence
length, early stopping on validation loss, and fixed random seeds. Training runs on Apple
Silicon via the MPS backend.

A deliberately plain PyTorch loop is used rather than the Trainer API, so the protocol is
explicit and auditable and does not depend on a particular Transformers release.

Usage:  python ml/train_transformers.py [--models distilbert bert] [--seeds 42 1337 2024]
"""
from __future__ import annotations

import argparse
import pathlib
import sys
import time

import numpy as np
import pandas as pd
import torch
from torch.utils.data import DataLoader, Dataset
from transformers import AutoModelForSequenceClassification, AutoTokenizer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from common import (MODELS, OUT, SEEDS, aggregate, load, metrics,  # noqa: E402
                    save_json, splits)

ROOT = pathlib.Path(__file__).resolve().parent.parent
EVASION = ROOT / "data" / "evasion_set.jsonl"

CHECKPOINTS = {
    "DistilBERT": "distilbert-base-uncased",
    "BERT": "bert-base-uncased",
}
MAX_LEN = 256
BATCH = 32
EPOCHS = 3
LR = 2e-5
PATIENCE = 1


def device() -> torch.device:
    if torch.backends.mps.is_available():
        return torch.device("mps")
    if torch.cuda.is_available():
        return torch.device("cuda")
    return torch.device("cpu")


class TextDS(Dataset):
    def __init__(self, texts, labels, tok):
        self.enc = tok(list(texts), truncation=True, padding="max_length",
                       max_length=MAX_LEN, return_tensors="pt")
        self.labels = torch.tensor(list(labels), dtype=torch.long)

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, i):
        item = {k: v[i] for k, v in self.enc.items()}
        item["labels"] = self.labels[i]
        return item


@torch.no_grad()
def predict(model, loader, dev):
    model.eval()
    probs = []
    for batch in loader:
        batch = {k: v.to(dev) for k, v in batch.items() if k != "labels"}
        logits = model(**batch).logits
        probs.append(torch.softmax(logits.float(), dim=-1)[:, 1].cpu().numpy())
    return np.concatenate(probs)


@torch.no_grad()
def val_loss(model, loader, dev):
    model.eval()
    tot, n = 0.0, 0
    for batch in loader:
        batch = {k: v.to(dev) for k, v in batch.items()}
        out = model(**batch)
        tot += float(out.loss) * len(batch["labels"])
        n += len(batch["labels"])
    return tot / max(n, 1)


def train_one(name: str, ckpt: str, seed: int, train, val, test, evasion, dev):
    torch.manual_seed(seed)
    np.random.seed(seed)

    tok = AutoTokenizer.from_pretrained(ckpt)
    model = AutoModelForSequenceClassification.from_pretrained(ckpt, num_labels=2).to(dev)

    dl_tr = DataLoader(TextDS(train.text, train.label, tok), batch_size=BATCH, shuffle=True)
    dl_va = DataLoader(TextDS(val.text, val.label, tok), batch_size=BATCH)
    dl_te = DataLoader(TextDS(test.text, test.label, tok), batch_size=BATCH)

    opt = torch.optim.AdamW(model.parameters(), lr=LR)
    best, bad, best_state = float("inf"), 0, None
    t0 = time.perf_counter()

    for ep in range(EPOCHS):
        model.train()
        for i, batch in enumerate(dl_tr):
            batch = {k: v.to(dev) for k, v in batch.items()}
            loss = model(**batch).loss
            loss.backward()
            opt.step()
            opt.zero_grad()
            if i % 100 == 0:
                print(f"      ep{ep} step{i}/{len(dl_tr)} loss={float(loss):.4f}", flush=True)
        vl = val_loss(model, dl_va, dev)
        print(f"    {name} seed={seed} epoch {ep}: val_loss={vl:.4f}", flush=True)
        if vl < best - 1e-4:
            best, bad = vl, 0
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        else:
            bad += 1
            if bad > PATIENCE:
                print(f"    early stopping at epoch {ep}", flush=True)
                break
    if best_state is not None:
        model.load_state_dict(best_state)
    fit_s = time.perf_counter() - t0

    sc = predict(model, dl_te, dev)
    m = metrics(test.label, (sc >= 0.5).astype(int), sc)
    m["fit_seconds"] = round(fit_s, 1)
    m["best_val_loss"] = best

    per_class = {}
    pred = (sc >= 0.5).astype(int)
    for cls in ("direct_injection", "jailbreak", "indirect_injection"):
        mask = (test.attack_class == cls).values
        if mask.sum():
            per_class[cls] = float((pred[mask] == 1).mean())

    ev = None
    if evasion is not None and len(evasion):
        dl_ev = DataLoader(TextDS(evasion.text, evasion.label, tok), batch_size=BATCH)
        ev_sc = predict(model, dl_ev, dev)
        ev_pred = (ev_sc >= 0.5).astype(int)
        ev = {"detection_rate": float(ev_pred.mean())}
        for tf, g in evasion.groupby("transform"):
            idx = evasion.index.get_indexer(g.index)
            ev[f"dr_{tf}"] = float(ev_pred[idx].mean())

    return model, tok, m, per_class, ev


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="*", default=list(CHECKPOINTS))
    ap.add_argument("--seeds", nargs="*", type=int, default=SEEDS)
    args = ap.parse_args()

    dev = device()
    print(f"device: {dev}")
    train, val, test = splits(load())
    evasion = pd.read_json(EVASION, lines=True).reset_index(drop=True) if EVASION.exists() else None
    print(f"train={len(train)} val={len(val)} test={len(test)} "
          f"evasion={0 if evasion is None else len(evasion)}")

    outfile = OUT / "metrics_transformers.json"
    results = {}
    if outfile.exists():
        import json
        results = json.loads(outfile.read_text())

    for name in args.models:
        ckpt = CHECKPOINTS[name]
        runs, evs, pcs = [], [], []
        for seed in args.seeds:
            print(f"\n=== {name} ({ckpt}) seed={seed}", flush=True)
            model, tok, m, pc, ev = train_one(name, ckpt, seed, train, val, test, evasion, dev)
            runs.append(m)
            pcs.append(pc)
            if ev:
                evs.append(ev)
            print(f"  -> F1={m['f1']:.4f} FPR={m['fpr']:.4f} AUC={m.get('roc_auc', 0):.4f} "
                  f"({m['fit_seconds']}s)", flush=True)
            if seed == args.seeds[0]:
                d = MODELS / name.lower()
                model.save_pretrained(d)
                tok.save_pretrained(d)

        results[name] = {
            "checkpoint": ckpt,
            "test": aggregate(runs),
            "test_per_seed": runs,
            "per_class_recall": {k: float(np.mean([d.get(k, np.nan) for d in pcs]))
                                 for k in pcs[0]},
            "seeds": args.seeds,
            "hyperparameters": {"max_len": MAX_LEN, "batch_size": BATCH, "lr": LR,
                                "max_epochs": EPOCHS, "early_stopping_patience": PATIENCE,
                                "device": str(dev)},
        }
        if evs:
            results[name]["evasion"] = aggregate(evs)
        save_json(results, outfile)

    print(f"\nWrote {outfile}")


if __name__ == "__main__":
    main()
