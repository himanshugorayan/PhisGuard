"""Stage-2 analysis on D3: how much do DNS, WHOIS, VirusTotal and the brand check add to the lexical model?

Protocol: time-ordered split (train on the earliest collection days, test on the latest), test domains that
also occur in train are dropped, fixed hyper-parameters (no tuning on test), bootstrap confidence intervals.
Run:  python train_stage2.py            (add --url-mode full to keep the phishing URL paths)
"""
import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve

HERE = Path(__file__).resolve().parent
BACKEND = HERE.parent / "backend"
sys.path.insert(0, str(BACKEND))
from app import config  # noqa: E402
from app.features import FEATURE_COLS, extract_features  # noqa: E402
from app.policy import decide  # noqa: E402

RESULTS = HERE / "results"
GROUPS = {
    "DNS": ["dns_resolves", "dns_nx", "dns_n_a", "dns_n_aaaa", "dns_mx", "dns_ns", "dns_err"],
    "WHOIS": ["who_age_days", "who_missing", "who_notreg"],
    "VirusTotal": ["vt_found", "vt_mal", "vt_susp", "vt_harm", "vt_undet"],
    "Brand": ["brand_flag", "brand_lookalike"],
}
ALL = [c for g in GROUPS.values() for c in g]


def load(db):
    df = pd.read_sql_query("SELECT * FROM urls WHERE net_done=1", sqlite3.connect(db))
    df["first_seen"] = pd.to_datetime(df["first_seen_utc"])
    return df.sort_values("first_seen").reset_index(drop=True)


def model_url(row, mode):
    if mode == "full":
        return row.url
    h = row.host[4:] if row.host.startswith("www.") else row.host   # strip www: no formatting shortcut
    return f"https://{h}/"


def build(df, url_mode):
    stage1 = joblib.load(BACKEND / "models" / "phisguard_model.joblib")
    urls = [model_url(r, url_mode) for r in df.itertuples()]
    X = pd.DataFrame([extract_features(u) for u in urls], columns=FEATURE_COLS)
    p = stage1.predict_proba(X)[:, 1]
    rows, sig = [], []
    for r, pi in zip(df.itertuples(), p):
        d = json.loads(r.dns_json) if r.dns_json else {}
        w = json.loads(r.whois_json) if r.whois_json else {}
        v = json.loads(r.vt_json) if r.vt_json else None
        b = json.loads(r.brand_json) if r.brand_json else None
        rows.append({
            "lex_logit": float(np.log(np.clip(pi, 1e-6, 1 - 1e-6) / (1 - np.clip(pi, 1e-6, 1 - 1e-6)))),
            "dns_resolves": int(bool(d.get("resolves"))), "dns_nx": int(bool(d.get("nxdomain"))),
            "dns_n_a": len(d.get("a", [])), "dns_n_aaaa": len(d.get("aaaa", [])),
            "dns_mx": d.get("mx_count", 0), "dns_ns": d.get("ns_count", 0), "dns_err": int(bool(d.get("error"))),
            "who_age_days": w.get("age_days") if w.get("age_days") is not None else np.nan,
            "who_missing": int(w.get("age_days") is None), "who_notreg": int(bool(w.get("not_registered"))),
            "vt_found": (int(v["found"]) if v else np.nan), "vt_mal": (v["malicious"] if v else np.nan),
            "vt_susp": (v["suspicious"] if v else np.nan), "vt_harm": (v["harmless"] if v else np.nan),
            "vt_undet": (v["undetected"] if v else np.nan),
            "brand_flag": int(b is not None), "brand_lookalike": int(bool(b and b["kind"] == "lookalike")),
        })
        sig.append((float(pi), d or None, w or None, v, b))
    return pd.DataFrame(rows), p, sig


def tpr_at_fpr(y, s, fpr=0.01):
    f, t, _ = roc_curve(y, s)
    return float(t[f <= fpr].max()) if (f <= fpr).any() else 0.0


def boot(y, s, fn, n, seed=0):
    rng, vals = np.random.default_rng(seed), []
    for _ in range(n):
        i = rng.integers(0, len(y), len(y))
        if len(set(y[i])) == 2:
            vals.append(fn(y[i], s[i]))
    return (float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))) if vals else (np.nan, np.nan)


def make_model():
    return HistGradientBoostingClassifier(max_iter=200, learning_rate=0.05, max_leaf_nodes=15,
                                          l2_regularization=1.0, random_state=42)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=os.getenv("PHISGUARD_DB", str(HERE / "data" / "d3.sqlite")))
    ap.add_argument("--url-mode", choices=["host", "full"], default="host")
    ap.add_argument("--train-frac", type=float, default=0.7)
    ap.add_argument("--boot", type=int, default=300)
    args = ap.parse_args()
    RESULTS.mkdir(exist_ok=True)

    df = load(args.db)
    if len(df) < 200:
        sys.exit(f"only {len(df)} enriched rows - collect more first (python collect.py status)")
    F, p_lex, sig = build(df, args.url_mode)
    y = df["label"].to_numpy()

    print("\n== Class summary (share of rows) ==")
    summ = pd.DataFrame({"label": y, "dns_resolves": F.dns_resolves, "whois_missing": F.who_missing,
                         "mean_age_days": F.who_age_days, "vt_found": F.vt_found,
                         "vt_mal>=1": (F.vt_mal >= 1).astype(float).where(F.vt_mal.notna())})
    print(summ.groupby("label").mean().round(3).to_string())
    if df["vt_queried_utc"].notna().any():
        lag = (pd.to_datetime(df["vt_queried_utc"]) - df["first_seen"]).dt.total_seconds() / 3600
        print("\nVirusTotal query lag after ingestion (hours), by label:")
        print(lag.groupby(df["label"]).describe()[["count", "50%", "max"]].round(2).to_string())

    days = sorted(df["first_seen"].dt.date.unique())
    cut = max(1, int(len(days) * args.train_frac))
    tr_mask = df["first_seen"].dt.date.isin(set(days[:cut]))
    te_mask = ~tr_mask & ~df["domain"].isin(set(df.loc[tr_mask, "domain"]))
    ytr, yte = y[tr_mask], y[te_mask]
    print(f"\n{len(days)} collection days -> train {tr_mask.sum()} rows ({cut} days), "
          f"test {te_mask.sum()} rows (domain-disjoint). phishing share train/test: {ytr.mean():.2f}/{yte.mean():.2f}")
    if len(set(ytr)) < 2 or len(set(yte)) < 2:
        sys.exit("train or test split has a single class - collect over more days")
    Ftr, Fte = F[tr_mask], F[te_mask]

    configs = [("A  lexical only (refit)", ["lex_logit"]),
               ("B  + DNS", ["lex_logit"] + GROUPS["DNS"]),
               ("C  + WHOIS", ["lex_logit"] + GROUPS["WHOIS"]),
               ("D  + VirusTotal", ["lex_logit"] + GROUPS["VirusTotal"]),
               ("E  + brand check", ["lex_logit"] + GROUPS["Brand"]),
               ("F  all signals", ["lex_logit"] + ALL),
               ("G  all minus VirusTotal", ["lex_logit"] + GROUPS["DNS"] + GROUPS["WHOIS"] + GROUPS["Brand"]),
               ("S  WHOIS age ONLY (shortcut check)", GROUPS["WHOIS"])]
    scores = {"Stage-1 as deployed (no refit)": p_lex[te_mask.to_numpy()]}
    rule = []
    for (pi, d, w, v, b), keep in zip(sig, te_mask.to_numpy()):
        if keep:
            try:
                lvl = decide(pi, config.TAU, d, w, v, config.WARN_MARGIN, brand=b)["level"]
            except TypeError:        # backend not updated with the brand check yet
                lvl = decide(pi, config.TAU, d, w, v, config.WARN_MARGIN)["level"]
            rule.append(lvl + pi)
    scores["Rule policy (current app)"] = np.array(rule)
    models = {}
    for name, cols in configs:
        m = make_model().fit(Ftr[cols], ytr)
        scores[name], models[name] = m.predict_proba(Fte[cols])[:, 1], (m, cols)

    out = []
    for name, s in scores.items():
        lo, hi = boot(yte, s, lambda a, b: tpr_at_fpr(a, b), args.boot)
        alo, ahi = boot(yte, s, roc_auc_score, args.boot)
        out.append({"model": name, "ROC_AUC": roc_auc_score(yte, s), "AUC_ci": f"[{alo:.4f}, {ahi:.4f}]",
                    "PR_AUC": average_precision_score(yte, s), "TPR@1%FPR": tpr_at_fpr(yte, s),
                    "TPR_ci": f"[{lo:.3f}, {hi:.3f}]", "_lo": lo, "_hi": hi})
    res_full = pd.DataFrame(out)
    res = res_full.drop(columns=["_lo", "_hi"])
    res.to_csv(RESULTS / "ablation.csv", index=False)
    print("\n== Ablation (time-ordered, domain-disjoint test set) ==")
    print(res.round(4).to_string(index=False))

    m, cols = models["F  all signals"]
    imp = permutation_importance(m, Fte[cols], yte, scoring="roc_auc", n_repeats=10, random_state=0)
    imp_df = pd.DataFrame({"feature": cols, "auc_drop": imp.importances_mean}).sort_values("auc_drop", ascending=False)
    imp_df.to_csv(RESULTS / "importance.csv", index=False)
    print("\n== Permutation importance (config F, drop in test AUC) ==")
    print(imp_df.head(10).round(4).to_string(index=False))

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(8, 4.5))
        yy = np.arange(len(res))[::-1]
        err = np.array([res_full["TPR@1%FPR"] - res_full["_lo"], res_full["_hi"] - res_full["TPR@1%FPR"]])
        ax.barh(yy, res_full["TPR@1%FPR"], xerr=np.clip(err, 0, None), color="#5C8AE6")
        ax.set_yticks(yy)
        ax.set_yticklabels(res["model"], fontsize=8)
        ax.set_xlabel("Recall of phishing at 1% false-positive rate (95% bootstrap CI)")
        fig.tight_layout()
        fig.savefig(RESULTS / "ablation.png", dpi=160)
        fig2, ax2 = plt.subplots(figsize=(5, 4.5))
        for name in ["A  lexical only (refit)", "G  all minus VirusTotal", "F  all signals"]:
            f, t, _ = roc_curve(yte, scores[name])
            ax2.plot(f, t, label=name.split("  ")[1])
        ax2.set_xscale("log"); ax2.set_xlim(1e-3, 1); ax2.set_xlabel("False-positive rate"); ax2.set_ylabel("True-positive rate")
        ax2.legend(fontsize=8); fig2.tight_layout(); fig2.savefig(RESULTS / "roc.png", dpi=160)
        print(f"\nfigures saved in {RESULTS}")
    except ImportError:
        print("matplotlib not installed - skipped figures")

    print("\nREAD BEFORE CLAIMING ANYTHING: config S shows how much a single shortcut (domain age) explains; "
          "VirusTotal vendors may consume the same feed that labels phishing (compare F vs G); "
          "benign rows are homepages, so --url-mode host (default) is the fair comparison.")


if __name__ == "__main__":
    main()
