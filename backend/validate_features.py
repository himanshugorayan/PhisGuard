"""Check extract_features() against the dataset's own pre-computed columns.
Run from this folder:  python validate_features.py
(put PhiUSIIL_Phishing_URL_Dataset.csv next to this file)
"""
import pandas as pd

from app.features import FEATURE_COLS, extract_features

CSV = "PhiUSIIL_Phishing_URL_Dataset.csv"
df = pd.read_csv(CSV).sample(3000, random_state=1)
mine = pd.DataFrame([extract_features(u) for u in df["URL"]], index=df.index)

print(f"{'feature':30s} match%  max_abs_diff")
bad = []
for c in FEATURE_COLS:
    diff = (mine[c] - df[c]).abs()
    ok = diff < 1e-6
    print(f"{c:30s} {ok.mean()*100:6.1f}  {diff.max():.4f}")
    if ok.mean() < 0.999:
        bad.append(c)

print("\nFeatures needing a fix:", bad or "none - all match")
for c in bad[:4]:
    wrong = df.loc[((mine[c] - df[c]).abs() >= 1e-6)].head(3)
    print(f"\n--- {c}: examples ---")
    for i, r in wrong.iterrows():
        print(r["URL"], "| dataset:", r[c], "| mine:", mine.loc[i, c])
