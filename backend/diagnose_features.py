from urllib.parse import urlsplit

import numpy as np
import pandas as pd

CSV = "PhiUSIIL_Phishing_URL_Dataset.csv"
df = pd.read_csv(CSV).sample(4000, random_state=3).reset_index(drop=True)


def parts(u):
    s = urlsplit(u)
    return {
        "scheme": s.scheme + "://",
        "netloc": s.netloc,
        "path": s.path,
        "query": ("?" + s.query) if s.query else "",
        "frag": ("#" + s.fragment) if s.fragment else "",
    }


P = [parts(u) for u in df["URL"]]
COMP = ["scheme", "netloc", "path", "query", "frag"]
SPECIAL_EXCL = set("=?&")


def regress(name, target, fn, labels):
    A = np.array([[fn(p[c]) for c in COMP] + [1] for p in P], dtype=float)
    y = df[target].to_numpy(dtype=float)
    coef, *_ = np.linalg.lstsq(A, y, rcond=None)
    exact = (np.rint(A @ coef) == y).mean() * 100
    print(f"\n{name}  (target column: {target})")
    for lab, c in zip(labels + ["constant"], coef):
        print(f"   {lab:10s} coefficient = {c:7.3f}")
    print(f"   rounded-model exact match: {exact:.1f}%")


L = COMP
regress("Total length by component", "URLLength", len, L)
regress("Letters by component", "NoOfLettersInURL", lambda s: sum(c.isalpha() for c in s), L)
regress("Digits by component", "NoOfDegitsInURL", lambda s: sum(c.isdigit() for c in s), L)
regress("Other special chars by component", "NoOfOtherSpecialCharsInURL",
        lambda s: sum((not c.isalnum()) and c not in SPECIAL_EXCL for c in s), L)
regress("Ampersands by component", "NoOfAmpersandInURL", lambda s: s.count("&"), L)

chars = sorted({c for p in P for s in p.values() for c in s if not c.isalnum() and c not in SPECIAL_EXCL})[:12]
A = np.array([[sum(s.count(ch) for s in p.values()) for ch in chars] for p in P], dtype=float)
coef, *_ = np.linalg.lstsq(A, df["NoOfOtherSpecialCharsInURL"].to_numpy(dtype=float), rcond=None)
print("\nPer-character weight in NoOfOtherSpecialCharsInURL (1 = counted, 0 = ignored):")
print("   " + "  ".join(f"{ch!r}:{c:.2f}" for ch, c in zip(chars, coef)))

print("\nRatio denominators (match% of  round(count/denominator, 3) == dataset ratio):")
for cnt, ratio in [("NoOfLettersInURL", "LetterRatioInURL"), ("NoOfDegitsInURL", "DegitRatioInURL"),
                   ("NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL")]:
    n = df[cnt].to_numpy(dtype=float)
    for lab, den in [("dataset URLLength", df["URLLength"].to_numpy(dtype=float)),
                     ("len(URL string)", df["URL"].str.len().to_numpy(dtype=float))]:
        ok = (np.abs(n / den - df[ratio].to_numpy(dtype=float)) < 0.0006).mean() * 100
        print(f"   {ratio:24s} / {lab:18s}: {ok:5.1f}%")
