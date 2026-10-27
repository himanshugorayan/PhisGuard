# PhisGuard

Pre-navigation phishing triage. A lexical ML model (HistGradientBoosting, 18 URL features) scores a link
instantly; DNS, WHOIS (domain age) and VirusTotal evidence are then fetched in parallel and combined by a
rule-based policy engine into **SAFE / SUSPICIOUS / PHISHING** with human-readable reasons.
The destination page is never visited.

```
URL -> feature extraction -> ML probability --(>=0.9: stop, already PHISHING)
                                   |
                      DNS + WHOIS + VirusTotal (parallel, cached, timeouts)
                                   |
                           policy engine -> verdict + reasons
```

## Layout
```
backend/app/        features.py  dns_check.py  whois_check.py  vt_check.py  policy.py  main.py
backend/models/     phisguard_model.joblib  phisguard_features.joblib   (copy from your notebook)
backend/static/     index.html (web UI)
backend/tests/      pytest suite
Dockerfile
```

## Run locally
```bash
cd backend
pip install -r requirements.txt
# pin scikit-learn to the exact version used in the notebook:
echo "scikit-learn==$(python -c 'import sklearn;print(sklearn.__version__)')" >> requirements.txt
export VT_API_KEY=your-key        # optional; without it the VirusTotal card says "not configured"
uvicorn app.main:app --reload
```
Open http://127.0.0.1:8000 (UI) or http://127.0.0.1:8000/docs (interactive API docs).

## Validate feature extraction (do this once)
Copy `PhiUSIIL_Phishing_URL_Dataset.csv` into `backend/`, then `python validate_features.py`.
Every feature should show ~100% match; mismatches mean the extractor differs from the dataset's definition.

## Tests
```bash
pip install -r requirements-dev.txt && pytest -q
```

## Docker
```bash
docker build -t phisguard .
docker run --rm -p 8000:8000 -e VT_API_KEY=your-key phisguard
```

## Deploy (Render, free tier)
1. Push this folder to GitHub (`.env` and CSVs are git-ignored; commit `backend/models/*.joblib`).
2. Render -> New -> Web Service -> connect the repo -> Runtime: **Docker**.
3. Environment -> add `VT_API_KEY`. Deploy. Health check path: `/health`.
Free instances sleep when idle, so the first request after a pause is slow.

## Configuration (env vars)
`VT_API_KEY`, `PHISGUARD_TAU` (default 0.385), `PHISGUARD_WARN_MARGIN` (0.15), `PHISGUARD_SKIP_ABOVE` (0.9),
`EXTERNAL_TIMEOUT` (8 s), `RATE_LIMIT_PER_MIN` (20).

## Design notes / limitations (for your report)
- The 99.79 % accuracy belongs to the lexical model on a random split; DNS/WHOIS/VirusTotal are rule-based additions.
- Deep scans leave the paper's "static only" boundary: DNS/WHOIS servers see the domain, VirusTotal receives the URL.
- Logs store a SHA-256 prefix of the URL, never the URL. Input is validated (http/https, valid hostname, 2048 chars); the app never fetches the submitted URL, so it cannot be used for SSRF.
- Rate limiting is in-memory per instance; use a shared store if you scale out.
- Evaluation is by random row split; domain-grouped/temporal evaluation is the main open validity question.
