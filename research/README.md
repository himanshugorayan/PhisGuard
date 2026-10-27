# PhisGuard research: dataset D3 and the stage-2 ablation

Goal: measure how much DNS, WHOIS, VirusTotal and the brand check add to the lexical model, on data where those
signals were recorded at the time the URL was first seen.

## Setup (once)
```bash
cd ~/PhisGuard/research
pip install tranco                    # Tranco list client
export VT_API_KEY=your-key            # free VirusTotal key; never commit it
```
The backend update (brand check, WHOIS fix) must already be applied.

## Daily routine (run for 10-14 days, same time each day)
```bash
python collect.py ingest --n-phish 200 --n-benign 200   # new phishing URLs + Tranco benign domains
python collect.py enrich                                # DNS + WHOIS + brand check (a few minutes)
python collect.py enrich-vt --cap 450                   # VirusTotal; ~2 h because of the 4 requests/min limit
python collect.py status
```
If the feed download is blocked, save https://openphish.com/feed.txt by hand and pass `--feed-file feed.txt`.
For the Tranco list without the package, pass `--tranco-file list.csv` (lines `rank,domain`).

## Analysis
```bash
python train_stage2.py            # writes results/ablation.csv, importance.csv, ablation.png, roc.png
python train_stage2.py --url-mode full   # keep phishing URL paths (benign rows are still homepages)
```
Aim for at least ~1,000 benign and ~1,000 phishing rows in total. With a small test set, "recall at 1% false-positive
rate" is not meaningful (1% of 100 benign rows is a single URL).

## Safety and terms
- Feed URLs are never opened or fetched; only DNS, WHOIS and VirusTotal lookups run. Do not open them in a browser.
- OpenPhish community feed: non-commercial use only. VirusTotal free API: 4 requests/min, 500/day, non-commercial.
- VirusTotal calls are GET lookups of existing reports; nothing is submitted for scanning.

## Design decisions to state in the paper
1. Time-aligned enrichment: old phishing URLs queried later are mostly dead, which would leak the label.
2. Benign rows are Tranco homepages while phishing URLs have paths, so the default `--url-mode host` models both
   classes as `https://<host>/` with `www.` removed. Both modes are reportable.
3. Tranco sampled evenly across rank bands (1-1k, 1k-10k, 10k-100k, 100k-1M) so "old, famous domain" is not the only benign type.
4. At most one phishing URL per registered domain per batch; test domains that appear in train are dropped.
5. Time-ordered split (earliest days train, latest days test); fixed hyper-parameters; bootstrap 95% intervals.
6. Config S (WHOIS age only) quantifies the popularity shortcut; compare F (all) with G (all minus VirusTotal) because
   VirusTotal vendors may consume the same feed that labels the phishing rows.
7. Train/serve parity: VirusTotal is queried in `url` mode here. The live app currently falls back to the domain;
   use the same mode when stage 2 is deployed.

## Known limitations
Feed-listed URLs are the ones the feed's detector found (selection bias); phishing hosted on legitimate platforms
becomes label noise in host mode; WHOIS is often redacted (missingness is modelled explicitly); results describe
the collection window only.
