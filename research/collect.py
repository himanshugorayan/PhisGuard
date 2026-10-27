"""PhisGuard research data collector -> dataset D3.

Collects FRESH phishing URLs (OpenPhish community feed) and benign domains (Tranco list), then records
DNS, WHOIS, brand-check and VirusTotal evidence at collection time, so the external signals are
time-aligned with the URL (see README for why this matters).

Safety: URLs from the feed are NEVER opened or fetched. Only DNS, WHOIS and VirusTotal lookups are made.
"""
import argparse
import base64
import json
import os
import random
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "backend"))
from app.features import parse_target, registered_domain  # noqa: E402  (same code as the live app)

DB_PATH = Path(os.getenv("PHISGUARD_DB", HERE / "data" / "d3.sqlite"))
FEED_URL = "https://openphish.com/feed.txt"
BANDS = [(1, 1_000), (1_001, 10_000), (10_001, 100_000), (100_001, 1_000_000)]  # Tranco rank strata
VT_MIN_INTERVAL = 15.5   # seconds: free API allows 4 requests/minute

SCHEMA = """
CREATE TABLE IF NOT EXISTS urls(
  id INTEGER PRIMARY KEY, url TEXT UNIQUE, host TEXT, domain TEXT,
  label INTEGER, source TEXT, tranco_rank INTEGER, first_seen_utc TEXT,
  net_done INTEGER DEFAULT 0, enriched_utc TEXT, dns_json TEXT, whois_json TEXT, brand_json TEXT,
  vt_done INTEGER DEFAULT 0, vt_queried_utc TEXT, vt_json TEXT)"""


def now_utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(SCHEMA)
    return conn


def insert(conn, url, host, domain, label, source, rank):
    cur = conn.execute(
        "INSERT OR IGNORE INTO urls(url,host,domain,label,source,tranco_rank,first_seen_utc) VALUES(?,?,?,?,?,?,?)",
        (url, host, domain, label, source, rank, now_utc()))
    return cur.rowcount == 1


# ----------------------------------------------------------------------------- ingestion
def download_feed():
    req = urllib.request.Request(FEED_URL, headers={"User-Agent": "PhisGuard-research/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "ignore").splitlines()


def load_tranco(path=None):
    if path:                                    # CSV lines: rank,domain
        out = []
        for line in Path(path).read_text().splitlines():
            rank, _, dom = line.partition(",")
            if rank.strip().isdigit() and dom.strip():
                out.append((int(rank), dom.strip().lower()))
        return out
    try:
        from tranco import Tranco
    except ImportError:
        sys.exit("Install the Tranco client first:  pip install tranco   (or pass --tranco-file rank,domain.csv)")
    latest = Tranco(cache=True, cache_dir=str(HERE / "data" / ".tranco")).list()
    return [(i + 1, d) for i, d in enumerate(latest.top(1_000_000))]


def ingest(conn, n_phish, n_benign, feed_file=None, tranco_file=None, seed=None):
    rng = random.Random(seed if seed is not None else int(time.time()))

    lines = Path(feed_file).read_text().splitlines() if feed_file else download_feed()
    rng.shuffle(lines)
    seen = {r[0] for r in conn.execute("SELECT domain FROM urls")}
    added_p = 0
    for line in lines:
        url = line.strip()
        try:
            _, host = parse_target(url)
        except ValueError:
            continue
        domain = registered_domain(host)
        if domain in seen:                      # at most one URL per registered domain (no domain flooding)
            continue
        seen.add(domain)
        if insert(conn, url, host, domain, 1, "openphish", None):
            added_p += 1
        if added_p >= n_phish:
            break

    ranks = load_tranco(tranco_file)
    per_band = max(1, n_benign // len(BANDS))
    added_b = 0
    for lo, hi in BANDS:
        pool = []
        for rank, dom in ranks:
            if lo <= rank <= hi:
                host = dom
                d = registered_domain(host)
                if d not in seen:
                    pool.append((rank, host, d))
        for rank, host, d in rng.sample(pool, min(per_band, len(pool))):
            seen.add(d)
            if insert(conn, f"https://{host}/", host, d, 0, "tranco", rank):
                added_b += 1
    conn.commit()
    print(f"added {added_p} phishing + {added_b} benign URLs")


# ----------------------------------------------------------------------------- enrichment
def real_fns():
    try:
        from app.brand_check import brand_lookalike
    except ImportError:
        sys.exit("backend/app/brand_check.py is missing - apply the backend update first")
    from app.dns_check import check_dns
    from app.whois_check import check_whois
    return {"dns": check_dns, "whois": check_whois, "brand": brand_lookalike}


def enrich_net(conn, limit=500, workers=4, fns=None):
    """DNS + WHOIS + brand check (run on the same day the URL was ingested)."""
    fns = fns or real_fns()
    rows = conn.execute("SELECT id,host,domain FROM urls WHERE net_done=0 ORDER BY id LIMIT ?", (limit,)).fetchall()

    def work(r):
        i, host, domain = r
        return (i, json.dumps(fns["dns"](host, domain)), json.dumps(fns["whois"](domain)),
                json.dumps(fns["brand"](host, domain)))

    with ThreadPoolExecutor(workers) as ex:
        for k, (i, d, w, b) in enumerate(ex.map(work, rows), 1):
            conn.execute("UPDATE urls SET dns_json=?,whois_json=?,brand_json=?,net_done=1,enriched_utc=? WHERE id=?",
                         (d, w, b, now_utc(), i))
            if k % 25 == 0:
                conn.commit()
                print(f"  network enrichment {k}/{len(rows)}")
    conn.commit()
    print(f"enriched {len(rows)} rows (DNS/WHOIS/brand)")


def vt_lookup(url, domain, mode="url"):
    """Read an EXISTING VirusTotal report (GET only - nothing is submitted for scanning)."""
    key = os.getenv("VT_API_KEY", "")
    out = {"enabled": bool(key), "found": False, "source": mode, "error": None,
           "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
    if not key:
        out["error"] = "no_api_key"
        return out
    path = "urls/" + base64.urlsafe_b64encode(url.encode()).decode().strip("=") if mode == "url" else f"domains/{domain}"
    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/{path}",
                                 headers={"x-apikey": key, "User-Agent": "PhisGuard-research/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            stats = json.load(r)["data"]["attributes"].get("last_analysis_stats", {})
        out.update(found=True, **{k: int(stats.get(k, 0)) for k in ("malicious", "suspicious", "harmless", "undetected")})
    except urllib.error.HTTPError as e:
        if e.code == 429:
            out["error"] = "rate_limited"
        elif e.code != 404:                      # 404 = no record: a valid, informative outcome
            out["error"] = f"http_{e.code}"
    except Exception as e:  # noqa: BLE001
        out["error"] = type(e).__name__
    return out


def enrich_vt(conn, cap=450, mode="url", lookup=None, pace=True):
    if lookup is None and not os.getenv("VT_API_KEY"):
        sys.exit("Set your key first:  export VT_API_KEY=...")
    today = datetime.now(timezone.utc).date().isoformat()
    used = conn.execute("SELECT COUNT(*) FROM urls WHERE vt_queried_utc LIKE ?", (today + "%",)).fetchone()[0]
    rows = conn.execute("SELECT id,url,domain FROM urls WHERE vt_done=0 ORDER BY id").fetchall()
    last, done = 0.0, 0
    for i, url, domain in rows:
        if used >= cap:
            print(f"daily cap of {cap} reached - run again tomorrow")
            break
        if pace and lookup is None:
            wait = VT_MIN_INTERVAL - (time.monotonic() - last)
            if wait > 0:
                time.sleep(wait)
        res = (lookup or vt_lookup)(url, domain, mode)
        last = time.monotonic()
        if res["error"] == "rate_limited":
            print("VirusTotal rate limit hit - stop and retry later")
            break
        if res["error"]:                          # transient problem: leave unfinished, retry next run
            continue
        conn.execute("UPDATE urls SET vt_json=?,vt_done=1,vt_queried_utc=? WHERE id=?", (json.dumps(res), now_utc(), i))
        conn.commit()
        used += 1
        done += 1
        if done % 25 == 0:
            print(f"  VirusTotal {done} done (today: {used}/{cap})")
    print(f"VirusTotal: {done} rows this run")


def status(conn):
    q = lambda sql: conn.execute(sql).fetchall()
    print("rows by label (1=phishing, 0=benign):", q("SELECT label,COUNT(*) FROM urls GROUP BY label"))
    print("collection days:", q("SELECT substr(first_seen_utc,1,10),COUNT(*) FROM urls GROUP BY 1"))
    print("network-enriched:", q("SELECT COUNT(*) FROM urls WHERE net_done=1")[0][0],
          "| VirusTotal done:", q("SELECT COUNT(*) FROM urls WHERE vt_done=1")[0][0])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("ingest", help="add today's phishing + benign URLs")
    a.add_argument("--n-phish", type=int, default=200)
    a.add_argument("--n-benign", type=int, default=200)
    a.add_argument("--feed-file", help="local copy of the feed (one URL per line) instead of downloading")
    a.add_argument("--tranco-file", help="CSV of rank,domain instead of the tranco package")
    a.add_argument("--seed", type=int)
    b = sub.add_parser("enrich", help="DNS + WHOIS + brand check")
    b.add_argument("--limit", type=int, default=500)
    b.add_argument("--workers", type=int, default=4)
    c = sub.add_parser("enrich-vt", help="VirusTotal lookups (slow: free tier 4/min, 500/day)")
    c.add_argument("--cap", type=int, default=450)
    c.add_argument("--mode", choices=["url", "domain"], default="url")
    sub.add_parser("status")
    args = ap.parse_args()

    conn = connect()
    if args.cmd == "ingest":
        ingest(conn, args.n_phish, args.n_benign, args.feed_file, args.tranco_file, args.seed)
    elif args.cmd == "enrich":
        enrich_net(conn, args.limit, args.workers)
    elif args.cmd == "enrich-vt":
        enrich_vt(conn, args.cap, args.mode)
    else:
        status(conn)


if __name__ == "__main__":
    main()
