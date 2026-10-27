"""Stage 3 - policy engine: turns ML score + external evidence into an auditable verdict.

Rules (deliberately simple so they can be explained and defended):
  1. ML score >= tau                         -> PHISHING;  tau-margin <= score < tau -> SUSPICIOUS
  2. Brand lookalike / brand name embedded   -> at least SUSPICIOUS
  3. VirusTotal malicious >= 3               -> PHISHING;  1-2 malicious or >= 2 suspicious -> at least SUSPICIOUS
  4. Domain registered < 30 days ago         -> escalate one level (SAFE->SUSPICIOUS->PHISHING)
  5. DNS is informational (unresolvable domains are reported, not escalated)
"""
LEVELS = ["SAFE", "SUSPICIOUS", "PHISHING"]


def decide(prob, tau, dns=None, whois=None, vt=None, warn_margin=0.15, brand=None) -> dict:
    reasons, level = [], 0

    if prob >= tau:
        level = 2
        reasons.append(f"ML score {prob:.3f} is at or above the blocking threshold {tau:.3f}")
    elif prob >= tau - warn_margin:
        level = 1
        reasons.append(f"ML score {prob:.3f} is inside the warning band")
    else:
        reasons.append(f"ML score {prob:.3f} is low (URL structure looks ordinary)")

    if brand:
        level = max(level, 1)
        if brand["kind"] == "lookalike":
            reasons.append(f"'{brand['label']}' imitates the brand '{brand['brand']}' "
                           f"(lookalike spelling) but is not its official domain")
        else:
            reasons.append(f"The brand name '{brand['brand']}' appears in the {brand['where']} "
                           f"('{brand['label']}') but this is not its official domain")

    if vt:
        if vt.get("found"):
            m = int(vt.get("malicious", 0))
            s = int(vt.get("suspicious", 0))
            h = int(vt.get("harmless", 0))
            u = int(vt.get("undetected", 0))
            reasons.append(
                f"VirusTotal reputation: {m} malicious, {s} suspicious, "
                f"{h} harmless, {u} undetected"
            )
            if m >= 3:
                level = 2
                reasons.append("Policy trigger: 3 or more malicious detections sets the verdict to PHISHING")
            elif m >= 1 or s >= 2:
                level = max(level, 1)
                reasons.append("Policy trigger: malicious detections or 2+ suspicious detections raise the verdict to at least SUSPICIOUS")
            else:
                reasons.append("VirusTotal did not trigger a verdict escalation; this does not guarantee the URL is safe")
        elif vt.get("error"):
            reasons.append(f"VirusTotal lookup failed or unavailable ({vt['error']})")
        elif vt.get("enabled"):
            reasons.append("VirusTotal has no existing record of this URL or domain")
        else:
            reasons.append("VirusTotal check skipped: API key is not configured")

    if whois:
        age = whois.get("age_days")
        if whois.get("not_registered"):
            reasons.append("WHOIS: this domain is not registered")
        elif age is not None:
            if age < 30:
                level = min(level + 1, 2)
                reasons.append(f"Domain was registered only {age} days ago (escalated one level)")
            elif age < 180:
                reasons.append(f"Domain is fairly new ({age} days old)")
            else:
                reasons.append(f"Domain is established ({age} days old)")
        elif whois.get("error"):
            reasons.append(f"WHOIS lookup failed ({whois['error']})")
        else:
            reasons.append("WHOIS returned no creation date")

    if dns:
        if dns.get("nxdomain"):
            reasons.append("DNS: domain does not exist (NXDOMAIN)")
        elif dns.get("error"):
            reasons.append(f"DNS lookup failed ({dns['error']})")
        elif not dns.get("resolves"):
            reasons.append("DNS: no A/AAAA records found")
        else:
            n = len(dns.get("a", [])) + len(dns.get("aaaa", []))
            reasons.append(f"DNS: resolves to {n} address(es)")

    return {"verdict": LEVELS[level], "level": level, "reasons": reasons}
