"""Stage 2a - DNS evidence (contacts DNS servers, never the destination site)."""
import re

import dns.exception
import dns.resolver

_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _records(resolver, name, rtype):
    """Returns (records, nxdomain)."""
    try:
        return [r.to_text() for r in resolver.resolve(name, rtype)], False
    except dns.resolver.NXDOMAIN:
        return [], True
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return [], False


def check_dns(host: str, domain: str, timeout: float = 3.0) -> dict:
    out = {"resolves": False, "nxdomain": False, "a": [], "aaaa": [], "via": None,
           "mx_count": 0, "ns_count": 0, "error": None}
    if _IP_RE.match(host):
        out.update(resolves=True, a=[host], via=host)
        return out
    resolver = dns.resolver.Resolver()
    resolver.timeout = resolver.lifetime = timeout
    try:
        names = [host] + ([domain] if domain and domain != host else [])
        missing = 0
        for name in names:                      # try www.x.com first, then the bare domain x.com
            a, nx_a = _records(resolver, name, "A")
            aaaa, _ = _records(resolver, name, "AAAA")
            missing += 1 if nx_a else 0
            if a or aaaa:
                out.update(resolves=True, a=a[:5], aaaa=aaaa[:5], via=name)
                break
        out["nxdomain"] = (not out["resolves"]) and missing == len(names)
        out["mx_count"] = len(_records(resolver, domain, "MX")[0])
        out["ns_count"] = len(_records(resolver, domain, "NS")[0])
    except Exception as e:  # noqa: BLE001 - report, never crash the scan
        out["error"] = type(e).__name__
    return out
