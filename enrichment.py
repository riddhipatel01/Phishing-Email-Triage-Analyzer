import json
import os
import hashlib
import ipaddress
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv

# Always find .env relative to this file — works regardless of launch directory
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

CACHE_DIR         = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cache')
VT_API_KEY        = os.getenv("VIRUSTOTAL_API_KEY", "")
VT_DOMAIN_ENDPOINT = "https://www.virustotal.com/api/v3/domains/{}"
VT_IP_ENDPOINT     = "https://www.virustotal.com/api/v3/ip_addresses/{}"


# ── Cache helpers ─────────────────────────────────────────────────────────────

def _cache_path(indicator: str) -> str:
    key = hashlib.md5(indicator.encode()).hexdigest()
    return os.path.join(CACHE_DIR, f"{key}.json")

def _load_cache(indicator: str):
    path = _cache_path(indicator)
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None

def _save_cache(indicator: str, data: dict):
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(_cache_path(indicator), "w") as f:
        json.dump(data, f)


# ── VT response parsers ───────────────────────────────────────────────────────

def _parse_vt_stats(response_json: dict) -> dict:
    """Extract malicious/suspicious/harmless counts from VT response."""
    try:
        stats = response_json["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }
    except (KeyError, TypeError):
        return {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}


def _parse_domain_age(response_json: dict) -> dict:
    """
    Extract domain creation date from VT response and calculate age in days.
    VT returns creation_date as a Unix timestamp integer.
    """
    age_info = {"creation_date": None, "age_days": None}
    try:
        attrs = response_json["data"]["attributes"]
        creation_ts = attrs.get("creation_date")
        if creation_ts:
            creation_dt = datetime.fromtimestamp(creation_ts, tz=timezone.utc)
            now = datetime.now(tz=timezone.utc)
            age_days = (now - creation_dt).days
            age_info["creation_date"] = creation_dt.strftime("%Y-%m-%d")
            age_info["age_days"] = age_days
    except (KeyError, TypeError, OSError):
        pass
    return age_info


# ── Public IP filter ──────────────────────────────────────────────────────────

def _is_public_ip(ip_str: str) -> bool:
    """Return True only for routable public IPs — skip private/loopback/reserved."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            not ip.is_private and
            not ip.is_loopback and
            not ip.is_link_local and
            not ip.is_multicast and
            not ip.is_reserved and
            not ip.is_unspecified
        )
    except ValueError:
        return False


# ── Domain lookup ─────────────────────────────────────────────────────────────

def lookup_domain(domain: str) -> dict:
    """
    Look up a domain on VirusTotal.
    Returns stats dict with malicious counts + domain age.
    """
    if not VT_API_KEY:
        return {}

    cached = _load_cache(domain)
    if cached:
        return cached

    try:
        url  = VT_DOMAIN_ENDPOINT.format(domain)
        resp = requests.get(
            url,
            headers={"x-apikey": VT_API_KEY},
            timeout=10
        )
        if resp.status_code == 200:
            rj   = resp.json()
            data = _parse_vt_stats(rj)
            data.update(_parse_domain_age(rj))   # adds creation_date + age_days
            data["type"] = "domain"
            _save_cache(domain, data)
            return data
        elif resp.status_code == 404:
            # Domain not in VT database — not necessarily bad, just unknown
            result = {"malicious": 0, "suspicious": 0, "harmless": 0,
                      "undetected": 0, "creation_date": None, "age_days": None,
                      "type": "domain", "note": "Not found in VT database"}
            _save_cache(domain, result)
            return result
    except Exception:
        pass
    return {}


# ── IP lookup ─────────────────────────────────────────────────────────────────

def lookup_ip(ip: str) -> dict:
    """
    Look up a public IP on VirusTotal.
    Skips private/internal IPs automatically.
    """
    if not VT_API_KEY:
        return {}

    if not _is_public_ip(ip):
        return {}   # silently skip — private IPs have no VT data

    cached = _load_cache(f"ip:{ip}")
    if cached:
        return cached

    try:
        url  = VT_IP_ENDPOINT.format(ip)
        resp = requests.get(
            url,
            headers={"x-apikey": VT_API_KEY},
            timeout=10
        )
        if resp.status_code == 200:
            rj   = resp.json()
            data = _parse_vt_stats(rj)
            data["type"] = "ip"
            # Also grab the country and owner if available
            try:
                attrs = rj["data"]["attributes"]
                data["country"] = attrs.get("country", "")
                data["owner"]   = attrs.get("as_owner", "")
            except (KeyError, TypeError):
                pass
            _save_cache(f"ip:{ip}", data)
            return data
    except Exception:
        pass
    return {}


# ── Main enrichment function called by app.py ─────────────────────────────────

def enrich_iocs(iocs: dict) -> dict:
    """
    Takes the iocs dict from analyzer.py.
    Looks up domains AND public IPs on VirusTotal.
    Returns { "evil.com": { malicious: N, age_days: X, ... }, ... }
    """
    results = {}

    # Domain lookups
    for domain in iocs.get("domains", []):
        vt = lookup_domain(domain)
        if vt:
            results[domain] = vt

    # IP lookups — only public IPs from Received chain
    for ip in iocs.get("ips", []):
        vt = lookup_ip(ip)
        if vt:
            results[ip] = vt

    return results