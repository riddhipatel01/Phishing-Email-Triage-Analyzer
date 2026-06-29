import re
import tldextract


def _root_domain(address: str) -> str:
    match = re.search(r'@([\w.\-]+)', address)
    host = match.group(1) if match else address
    ext = tldextract.extract(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return host.lower()


def score(result: dict) -> dict:
    signals   = []
    raw_score = 0

    auth             = result.get("authentication", {})
    iocs             = result.get("iocs", {})
    enrichment       = result.get("enrichment", {})
    headers          = result.get("headers", {})
    anomalies        = result.get("anomalies", [])
    urgency          = result.get("urgency", [])
    body_patterns    = result.get("body_patterns", [])
    lookalike_domains = result.get("lookalike_domains", [])
    attachment_risks = result.get("attachment_risks", [])
    qr_codes         = result.get("qr_codes", [])
    too_good         = result.get("too_good", [])

    spf   = auth.get("spf",   "missing")
    dkim  = auth.get("dkim",  "missing")
    dmarc = auth.get("dmarc", "missing")

    # ── SPF ───────────────────────────────────────────────────────────────────
    if spf in ("fail", "softfail", "none"):
        contrib = 20; raw_score += contrib
        signals.append({"name": "SPF", "status": spf,
            "detail": "Sending IP not authorised by domain policy",
            "contribution": contrib, "icon": "✗"})
    elif spf == "missing":
        contrib = 8; raw_score += contrib
        signals.append({"name": "SPF", "status": "missing",
            "detail": "No sender policy record found",
            "contribution": contrib, "icon": "⚠"})
    else:
        signals.append({"name": "SPF", "status": "pass",
            "detail": "Sending IP is authorised by the domain",
            "contribution": 0, "icon": "✓"})

    # ── DKIM ─────────────────────────────────────────────────────────────────
    if dkim in ("fail", "none"):
        contrib = 30 if spf == "pass" else 15; raw_score += contrib
        detail = ("Message signature invalid — body may have been tampered with in transit"
                  if spf == "pass" else "Signature invalid and SPF also failing")
        signals.append({"name": "DKIM", "status": "fail",
            "detail": detail, "contribution": contrib, "icon": "✗"})
    elif dkim == "missing":
        contrib = 8; raw_score += contrib
        signals.append({"name": "DKIM", "status": "missing",
            "detail": "Message was not cryptographically signed",
            "contribution": contrib, "icon": "⚠"})
    else:
        signals.append({"name": "DKIM", "status": "pass",
            "detail": "Signature valid — message not tampered with",
            "contribution": 0, "icon": "✓"})

    # ── DMARC ────────────────────────────────────────────────────────────────
    if dmarc in ("fail", "none", "bestguesspass"):
        contrib = 15  # weaker than real fail — it's guessing, not failing
        raw_score += contrib
        signals.append({"name": "DMARC", "status": dmarc,
        "detail": "No real DMARC record — server is guessing based on SPF/DKIM only",
        "contribution": contrib, "icon": "⚠"})
    elif dmarc == "missing":
        contrib = 10; raw_score += contrib
        signals.append({"name": "DMARC", "status": "missing",
            "detail": "No domain alignment policy configured",
            "contribution": contrib, "icon": "⚠"})
    else:
        signals.append({"name": "DMARC", "status": "pass",
            "detail": "From domain aligns with authenticated sender",
            "contribution": 0, "icon": "✓"})

    # ── All three passing: trust bonus ────────────────────────────────────────
    if spf == "pass" and dkim == "pass" and dmarc == "pass":
        contrib = -20; raw_score += contrib
        signals.append({"name": "Auth clean", "status": "all pass",
            "detail": "SPF, DKIM and DMARC all pass — sender identity verified",
            "contribution": contrib, "icon": "✓"})

    # ── Header anomalies ──────────────────────────────────────────────────────
    from_addr   = headers.get("from", "")
    return_path = headers.get("return_path", "")
    reply_to    = headers.get("reply_to", "")
    from_root   = _root_domain(from_addr)
    rp_root     = _root_domain(return_path)
    rt_root     = _root_domain(reply_to)

    if rp_root and from_root and from_root != rp_root:
        contrib = 20; raw_score += contrib
        signals.append({"name": "Return-Path mismatch", "status": "anomaly",
            "detail": f"From root ({from_root}) differs from Return-Path root ({rp_root})",
            "contribution": contrib, "icon": "⚠"})

    if rt_root and from_root and from_root != rt_root:
        contrib = 20; raw_score += contrib
        signals.append({"name": "Reply-To mismatch", "status": "anomaly",
            "detail": f"Replies routed to {rt_root}, not back to {from_root}",
            "contribution": contrib, "icon": "⚠"})

    for anomaly in anomalies:
        if "display-name spoofing" in anomaly.lower():
            contrib = 35; raw_score += contrib
            signals.append({"name": "Display-name spoofing", "status": "anomaly",
                "detail": anomaly, "contribution": contrib, "icon": "✗"})

    # ── Lookalike / typosquatted domains ──────────────────────────────────────
    for finding in lookalike_domains:
        contrib = 30; raw_score += contrib
        signals.append({"name": "Lookalike domain", "status": "typosquat",
            "detail": finding, "contribution": contrib, "icon": "✗"})

    # ── Urgency language ──────────────────────────────────────────────────────
    if len(urgency) >= 3:
        contrib = 15; raw_score += contrib
        signals.append({"name": "Urgency language", "status": f"{len(urgency)} phrases",
            "detail": f"High-pressure language: {', '.join(urgency[:3])}…",
            "contribution": contrib, "icon": "⚠"})
    elif len(urgency) >= 1:
        contrib = 8; raw_score += contrib
        signals.append({"name": "Urgency language", "status": f"{len(urgency)} phrase(s)",
            "detail": f"Pressure language detected: {', '.join(urgency)}",
            "contribution": contrib, "icon": "⚠"})

    # ── Suspicious body patterns ──────────────────────────────────────────────
    for pattern in body_patterns:
        contrib = 20; raw_score += contrib
        signals.append({"name": "Suspicious body", "status": "anomaly",
            "detail": pattern, "contribution": contrib, "icon": "✗"})

    # ── QR code / quishing ────────────────────────────────────────────────────
    for finding in qr_codes:
        contrib = 20; raw_score += contrib
        signals.append({"name": "QR code (quishing)", "status": "detected",
            "detail": finding, "contribution": contrib, "icon": "✗"})

    # ── Too good to be true ───────────────────────────────────────────────────
    for finding in too_good:
        contrib = 20; raw_score += contrib
        signals.append({"name": "Scam language", "status": "detected",
            "detail": finding, "contribution": contrib, "icon": "✗"})

    # ── Risky attachments ─────────────────────────────────────────────────────
    for finding in attachment_risks:
        contrib = 25; raw_score += contrib
        signals.append({"name": "Risky attachment", "status": "flagged",
            "detail": finding, "contribution": contrib, "icon": "✗"})

    # ── IOC counts ────────────────────────────────────────────────────────────
    url_count = len(iocs.get("urls", []))
    if url_count > 10:
        contrib = 10; raw_score += contrib
        signals.append({"name": "High URL count", "status": f"{url_count} URLs",
            "detail": "Large number of URLs in body — common in phishing lures",
            "contribution": contrib, "icon": "⚠"})

    # ── VirusTotal enrichment ─────────────────────────────────────────────────
    for indicator, vt in enrichment.items():
        malicious  = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)
        itype      = vt.get("type", "domain")
        age_days   = vt.get("age_days")

        # Unknown domain — never scanned, no history at all
        harmless   = vt.get("harmless", 0)
        if malicious == 0 and suspicious == 0 and harmless == 0 and itype == "domain":
            contrib = 10
            raw_score += contrib
            signals.append({"name": f"VT: {indicator}", "status": "unknown",
                "detail": "Domain has no scan history on VirusTotal — completely unknown",
                "contribution": contrib, "icon": "⚠"})

        if malicious >= 3:
            contrib = 40; raw_score += contrib
            signals.append({"name": f"VT: {indicator}", "status": f"{malicious} malicious",
                "detail": f"Flagged malicious by {malicious} security engines",
                "contribution": contrib, "icon": "✗"})
        elif malicious >= 1:
            contrib = 15; raw_score += contrib
            signals.append({"name": f"VT: {indicator}", "status": f"{malicious} malicious",
                "detail": f"Flagged by {malicious} engine — possible false positive, verify manually",
                "contribution": contrib, "icon": "⚠"})
        elif suspicious >= 3:
            contrib = 10; raw_score += contrib
            signals.append({"name": f"VT: {indicator}", "status": f"{suspicious} suspicious",
                "detail": f"Marked suspicious by {suspicious} engines",
                "contribution": contrib, "icon": "⚠"})
        else:
            age_str = f" | Registered {age_days} days ago" if age_days is not None else ""
            country = f" | {vt.get('country','')}" if vt.get('country') else ""
            signals.append({"name": f"VT: {indicator}", "status": "clean",
                "detail": f"{malicious} malicious, {suspicious} suspicious, {vt.get('harmless',0)} harmless{age_str}{country}",
                "contribution": 0, "icon": "✓"})

        # Domain age signal
        if itype == "domain" and age_days is not None:
            if age_days < 30:
                contrib = 25; raw_score += contrib
                signals.append({"name": f"New domain: {indicator}", "status": f"{age_days} days old",
                    "detail": f"Registered only {age_days} days ago — attackers use fresh domains to avoid reputation history",
                    "contribution": contrib, "icon": "✗"})
            elif age_days < 90:
                contrib = 10; raw_score += contrib
                signals.append({"name": f"Recent domain: {indicator}", "status": f"{age_days} days old",
                    "detail": f"Domain registered {age_days} days ago — relatively new",
                    "contribution": contrib, "icon": "⚠"})

    # ── Final confidence % ────────────────────────────────────────────────────
    confidence = max(0, min(100, raw_score))
    if confidence >= 60:   verdict = "high"
    elif confidence >= 26: verdict = "medium"
    else:                  verdict = "low"

    result["confidence"] = confidence
    result["verdict"]    = verdict
    result["signals"]    = signals
    result["reasons"]    = [
        f"{s['icon']} {s['name']}: {s['detail']} ({s['contribution']:+d}%)"
        for s in signals if s["contribution"] != 0
    ]
    return result