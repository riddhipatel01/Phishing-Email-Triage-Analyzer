import email
import hashlib
import os
import re
import tldextract

# ── Defanging ─────────────────────────────────────────────────────────────────

def defang_url(url: str) -> str:
    url = url.replace("http", "hxxp")
    parts = url.split("://", 1)
    if len(parts) == 2:
        parts[1] = parts[1].replace(".", "[.]", 1)
        return "://".join(parts)
    return url

def defang_domain(domain: str) -> str:
    return domain.replace(".", "[.]")

def defang_ip(ip: str) -> str:
    return ip.replace(".", "[.]")


# ── Header helpers ────────────────────────────────────────────────────────────

def get_header(msg, name: str) -> str:
    val = msg.get(name, "")
    return str(val).strip()

def extract_domain_from_address(address: str) -> str:
    match = re.search(r'@([\w.\-]+)', address)
    if match:
        return match.group(1).lower()
    return ""


# ── Authentication parser ─────────────────────────────────────────────────────

def parse_authentication_results(auth_header: str) -> dict:
    results = {"spf": "missing", "dkim": "missing", "dmarc": "missing"}
    if not auth_header:
        return results
    auth_lower = auth_header.lower()
    for protocol in ["spf", "dkim", "dmarc"]:
        match = re.search(rf'{protocol}=(\w+)', auth_lower)
        if match:
            results[protocol] = match.group(1)
    return results


# ── IOC extraction ────────────────────────────────────────────────────────────

def extract_urls(text: str) -> list:
    pattern = r'https?://[^\s<>"\')\]]+'
    return list(set(re.findall(pattern, text)))

def extract_ips_from_received(received_headers: list) -> list:
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    seen, unique = set(), []
    for header in received_headers:
        for ip in re.findall(ip_pattern, header):
            if ip not in seen:
                seen.add(ip)
                unique.append(ip)
    return unique

def extract_domains_from_urls(urls: list) -> list:
    domains = set()
    for url in urls:
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            domains.add(f"{ext.domain}.{ext.suffix}")
    return list(domains)

def hash_attachment(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


# ── Lookalike / typosquatted domain detection ─────────────────────────────────

KNOWN_BRANDS = {
    "paypal": "paypal.com", "amazon": "amazon.com", "microsoft": "microsoft.com",
    "apple": "apple.com", "google": "google.com", "netflix": "netflix.com",
    "facebook": "facebook.com", "instagram": "instagram.com", "linkedin": "linkedin.com",
    "chase": "chase.com", "wellsfargo": "wellsfargo.com", "citibank": "citibank.com",
    "dropbox": "dropbox.com", "docusign": "docusign.com", "zoom": "zoom.us",
    "fedex": "fedex.com", "ups": "ups.com", "irs": "irs.gov", "dhl": "dhl.com",
    "rippling": "rippling.com",
}

HOMOGLYPHS = str.maketrans({'0':'o','1':'l','3':'e','4':'a','5':'s','6':'g','8':'b'})

def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b): return _levenshtein(b, a)
    if len(b) == 0: return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(ca != cb)))
        prev = curr
    return prev[-1]

def detect_lookalike_domains(from_addr: str, domains: list) -> list:
    findings = []
    all_domains = list(set(domains))
    from_match = re.search(r'@([\w.\-]+)', from_addr)
    if from_match:
        fd = from_match.group(1).lower()
        if fd not in all_domains:
            all_domains.append(fd)

    for domain in all_domains:
        ext = tldextract.extract(domain)
        if not ext.domain: continue
        registered  = f"{ext.domain}.{ext.suffix}".lower()
        domain_part = ext.domain.lower()

        for brand, legit in KNOWN_BRANDS.items():
            legit_domain = tldextract.extract(legit).domain.lower()
            if registered == legit: continue

            norm = domain_part.translate(HOMOGLYPHS)
            if norm == legit_domain and domain_part != legit_domain:
                findings.append(f"Lookalike domain '{registered}' resembles '{legit}' (character substitution)")
                break

            dist = _levenshtein(domain_part, legit_domain)
            if 0 < dist <= 2:
                findings.append(f"Lookalike domain '{registered}' resembles '{legit}' (edit distance {dist})")
                break

            if brand in domain_part and domain_part != legit_domain and ('-' in domain_part):
                findings.append(f"Suspicious domain '{registered}' contains brand name '{brand}' but is not '{legit}'")
                break

    return list(set(findings))


# ── Suspicious attachment analysis ───────────────────────────────────────────

DANGEROUS_EXTENSIONS = {
    '.exe','.bat','.cmd','.com','.scr','.pif','.vbs','.vbe',
    '.js','.jse','.wsf','.wsh','.ps1','.msi','.dll','.hta','.jar','.reg',
}
SUSPICIOUS_EXTENSIONS = {
    '.zip','.rar','.7z','.gz','.tar',
    '.doc','.docx','.xls','.xlsx',
    '.pdf','.iso','.img','.lnk',
}
SUSPICIOUS_FILENAMES = [
    r'invoice', r'receipt', r'payment', r'order', r'shipment',
    r'delivery', r'refund', r'statement', r'account', r'verification',
    r'password', r'credential', r'urgent', r'action.required',
]

def analyze_attachments_risk(attachments: list) -> list:
    findings = []
    for att in attachments:
        filename = att.get("filename", "unknown").lower()
        _, ext = os.path.splitext(filename)
        ext = ext.lower()

        if ext in DANGEROUS_EXTENSIONS:
            findings.append(f"Dangerous attachment '{att['filename']}' — '{ext}' files can execute code directly")
        elif ext in SUSPICIOUS_EXTENSIONS:
            for pattern in SUSPICIOUS_FILENAMES:
                if re.search(pattern, filename):
                    findings.append(f"Suspicious attachment '{att['filename']}' — '{ext}' with social engineering filename")
                    break
            else:
                if ext in {'.zip','.rar','.7z','.iso','.img','.lnk'}:
                    findings.append(f"Risky attachment '{att['filename']}' — '{ext}' files frequently used to deliver malware")
    return findings


# ── QR code (quishing) detection ─────────────────────────────────────────────

def detect_qr_codes(html_body: str, plain_body: str) -> list:
    findings = []
    combined = (html_body + " " + plain_body).lower()

    if re.search(r'<img[^>]+(src|alt)=["\'][^"\']*qr[^"\']*["\']', html_body, re.IGNORECASE):
        findings.append("QR code image detected — scanning it could redirect to a fake login portal (quishing)")

    if re.search(r'\bqr\s*code\b|\bscan\s+(the\s+)?(qr|code|barcode)\b', combined):
        findings.append("Email instructs recipient to scan a QR code — common quishing technique to bypass URL filters")

    quishing_lures = [
        r'scan\s+to\s+(verify|confirm|access|login|resolve)',
        r'scan\s+(this|the)\s+(code|qr)',
        r'use\s+your\s+camera\s+to\s+scan',
    ]
    for pattern in quishing_lures:
        if re.search(pattern, combined):
            findings.append("Quishing lure phrase detected — QR code used to redirect to malicious site")
            break

    return list(set(findings))


# ── Too-good-to-be-true detection ─────────────────────────────────────────────

TOO_GOOD_PATTERNS = [
    (r'\b(won|winner|winning)\b.{0,40}\b(lottery|prize|jackpot|million|cash)\b', "Lottery/prize scam language"),
    (r'\byou\s+have\s+(been\s+selected|won|qualified)\b', "Fake selection/winner claim"),
    (r'\b(inheritance|inherited?|estate|fortune|next\s+of\s+kin)\b', "Inheritance scam language"),
    (r'\bmillion(s)?\s+(dollar|pound|euro|usd)', "Unrealistic financial claim"),
    (r'\b(free\s+gift|claim\s+your\s+(prize|reward|gift))\b', "Fake reward/gift claim"),
    (r'\b(double|triple|10x)\s+your\s+(money|investment|bitcoin|crypto)\b', "Unrealistic investment return"),
    (r'\bguaranteed\s+(return|profit|income)\b', "Guaranteed return — hallmark of scams"),
    (r'\bcongratulations.{0,40}(selected|chosen|winner|won)\b', "Fake congratulations scam"),
]

def detect_too_good(subject: str, body: str) -> list:
    text = (subject + " " + body).lower()
    return list({label for pattern, label in TOO_GOOD_PATTERNS if re.search(pattern, text)})


# ── Urgency / pressure language ───────────────────────────────────────────────

URGENCY_PATTERNS = [
    r'\bwithin\s+\d+\s+hours?\b', r'\bwithin\s+\d+\s+days?\b',
    r'\bimmediately\b', r'\burgent(ly)?\b', r'\baction\s+required\b',
    r'\bimmediate\s+attention\b', r'\bfinal\s+notice\b', r'\blast\s+warning\b',
    r'\bexpires?\s+(today|soon|now)\b', r'\bdeadline\b',
    r'\byour\s+account\s+(will\s+be|has\s+been)\s+(suspend|terminat|disabl|block)',
    r'\bunusual\s+(activity|sign.?in|login)\b', r'\bsecurity\s+alert\b',
    r'\bverif(y|ication)\s+required\b',
    r'\bconfirm\s+your\s+(identity|account|email|password)\b',
    r'\benter\s+your\s+password\b', r'\bclick\s+here\s+(immediately|now|to\s+verify)\b',
    r'\bfailure\s+to\s+(respond|verify|confirm)\b',
    r'\byour\s+account\s+has\s+been\s+comprom',
]

def detect_urgency(subject: str, body: str) -> list:
    text = (subject + " " + body).lower()
    matches = []
    for pattern in URGENCY_PATTERNS:
        found = re.search(pattern, text)
        if found:
            matches.append(found.group(0).strip())
    return list(set(matches))


# ── Suspicious body patterns ──────────────────────────────────────────────────

def detect_body_patterns(body: str, html_body: str) -> list:
    findings = []
    body_lower = body.lower()

    if re.search(r'<form[^>]*>', html_body, re.IGNORECASE):
        if re.search(r'type=["\']password["\']', html_body, re.IGNORECASE):
            findings.append("Embedded login form with password field — legitimate emails never collect credentials")

    cred_patterns = [
        (r'\b(ssn|social security)\b', "Requests Social Security Number"),
        (r'\b(bank account|routing number)\b', "Requests bank account details"),
        (r'\bcredit card\s+(number|details)\b', "Requests credit card details"),
    ]
    for pattern, label in cred_patterns:
        if re.search(pattern, body_lower):
            findings.append(label)

    # Link text vs href mismatch
    link_pattern = re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>', html_body, re.IGNORECASE)
    for href, display_text in link_pattern:
        display_clean = display_text.strip().lower()
        if re.match(r'^[\w.\-]+\.(com|net|org|io|co)$', display_clean):
            href_ext     = tldextract.extract(href)
            display_ext  = tldextract.extract(display_clean)
            if href_ext.domain and display_ext.domain and href_ext.domain != display_ext.domain:
                findings.append(f"Link text shows '{display_clean}' but href points to '{href_ext.domain}.{href_ext.suffix}'")

    return findings


# ── Anomaly detection ─────────────────────────────────────────────────────────

def detect_anomalies(from_addr: str, return_path: str, reply_to: str) -> list:
    anomalies = []
    from_domain = extract_domain_from_address(from_addr)
    rp_domain   = extract_domain_from_address(return_path)
    rt_domain   = extract_domain_from_address(reply_to)

    if rp_domain and from_domain and from_domain != rp_domain:
        anomalies.append(f"From domain ({from_domain}) does not match Return-Path domain ({rp_domain})")

    if rt_domain and from_domain and from_domain != rt_domain:
        anomalies.append(f"From domain ({from_domain}) does not match Reply-To domain ({rt_domain})")

    display_name_match = re.match(r'^"?([^<"]+)"?\s*<', from_addr)
    if display_name_match:
        display_name = display_name_match.group(1).strip().lower()
        for brand in KNOWN_BRANDS:
            if brand in display_name and brand not in from_domain:
                anomalies.append(
                    f"Possible display-name spoofing: '{display_name_match.group(1).strip()}' "
                    f"but sending domain is {from_domain}"
                )
                break
    return anomalies


# ── Attachment extractor ──────────────────────────────────────────────────────

def extract_attachments(msg) -> list:
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename() or "unknown"
            payload  = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": filename,
                "sha256":   hash_attachment(payload),
                "size":     len(payload),
            })
    return attachments


# ── Main entry point ──────────────────────────────────────────────────────────

def analyze(raw_bytes: bytes) -> dict:
    result = {
        "error": None, "headers": {}, "authentication": {},
        "anomalies": [], "urgency": [], "body_patterns": [],
        "lookalike_domains": [], "attachment_risks": [],
        "qr_codes": [], "too_good": [],
        "iocs": {
            "urls": [], "urls_defanged": [], "domains": [], "domains_defanged": [],
            "ips": [], "ips_defanged": [], "attachments": [],
        },
        "received_chain": [], "verdict": None,
    }

    try:
        msg = email.message_from_bytes(raw_bytes)
    except Exception as e:
        result["error"] = f"Failed to parse email: {e}"
        return result

    # 1. Key headers
    result["headers"] = {
        "from":        get_header(msg, "From"),
        "reply_to":    get_header(msg, "Reply-To"),
        "return_path": get_header(msg, "Return-Path"),
        "to":          get_header(msg, "To"),
        "subject":     get_header(msg, "Subject"),
        "date":        get_header(msg, "Date"),
        "message_id":  get_header(msg, "Message-ID"),
    }

    # 2. Received chain
    result["received_chain"] = msg.get_all("Received") or []

    # 3. Authentication
    result["authentication"] = parse_authentication_results(
        get_header(msg, "Authentication-Results")
    )

    # 4. Anomalies
    result["anomalies"] = detect_anomalies(
        result["headers"]["from"],
        result["headers"]["return_path"],
        result["headers"]["reply_to"],
    )

    # 5. Build body parts
    plain_body = ""
    html_body  = ""
    for part in msg.walk():
        ct = part.get_content_type()
        try:
            decoded = part.get_payload(decode=True).decode(errors="replace")
        except Exception:
            decoded = ""
        if ct == "text/plain":
            plain_body += decoded
        elif ct == "text/html":
            html_body += decoded

    full_body = plain_body + " " + re.sub(r'<[^>]+>', ' ', html_body)

    # 6. IOC extraction
    urls        = extract_urls(plain_body + " " + html_body)
    domains     = extract_domains_from_urls(urls)
    ips         = extract_ips_from_received(result["received_chain"])
    attachments = extract_attachments(msg)

    result["iocs"]["urls"]             = urls
    result["iocs"]["urls_defanged"]    = [defang_url(u) for u in urls]
    result["iocs"]["domains"]          = domains
    result["iocs"]["domains_defanged"] = [defang_domain(d) for d in domains]
    result["iocs"]["ips"]              = ips
    result["iocs"]["ips_defanged"]     = [defang_ip(ip) for ip in ips]
    result["iocs"]["attachments"]      = attachments

    subject = result["headers"]["subject"]

    # 7. All new detections
    result["urgency"]           = detect_urgency(subject, full_body)
    result["body_patterns"]     = detect_body_patterns(full_body, html_body)
    result["lookalike_domains"] = detect_lookalike_domains(result["headers"]["from"], domains)
    result["attachment_risks"]  = analyze_attachments_risk(attachments)
    result["qr_codes"]          = detect_qr_codes(html_body, plain_body)
    result["too_good"]          = detect_too_good(subject, full_body)

    return result