# Phishing Triage Analyzer

A locally hosted web app that takes a raw `.eml` email file and produces a structured triage report: who really sent it, whether it passed email authentication, what indicators (URLs, domains, IPs, attachment hashes) it contains, how those indicators score against VirusTotal threat intelligence, and an overall confidence percentage with the evidence behind it.

This is the same first-pass analysis a SOC analyst does by hand when a user reports a suspicious email. The tool turns that manual workflow into a repeatable, consistent process.

---

## Setup

**Requirements:** Python 3.10+, pip

```bash
# 1. Enter the project folder
cd ~/phishing-triage

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install flask tldextract dnspython requests python-dotenv

# 4. Add your VirusTotal API key
echo "VIRUSTOTAL_API_KEY=your_key_here" > .env

# 5. Run the app
python3 app.py
```

Then open **http://127.0.0.1:5000** in your browser.

To get a `.eml` file from Gmail: open the email → three-dot menu → Download message.
To get one from Outlook: open the email → File → Save As → .msg (then export as .eml).

---

## Usage

1. Open `http://127.0.0.1:5000`
2. Click "Choose file" and select any `.eml` file
3. Click "Analyze email"
4. The triage report renders in the browser
5. Click "Download JSON" to get the machine-readable version at `/report.json`

---

## What the tool checks

### Email authentication (SPF / DKIM / DMARC)

**SPF (Sender Policy Framework)** — checks whether the IP address that sent the email is authorised to send on behalf of the From domain. A `pass` means the sending server is listed in the domain's DNS. A `fail` or `softfail` means it isn't — the email could be spoofed.

**DKIM (DomainKeys Identified Mail)** — a cryptographic signature attached to the email by the sending server. A `pass` means the signature is valid and the message body hasn't been tampered with in transit. A `fail` or `none` means either the message was altered or the sender didn't sign it. DKIM failing when SPF passes is a stronger signal than both failing — it suggests the body was tampered with after leaving a legitimate server.

**DMARC (Domain-based Message Authentication, Reporting and Conformance)** — ties SPF and DKIM together and tells receiving servers what to do when they fail. A `pass` means at least one of SPF/DKIM passed and aligns with the From domain. A `fail` or `none` means neither aligned — this is the actual spoofing vector. `bestguesspass` is a non-standard Microsoft Exchange result meaning no DMARC record exists but the server guessed it probably passes.

**Auth clean bonus** — when all three pass simultaneously, the tool applies a -20% trust reduction to the confidence score. Verified sender identity is strong positive evidence, not just neutral.

### Header anomalies

**From vs Return-Path mismatch** — the Return-Path is where bounce messages go, set by the actual sending infrastructure. If the root domain differs from the From domain (not just a subdomain), that's suspicious. Subdomains of the same company (e.g. `rippling.com` vs `em4467.rippling.com`) are normal for bulk senders and are not flagged.

**Reply-To mismatch** — if replies go to a different domain than the From address, the attacker may be trying to harvest responses.

**Display-name spoofing** — checks if the visible name contains a known brand while the actual sending domain doesn't match. Example: `"PayPal" <attacker@evil-domain.com>`.

### Lookalike & typosquatted domains

Three detection methods applied to every domain extracted from the email:

1. **Homoglyph substitution** — normalises visually similar characters (0→o, 1→l, 3→e, 5→s) and checks if the result matches a known brand domain. Catches `paypa1.com`, `ripp1ing.com`.

2. **Levenshtein edit distance** — counts the minimum single-character changes to turn one domain into another. Flags anything within 2 edits of a known brand. Catches `micosoft.com` (1 edit), `goggle.com` (1 edit).

3. **Brand-in-hyphenated-domain** — flags domains containing a known brand name with a hyphen, like `paypal-secure.com` or `login-microsoft.net`.

### Content signals

**Urgency / pressure language** — 20 regex patterns scan the subject and body for time pressure, account threat, and credential request language. "Within 24 hours", "final notice", "your account will be suspended", "verify immediately". Scaled by count — 3+ phrases scores higher than 1-2.

**Suspicious body patterns** — detects embedded login forms with password fields (legitimate emails never collect credentials), explicit credential requests (SSN, bank account, credit card), and link text vs href mismatches where display text shows one domain but the link goes elsewhere.

**QR code / quishing** — detects QR code images in HTML, instructions to scan a code, and quishing lure phrases. QR codes are increasingly used in phishing because URL scanners can't read images — they bypass email security filters entirely.

**Scam / too-good-to-be-true language** — 8 pattern groups covering lottery and prize scams, inheritance fraud, fake selection/winner claims, unrealistic investment returns, guaranteed profits, and fake reward claims.

**Risky attachments** — two tiers:
- Dangerous (always flagged): `.exe`, `.bat`, `.ps1`, `.vbs`, `.js`, `.msi`, `.dll`, `.hta` — can execute code directly
- Suspicious (flagged when filename contains social engineering words like "invoice", "receipt", "payment"): `.zip`, `.pdf`, `.docx`, `.xlsx`, `.iso`

### Threat intelligence enrichment (VirusTotal)

Every domain extracted from the email body and every public IP from the Received chain is looked up against VirusTotal, which aggregates results from 90+ security vendors.

**Domain reputation** — malicious count from VT engines. 3+ engines = strong signal (+40%). 1-2 engines = possible false positive (+15%). 3+ suspicious = weak signal (+10%).

**Domain age** — extracted from VT's WHOIS data. Domains under 30 days old score +25% — attackers register fresh domains to avoid reputation history. Under 90 days scores +10%.

**IP reputation** — same thresholds as domain lookup, applied to public IPs from the Received chain. Private/internal IPs (192.168.x.x, 10.x.x.x, 127.x.x.x) are skipped automatically.

**Owner and country** — the Autonomous System owner and country code for each IP (e.g. "Microsoft Corporation · US") provides context on where the sending infrastructure physically lives.

Results are cached locally in the `cache/` folder so the same indicator is never queried twice, keeping usage within the free tier's 4 requests/minute limit.

### IOC defanging

All indicators in the report are defanged — `http` becomes `hxxp`, dots become `[.]` — so they can be safely pasted into tickets, Slack, or email without becoming clickable links. Raw versions are preserved in the JSON download for tools that need them.

### Risk verdict

| Verdict | Confidence | Meaning |
|---------|-----------|---------|
| LOW | 0–25% | Clean or minor signals — likely legitimate |
| MEDIUM | 26–59% | Suspicious but unconfirmed — analyst should review |
| HIGH | 60–100% | Strong phishing indicators — treat as malicious |

---

## Limitations — where the tool could be fooled

**1. Auth passes don't mean safe.**
An attacker who registers a clean-looking domain and properly configures SPF, DKIM, and DMARC will pass all three checks and earn the -20% trust bonus. The lookalike detector catches typosquatting against known brands, but a novel domain that doesn't resemble any known brand would score LOW on auth alone.

**2. VirusTotal cold-start problem.**
A domain registered yesterday has zero reputation history. Zero malicious flags doesn't mean clean — it means unknown. Established legitimate domains accumulate thousands of harmless votes over time; zero votes across all categories is itself suspicious. The tool flags completely unknown domains separately.

**3. No sandbox.**
Attachments are hashed (SHA-256) and the hash is checked against VirusTotal, but they are never opened or executed. A malicious PDF containing a zero-day exploit won't be caught if the hash isn't already in VT's database.

**4. No URL visiting.**
A phishing link hosted on a compromised legitimate website (e.g. a hacked WordPress blog) will show clean domain reputation because the domain itself is trusted. The tool extracts and defangs URLs but never visits them.

**5. English-only content detection.**
Urgency, scam, and quishing language patterns are English regex. A French or Spanish phishing email will not trigger these signals. Tested against a French LIDL phishing sample — urgency and scam patterns produced zero matches.

**6. Internal company emails.**
SPF, DKIM, and DMARC are checked at the mail server border when email arrives from outside. Emails downloaded from your own company's mailbox (sent internally within the same Exchange/Microsoft 365 tenant) may not have the `Authentication-Results` header stamped, causing all three to show as "missing" even for a fully legitimate internal email. The tool works best on externally received emails forwarded as attachments or saved directly from an external sender.

**7. Stale WHOIS data.**
VT caches WHOIS creation dates. If a domain was registered, used for phishing, and then expired (like `dtherhproblem.us` in testing), VT still shows the historical age from when it was active. The domain may no longer exist but appear old and established.

---

## Project structure

```
phishing-triage/
├── app.py              # Flask web server — upload, validate, pipeline, render
├── analyzer.py         # Core parser — headers, auth, IOCs, all detection logic
├── enrichment.py       # VirusTotal API lookups (domains + IPs) with local cache
├── scoring.py          # Confidence % scoring with per-signal weighted breakdown
├── templates/
│   ├── upload.html     # File upload form
│   └── report.html     # Triage report view
├── samples/            # Test .eml files (gitignored)
├── cache/              # VT API response cache (gitignored)
├── .env                # API keys (gitignored)
├── README.md
└── tests/
    └── test_analyzer.py
```

---

## Safety rules followed

- App binds to `127.0.0.1` only — never exposed to the network
- Uploads validated server-side: `.eml` extension, 5MB cap, binary signature check, email header sniff — never written to an executable path
- API keys stored in `.env`, gitignored — never hardcoded
- All indicators defanged in HTML output by default
- Attachments hashed in memory only — never written to disk, never opened or executed
- VT results cached locally to respect free-tier rate limits (4 req/min, 500/day)
- `debug=True` only — never deploy with this flag on a network-accessible host

---

## Future work

- Multi-language urgency and scam detection (French, Spanish, German patterns)
- Labeled test set to measure false positive / false negative rates and tune thresholds
- MITRE ATT&CK technique mapping (T1566 Phishing, T1598 Spearphishing With Attachment)
- Multi-file upload with summary risk table sorted by confidence
- Suppress missing-auth penalties for detected internal emails
- Live URL reputation check via Google Safe Browsing API
- Wiring report output format to match team triage note templates