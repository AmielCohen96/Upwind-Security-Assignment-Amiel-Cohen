# Part 1 — PenguWave Email Scanner (Gmail Add-on)

A Gmail sidebar add-on that reads the currently open email and assigns it a
**maliciousness score from 0 to 100** with a plain-English verdict and a list
of the signals that influenced the result.

---

## What It Does

When you open any email, the PenguWave panel appears in Gmail's right sidebar.
It runs a set of checks — both local and via Google's Safe Browsing API — and
shows you:

- **Score / 100** — higher is safer
- **Verdict** — Safe ✓ / Suspicious ⚠ / Malicious ✗
- **Signal list** — exactly which checks fired and why
- **Scan history** — your last three analysed emails at a glance
- **Block / Unblock** — a one-tap personal sender blocklist

---

## Implemented Features

| Feature | Description |
|---------|-------------|
| **14-signal scoring engine** | Combination of structural, heuristic, and reputation-based checks (see Signal Table below) |
| **Confidence-Tiered Architecture** | Prevents false positives by only applying weak signals when strong structural signals are also present |
| **Safe Browsing integration** | All URLs extracted from the email body are checked against Google's threat database in a single batched API call |
| **6-hour result cache** | Safe Browsing results are cached so repeated panel opens on the same email are instant |
| **Scan history** | Each scan is persisted to the user's private storage; the last 20 scans are kept and the most recent 3–5 are shown in the UI |
| **Personal blocklist** | Users can block any sender with one tap; blocked senders always score 0 / Malicious regardless of other signals |
| **HTML + plain-text URL scanning** | URLs are extracted from both the HTML `href` attributes and the plain-text body, catching links hidden behind display text |
| **ccTLD domain handling** | Domain comparisons use proper eTLD+1 extraction so `mail.company.com` and `company.com` are treated as the same entity |
| **LTR text enforcement** | All card text begins with a Unicode LTR mark to ensure correct display in Hebrew-locale Gmail |

---

## Architecture

```
Gmail (open email)
       │
       ▼
  buildAddOn(e)                    ← Gmail contextual trigger entry point
       │
       ├─► getScanHistory()        ← load previous scans before analysing
       │
       ├─► getEmailData()          ← extract subject, sender, body, URLs, attachments
       │         └─► parseHeaders()         ← Authentication-Results, Reply-To,
       │                                       Return-Path, Message-ID (RFC 2822)
       │         └─► extractUrls(plainBody) ← href attributes (Pass A)
       │         └─► extractUrls(htmlBody)  ← bare URLs + HTML entity decode (Pass B)
       │
       ├─► calculateScore(emailData)
       │         │
       │         ├─ [BLOCKLIST]            ← hard override, returns immediately
       │         │
       │         ├─ ── HIGH/MEDIUM TIER ── (deducted unconditionally)
       │         │   HOMOGLYPHS            DISPLAY_NAME_SPOOF    AUTH_FAIL
       │         │   MESSAGE_ID_MISMATCH   DOMAIN_MISMATCH       TYPOSQUATTING (sender)
       │         │   TYPOSQUATTING (URLs)  ATTACHMENT_RISK       SPELLING_ERRORS
       │         │   SUSPICIOUS_URLS       AUTH_SOFTFAIL
       │         │
       │         └─ ── LOW TIER ── (only applied when hmScore ≤ −30)
       │             BRAND_IMPERSONATION  URGENCY_LANGUAGE   URL_DOMAIN_MISMATCH
       │             SUSPICIOUS_TLD       LINK_SHORTENER
       │                    │
       │                    ▼
       │             score = clamp(100 + hmDeduction + lowDeduction, 0, 100)
       │
       ├─► saveScanHistory()       ← persist result to UserProperties
       │
       └─► CardService card rendered in Gmail sidebar
             • Email Info
             • Analysis Result (score, verdict, signals)
             • Recent Scans
             • Actions (Block / Unblock)
```

---

## Confidence-Tiered Architecture

The core design insight is that **no single weak indicator is reliable on its own**.

Consider a typical SaaS newsletter:
- Body mentions "Google Workspace" → looks like brand impersonation
- Links to `calendly.com` → external link mismatch
- Subject says "verify your settings" → urgency language

Under a naive additive model, these three signals would combine to push a
completely legitimate email into *Suspicious* or even *Malicious*. Under the
tiered model, none of these alone is a high-confidence structural signal, so
the LOW tier is never unlocked and the score stays at 100 / Safe.

**The gate condition is `hmScore ≤ −30`**, not merely `< 0`. A single mailing-list
DKIM break (AUTH_FAIL = −25) is common and should not unleash the LOW tier on
an otherwise clean email. The threshold of −30 ensures the gate only opens on
at least one high-confidence structural threat or multiple medium signals
stacking past it.

### Score formula

```
score = clamp(100 + hmDeduction + (hmDeduction ≤ −30 ? lowDeduction : 0), 0, 100)
```

### Verdict thresholds

| Score | Verdict |
|-------|---------|
| 80 – 100 | **Safe** ✓ |
| 50 – 79 | **Suspicious** ⚠ |
| 0 – 49 | **Malicious** ✗ |

A blocked sender always returns **0 / Malicious** regardless of all other signals.

---

## Security Signals

### HIGH / MEDIUM Confidence (always deducted)

| Signal | Weight | What it checks | Why it matters |
|--------|--------|---------------|----------------|
| `HOMOGLYPHS` | −40 | Non-ASCII characters in sender domain | Attackers substitute visually identical Unicode characters (e.g., Cyrillic 'а' for Latin 'a') to fake a domain. Legitimate email domains are ASCII-only by internet standards. Zero false-positive rate. |
| `DISPLAY_NAME_SPOOF` | −35 | Display name claims a known brand; sender domain doesn't belong to that brand | The display name is what you see in your inbox. Phishers set it to "PayPal Security" while sending from `random-domain.com`. |
| `AUTH_FAIL` | −25 | SPF, DKIM, or DMARC hard failure | Three email authentication standards that verify the sender is who they claim. A hard failure means the sending server or domain failed the check. |
| `AUTH_SOFTFAIL` | −12 | SPF softfail or DMARC monitoring-only policy | Weaker than a hard failure — the domain has published an authentication record but with a lenient policy. Half penalty. |
| `DOMAIN_MISMATCH` | −30 | Reply-To or Return-Path domain differs from sender domain | A classic phishing trick: the visible sender is `paypal.com` but replies go to `attacker.com`. Checked at the base-domain level to avoid false positives from subdomains. |
| `TYPOSQUATTING` (sender) | −30 | Sender domain is 1–2 characters away from a known brand | Catches look-alike domains like `paypa1.com` (paypal), `g00gle.com` (google) using Levenshtein edit distance. |
| `TYPOSQUATTING` (URLs) | −30 | Any URL in the email links to a look-alike domain | Catches the case where the sender uses Gmail but hides a malicious link like `amaz0n.com/login` in the body. |
| `MESSAGE_ID_MISMATCH` | −20 | Message-ID header domain differs from sender domain | The Message-ID is generated by the actual sending server. Phishing kits forge the `From:` header but often forget to align the Message-ID, revealing the true infrastructure. |
| `ATTACHMENT_RISK` | −20 | Executable or script file attached | File extensions like `.exe`, `.bat`, `.ps1`, `.vbs` are common malware delivery vectors. Only file metadata is inspected — no bytes are downloaded. |
| `SPELLING_ERRORS` | −10 | Specific phishing typos in body/subject | Deliberate misspellings (`acount`, `verfiy`, `passwrd`) are a classic phishing fingerprint that almost never appears in legitimate automated email. |
| `SUSPICIOUS_URLS` | −30 | Google Safe Browsing API flags a URL | All extracted URLs are sent in one batched request to Google's threat database. Results cached for 6 hours. |

### LOW Confidence (corroborating only — gate: hmScore ≤ −30)

| Signal | Weight | What it checks |
|--------|--------|---------------|
| `BRAND_IMPERSONATION` | −25 | Body/subject mentions a known brand the sender doesn't own |
| `URGENCY_LANGUAGE` | −10 | High-precision phishing phrases: "immediate action", "account suspended", "urgent action required", "verify within 24 hours" |
| `URL_DOMAIN_MISMATCH` | −10 | Email links to a domain not in the trusted whitelist |
| `SUSPICIOUS_TLD` | −15 | Sender or URL domain uses a high-abuse top-level domain (`.tk`, `.ml`, `.xyz`, etc.) |
| `LINK_SHORTENER` | −10 | Email contains a `bit.ly`, `t.co`, or similar link that hides the true destination |

---

## External APIs

### Google Safe Browsing v4

- **Endpoint**: `POST https://safebrowsing.googleapis.com/v4/threatMatches:find`
- **Checks for**: MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE
- **Free tier**: 10,000 requests/day; up to 500 URLs per request
- **Caching**: Results cached 6 hours in `CacheService` (keyed by MD5 hash of sorted URL list)
- **Graceful degradation**: If the API key is absent or the request fails, the check is skipped silently — local signals still produce a verdict

### API Key Setup

1. Enable **Safe Browsing API** in [Google Cloud Console](https://console.cloud.google.com/)
2. Create an API key restricted to the Safe Browsing API
3. In Apps Script editor: **Project Settings → Script Properties** → add `SAFE_BROWSING_API_KEY`

The key is never written to source code or logs.

### Why Safe Browsing and not VirusTotal?

VirusTotal provides richer metadata (detection ratios, 70+ engine results) but its
free API is limited to **4 requests per minute** with no batch endpoint. In Apps
Script's synchronous execution environment with a 30-second timeout, scanning even
10 URLs individually would take 150+ seconds.

Safe Browsing batches **500 URLs in one HTTP call** with a 10,000 req/day free
quota. One call covers a full email regardless of link count — the correct
architectural fit for a synchronous per-email add-on.

---

## OAuth Scopes

| Scope | Why it's needed |
|-------|----------------|
| `gmail.addons.execute` | Required for the add-on framework to run at all |
| `gmail.addons.current.message.readonly` | Access to the currently open email via the event object |
| `gmail.readonly` | Read email body, headers, and attachment metadata |
| `script.external_request` | Make HTTPS calls to the Safe Browsing API |
| `userinfo.email` | Identify the current user (required by the framework) |
| `script.storage` | Read/write blocklist and scan history via UserProperties |

---

## Setup & Deployment

1. Open [Google Apps Script](https://script.google.com) and create a new project
2. Replace `Code.gs` with `Code.js` from this directory
3. Add `appsscript.json` (**View → Show manifest file** if hidden)
4. Set `SAFE_BROWSING_API_KEY` in Script Properties
5. **Deploy → New deployment → Gmail Add-on**
6. Open Gmail, open any email — the panel appears in the right sidebar
7. Authorize the requested OAuth scopes when prompted

---

## Design Decisions & Trade-offs

### Confidence-Tiered Architecture (vs. flat additive scoring)
Flat additive models produce systematic false positives: a newsletter mentioning
a brand name + containing an external link + using the word "verify" can score
below 50 under naive subtraction. The tiered model gates the LOW signals behind
a −30 threshold, so weak signals only amplify an existing structural threat — they
can never initiate one.

### eTLD+1 domain comparison (vs. string equality)
Comparing `mail.company.com !== company.com` would flag every company that uses a
subdomain for sending and a root domain for bounces. Extracting the effective
top-level domain + one label (`company.com`) for both sides eliminates this class
of false positive. The same extraction also fixes Levenshtein SLD comparisons for
country-code TLD senders (`paypa1.co.uk` → SLD `paypa1`, not `co`).

### Word-boundary brand matching (vs. substring)
Simple `indexOf('apple')` matches "Snapple", "pineapple", "Apple". Wrapping the
check in `/(^|[^a-z])apple($|[^a-z])/i` prevents these substring collisions with
no meaningful increase in complexity.

### Scan history in UserProperties (vs. no persistence)
UserProperties is private per user, server-side, and requires no backend. Each
entry is ~200 bytes; capping at 20 entries keeps the total well under the 50 KB
per-key limit. The history is displayed in the sidebar and on the homepage card,
giving users context across sessions.

### Blocklist in UserProperties (vs. a shared backend)
The blocklist is personal and private — it should not be visible to other users of
the same deployed add-on. UserProperties is user-scoped by design and requires no
additional infrastructure.

### Safe Browsing 6-hour cache
The Safe Browsing API returns a `cacheDuration` field. Implementing client-side
caching with a 6-hour TTL eliminates repeated network calls for the same email
(e.g., closing and reopening the panel) while staying within the window where a
newly discovered phishing URL would be indexed.

### Softfail at half penalty
`spf=softfail` means the domain's SPF policy is published but not enforced
(`~all`). This is common in small-business email and is not conclusive evidence
of spoofing. A half penalty (−12) reflects this lower confidence while still
contributing to the overall picture.

### Link shorteners removed from trusted whitelist
Earlier versions whitelisted `bit.ly`, `t.co` etc. as "trusted domains". This was
inverted logic — a shortener hides the true destination and is the most opaque
link possible. They are now flagged separately as `LINK_SHORTENER` (LOW tier, −10).

---

## Precision Engineering Highlights

### Homoglyph detection
```js
/[^\x00-\x7F]/.test(senderDomain)
```
A single regex catches Unicode homograph attacks (Cyrillic 'а' for Latin 'a' etc.).
False-positive rate: zero — legitimate email domains are ASCII-only by RFC standard.

### Message-ID consistency
The `Message-ID` header is generated by the originating mail server and contains
its domain. Phishing kits routinely forge `From:` but neglect `Message-ID`,
leaving a structural inconsistency. This signal catches a real attacker mistake
that most scanners ignore.

### Typosquatting extended to URL domains
The Levenshtein check runs twice: once on the sender domain, and independently on
every URL extracted from the body. A phisher sending from `user@gmail.com` (passes
sender check) with a link to `paypa1.com/login` will be caught by the URL pass.

---

## Known Limitations

**30-second execution budget**
Apps Script add-on calls must complete within ~30 seconds. The Safe Browsing
cache eliminates latency for repeated opens; the 500-URL cap keeps the API call
within budget for even large HTML emails.

**Mailing list DKIM failure → Suspicious**
A newsletter modified in transit (mailing list footer added) will break the DKIM
signature and score 75 / Suspicious (AUTH_FAIL −25, gate not reached). The score
is accurate — the body was altered — but may surprise users who recognise the sender.

**Attachment content not inspected**
Only MIME type and filename extension are checked. Detecting macros in Office
documents would require downloading the attachment and integrating a sandbox —
outside scope.

**Levenshtein distance 2 on short brand names**
For brands with short SLDs (e.g., `apple` = 5 chars), a threshold of 2 is
relatively wide. A normalized threshold — `distance / max(len_a, len_b) ≤ 0.25` —
would scale correctly with name length and is the intended architectural fix for
future iterations.

**Scan history not displayed for the current email**
The "Recent Scans" section intentionally shows the *previous* scans, not the
current one — the current result is already displayed in the Analysis Result
section above it.

**RFC 2822 header parser robustness**
The `parseHeaders` function assumes well-formed RFC 2822 compliance. It lacks
robust defenses against deliberate header smuggling, malformed folding, or
edge-case parsing attacks.

**Card label refresh after block/unblock**
The block button label does not update in-place. Close and re-open the panel to
see the updated state.
