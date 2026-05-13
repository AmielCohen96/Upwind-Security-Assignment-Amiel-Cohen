# PenguWave Email Scanner — Full Code Review

> **Scope**: `Part1-Gmail-Security-Addon/` — Google Apps Script Gmail Add-on  
> **Files covered**: `Code.js`, `appsscript.json`, `.clasp.json`, `README.md`

---

## 1. Goal

Build a **Gmail contextual add-on** that, whenever a user opens an email, automatically analyses it and produces:

- A **score from 0 to 100** (100 = clean, 0 = confirmed threat)
- A **verdict**: Safe (80–100), Suspicious (50–79), Malicious (0–49)
- A list of **human-readable signals** explaining why the score is what it is

The secondary, harder goal is **accuracy without false positives**. Legitimate business email, newsletters, and transactional mail must not be flagged. This is difficult because the same surface patterns (brand names, external links, urgency words) appear in both phishing and normal mail.

---

## 2. Files Overview

| File | Role |
|------|------|
| `Code.js` | All logic — constants, helpers, scoring engine, Gmail entry point |
| `appsscript.json` | Apps Script manifest — OAuth scopes, trigger wiring, add-on metadata |
| `.clasp.json` | Local `clasp` CLI config — maps the directory to a remote Apps Script project ID |
| `README.md` | Architecture documentation, signal table, design rationale |
| `REVIEW.md` | This file |

---

## 3. `appsscript.json` — The Manifest

```json
{
  "timeZone": "Asia/Jerusalem",
  "runtimeVersion": "V8",
  "oauthScopes": [ "...6 scopes..." ],
  "addOns": {
    "common": { "homepageTrigger": { "runFunction": "buildAddOn" } },
    "gmail":  { "contextualTriggers": [{ "unconditional": {}, "onTriggerFunction": "buildAddOn" }] }
  }
}
```

### `runtimeVersion: V8`
Without this, Apps Script uses the legacy Rhino JS engine (ES3 era). V8 enables `Array.from`, `const`, arrow functions, and modern regex features.

### `oauthScopes`
Every permission the add-on requests. Gmail enforces this list strictly — the script cannot access anything not declared here.

| Scope | Why it's needed |
|-------|----------------|
| `gmail.addons.execute` | Framework permission to run the script at all |
| `gmail.addons.current.message.readonly` | Event object access to the currently open message |
| `gmail.readonly` | `GmailApp.getMessageById()` — read body, headers, attachments |
| `script.external_request` | `UrlFetchApp.fetch()` to the Safe Browsing API |
| `userinfo.email` | Identify the current user (required by the framework) |
| `script.storage` | `PropertiesService` — blocklist and API key storage |

### Triggers
Both `homepageTrigger` (panel opened, no email selected) and `contextualTriggers` (email opened) call the same function `buildAddOn`. The function distinguishes the two cases internally by checking `e.gmail.messageId`.

### `.clasp.json`
Maps the local directory to `scriptId: 1ETr_nnEZbjsnlKj...`. Running `clasp push --force` uploads `Code.js` and `appsscript.json` to that project, replacing whatever was there.

---

## 4. `Code.js` — Architecture Overview

The file is structured in five layers:

```
┌─────────────────────────────────────────────────────────────┐
│  1. Module-level constants (weights, brand lists, domains)  │
├─────────────────────────────────────────────────────────────┤
│  2. Pure helper functions (no Gmail API, no I/O)            │
├─────────────────────────────────────────────────────────────┤
│  3. Persistence — scan history + blocklist                  │
│     (UserProperties, user-scoped and private)               │
├─────────────────────────────────────────────────────────────┤
│  4. Gmail-aware functions (email extraction, Safe Browsing) │
├─────────────────────────────────────────────────────────────┤
│  5. Entry point — buildAddOn() → calculateScore() →        │
│     CardService card                                        │
└─────────────────────────────────────────────────────────────┘
```

---

## 5. Module-level Constants

### `SCORING_WEIGHTS`

```js
var SCORING_WEIGHTS = {
  // HIGH/MEDIUM — deducted immediately
  AUTH_FAIL:            -25,
  HOMOGLYPHS:           -40,
  DISPLAY_NAME_SPOOF:   -35,
  MESSAGE_ID_MISMATCH:  -20,
  DOMAIN_MISMATCH:      -30,
  TYPOSQUATTING:        -30,
  ATTACHMENT_RISK:      -20,
  SPELLING_ERRORS:      -10,
  SUSPICIOUS_URLS:      -30,
  // LOW — corroborating only
  BRAND_IMPERSONATION:  -25,
  URGENCY_LANGUAGE:     -10,
  URL_DOMAIN_MISMATCH:  -10,
  SUSPICIOUS_TLD:       -15,
  LINK_SHORTENER:       -10
};
```

The split into HIGH/MEDIUM and LOW is a conceptual grouping — the actual tier enforcement happens in `calculateScore`. The weights reflect signal confidence: HOMOGLYPHS is −40 because it has a zero false-positive rate; URGENCY_LANGUAGE is −10 because it fires on legitimate transactional email constantly.

### `BRAND_DOMAINS`

```js
var BRAND_DOMAINS = {
  paypal: 'paypal.com', google: 'google.com', microsoft: 'microsoft.com',
  apple: 'apple.com', amazon: 'amazon.com', facebook: 'facebook.com',
  instagram: 'instagram.com', netflix: 'netflix.com', docusign: 'docusign.com',
  dropbox: 'dropbox.com', wetransfer: 'wetransfer.com'
};
```

Single source of truth consumed by three signals: `DISPLAY_NAME_SPOOF`, `BRAND_IMPERSONATION`, and `TYPOSQUATTING` (both sender and URL). Adding a new brand to this map automatically updates all three checks.

### `PERSONAL_EMAIL_PROVIDERS`
Consumer email domains (`gmail.com`, `yahoo.com`, etc.). Used to exclude senders from `BRAND_IMPERSONATION` body scanning — a Gmail user mentioning "Google" in an email is not phishing.

### `ESP_BOUNCE_DOMAINS`
Known ESP MTA/bounce domains (`amazonses.com`, `sendgrid.net`, etc.). Whitelisted in `DOMAIN_MISMATCH` (Return-Path) and `MESSAGE_ID_MISMATCH` because these services legitimately route email on behalf of clients using their own infrastructure domains.

### `LINK_SHORTENER_DOMAINS`
`bit.ly`, `t.co`, `tinyurl.com`, etc. These are explicitly **removed** from the trusted domains whitelist and flagged as a separate weak signal. A shortener hides the true destination — it must never be trusted blindly.

---

## 6. Helper Functions (Pure, No I/O)

### `levenshtein(a, b)` — Edit Distance

Standard dynamic-programming implementation. Builds an `(m+1) × (n+1)` matrix where `dp[i][j]` = minimum edit distance between the first `i` characters of `a` and the first `j` characters of `b`. Returns `dp[m][n]`.

Used exclusively by TYPOSQUATTING to compare second-level domain labels (SLDs).

**Time complexity**: O(m × n). For domain SLDs (typically 3–15 characters), this is negligible.

---

### `getBaseDomain(domain)` — eTLD+1 Extraction

```js
function getBaseDomain(domain) {
  var parts        = domain.split('.');
  var secondToLast = parts[parts.length - 2];
  var tld          = parts[parts.length - 1];
  if (parts.length >= 3 && tld.length === 2 &&
      ['co','com','net','org','gov','edu','ac'].indexOf(secondToLast) !== -1) {
    return parts.slice(-3).join('.'); // paypal.co.uk
  }
  return parts.slice(-2).join('.');   // company.com
}
```

**The most architecturally important helper.** It solves two problems that caused false positives and incorrect signal behaviour in earlier versions:

**Problem 1 — Subdomain false positives in DOMAIN_MISMATCH.**  
`notifications.company.com` sending with `Return-Path: bounce@company.com` previously triggered DOMAIN_MISMATCH because the strings were unequal. With `getBaseDomain`, both reduce to `company.com`.

**Problem 2 — Broken SLD extraction for ccTLD senders.**  
TYPOSQUATTING previously used `domain.split('.').slice(-2,-1)[0]`. For `paypa1.co.uk` this returned `co` instead of `paypa1`, making the check completely useless for any country-code TLD sender. `getBaseDomain('paypa1.co.uk')` → `paypa1.co.uk`, then `.split('.')[0]` → `paypa1`. Correct.

**Detection logic:** if the last label is a 2-letter country code AND the second-to-last label is a known SLD word (`co`, `com`, `org`, etc.), treat the last 3 labels as the base domain. Otherwise take the last 2.

| Input | Output | Scenario |
|-------|--------|---------|
| `mail.company.com` | `company.com` | Subdomain sender |
| `paypal.co.uk` | `paypal.co.uk` | Legitimate ccTLD brand |
| `paypa1.co.uk` | `paypa1.co.uk` | Typosquatted ccTLD |
| `attacker.xyz` | `attacker.xyz` | Single-level suspicious TLD |

---

### `containsBrandWord(text, brand)` — Word-Boundary Brand Match

```js
function containsBrandWord(text, brand) {
  return new RegExp('(^|[^a-z])' + brand + '($|[^a-z])', 'i').test(text);
}
```

Tests whether the brand keyword appears as a **whole word**, not as a substring of a longer word. Uses a character-class boundary `[^a-z]` rather than `\b` because `\b` treats `-` as a word boundary (so `\bapple\b` would match "apple" in "pineapple-juice").

| Input text | Brand tested | Result | Reason |
|-----------|-------------|--------|--------|
| `"PayPal Security"` | `paypal` | Match | Preceded by start-of-string |
| `"Snapple Beverages"` | `apple` | No match | `'n'` before `apple` is `[a-z]` |
| `"Pineapple Studio"` | `apple` | No match | `'e'` before `apple` is `[a-z]` |
| `"Dropboxing Fitness"` | `dropbox` | No match | `'i'` after `dropbox` is `[a-z]` |
| `"your PayPal account"` | `paypal` | Match | Space before, space after |

Used by both `DISPLAY_NAME_SPOOF` and `BRAND_IMPERSONATION`.

---

### `isSenderFromBrand(senderDomain, brandDomain)` — Legitimacy Check

```js
function isSenderFromBrand(senderDomain, brandDomain) {
  if (senderDomain === brandDomain) return true;                    // exact match
  if (senderDomain.endsWith('.' + brandDomain)) return true;        // subdomain
  var senderSld = getBaseDomain(senderDomain).split('.')[0];
  var brandSld  = brandDomain.split('.')[0];
  return senderSld === brandSld;                                     // ccTLD variant
}
```

Returns `true` when the sender legitimately belongs to the given brand. The three tiers handle:
1. `paypal.com === paypal.com` — exact match
2. `notifications.paypal.com` ends with `.paypal.com` — legitimate subdomain
3. `paypal.co.uk` SLD `paypal` === brand SLD `paypal` — legitimate ccTLD variant

Without the third tier, `paypal.co.uk` would be flagged as spoofing PayPal by both DISPLAY_NAME_SPOOF and BRAND_IMPERSONATION.

---

### `isEspDomain(domain)` — ESP Whitelist Check

```js
function isEspDomain(domain) {
  return ESP_BOUNCE_DOMAINS.some(function(esp) {
    return domain === esp || domain.endsWith('.' + esp);
  });
}
```

Membership test against the ESP whitelist. Extracted into its own function because the identical check is needed in two places: `DOMAIN_MISMATCH` (Return-Path) and `MESSAGE_ID_MISMATCH`.

---

### `extractDomain(str)` — Email Address → Domain

```js
function extractDomain(str) {
  var match = str.match(/@([^>@\s]+)/);
  return match ? match[1].toLowerCase() : null;
}
```

Regex `/@([^>@\s]+)/` captures everything after `@` up to the first `>`, `@`, or whitespace. Works on:
- `"PayPal <noreply@paypal.com>"` → `paypal.com`
- `"noreply@paypal.com"` → `paypal.com`
- `"<0100@email.amazonses.com>"` (Message-ID format) → `email.amazonses.com`

---

### `extractUrlDomain(url)` — URL → Hostname

```js
function extractUrlDomain(url) {
  var m = url.match(/^https?:\/\/([^/?#:]+)/i);
  return m ? m[1].toLowerCase() : null;
}
```

Captures the hostname portion of any HTTP/HTTPS URL, stopping before the first `/`, `?`, `#`, or `:` (port separator). Returns a pure hostname without port number.

---

### `extractEmail(str)` — Header Value → Email Address

```js
function extractEmail(str) {
  var angle = str.match(/<([^>]+)>/);
  if (angle) return angle[1].toLowerCase().trim();
  var bare = str.match(/[\w.+\-]+@[\w.\-]+\.[a-z]{2,}/i);
  return bare ? bare[0].toLowerCase() : null;
}
```

Two-pass: tries angle-bracket form first, falls back to bare address regex. Used by `isBlocked()` and `toggleBlocklist()` to normalise sender strings for blocklist comparison.

---

### `extractUrls(text)` — URL Extraction (Two-Pass)

```js
// Pass A — href attributes
var hrefRe = /href\s*=\s*"(https?:\/\/[^"]+)"|href\s*=\s*'(https?:\/\/[^']+)'|href\s*=\s*(https?:\/\/[^\s>"']+)/gi;

// Pass B — bare URLs
var bare = text.match(/https?:\/\/[^\s"<>]+/g) || [];
bare.forEach(function(url) { raw.push(url.replace(/[),.'"\]>]+$/, '')); });

// Deduplicate + decode
return Array.from(new Set(raw.map(function(u) {
  return u.replace(/&amp;/gi, '&').replace(/&#38;/gi, '&');
})));
```

**Pass A** finds URLs inside HTML `href` attributes in three delimited forms (double-quoted, single-quoted, unquoted). This catches URLs hidden behind display text like `<a href="https://evil.com">Click here</a>` — pure plain-text scanning misses these entirely.

**Pass B** finds bare `https://` URLs in plain text. The trailing `.replace(/[),.'"\]>]+$/, '')` strips punctuation that commonly trails a URL in prose (e.g., "visit https://example.com." — the period is not part of the URL).

**Entity decoding**: HTML attributes encode `&` as `&amp;`. Without decoding, `https://example.com?a=1&amp;b=2` would be submitted to Safe Browsing and fail to match the database entry for `https://example.com?a=1&b=2`. Both `&amp;` and the numeric form `&#38;` are decoded.

**Deduplication**: `Array.from(new Set(...))` removes URLs that appear in both the HTML and plain-text versions of the same email.

---

### `parseHeaders(rawContent)` — RFC 2822 Header Parsing

```js
function parseHeaders(rawContent) {
  var result = { authenticationResults: null, replyTo: null, returnPath: null, messageId: null };
  var headerBlock = rawContent.split(/\r?\n\r?\n/)[0];      // isolate header block
  var unfolded    = headerBlock.replace(/\r?\n[ \t]+/g, ' '); // unfold continuations
  var lines       = unfolded.split(/\r?\n/);
  for (var i = 0; i < lines.length; i++) { /* match and extract */ }
  return result;
}
```

RFC 2822 emails are structured as `headers\r\n\r\nbody`. Splitting on the first blank line and taking `[0]` discards the body — which can be megabytes of HTML — before any processing. This is a deliberate **security property**: `rawContent` is consumed inside this function and never returned or logged.

**Header unfolding**: long headers are split across multiple lines using `\r\n` followed by a tab or space. `Authentication-Results:` is always multi-line. The `replace(/\r?\n[ \t]+/g, ' ')` re-joins folded lines before parsing, making the regex matching reliable.

**Four headers extracted**:
| Header | Used by |
|--------|---------|
| `Authentication-Results` | `AUTH_FAIL` (SPF/DKIM/DMARC verdict) |
| `Reply-To` | `DOMAIN_MISMATCH` |
| `Return-Path` | `DOMAIN_MISMATCH` |
| `Message-ID` | `MESSAGE_ID_MISMATCH` |

Only the **first** occurrence of each header is captured. This is correct for `Authentication-Results` — the topmost instance is added by the final receiving server (the only one the recipient can trust).

**Known limitation**: `parseHeaders` assumes well-formed RFC 2822 compliance. It lacks robust defenses against deliberate header smuggling, malformed folding, or edge-case parsing attacks.

---

### `getEmailData(message)` — Structured Extraction

```js
function getEmailData(message) {
  var plainBody = message.getPlainBody();
  var htmlBody  = message.getBody();
  var headers   = parseHeaders(message.getRawContent());
  var allUrls   = Array.from(new Set(extractUrls(plainBody).concat(extractUrls(htmlBody))));
  var attachments = message.getAttachments().map(function(a) {
    return { name: a.getName(), contentType: a.getContentType() };
  });
  return { subject, sender, date, plainBody, attachments, urls, headers };
}
```

Calls the Gmail API and delegates all extraction to helpers. Key decisions:

- **Both plain and HTML body are URL-scanned.** HTML emails embed real URLs in `href` attributes behind display text. Scanning only plain text misses these — this was the attack vector in the original WeTransfer phishing test case.
- **`htmlBody` is not returned.** URL extraction happens inside `getEmailData` and only the deduplicated URL list is kept.
- **Attachments are metadata-only.** `getAttachments()` returns objects; only `getName()` and `getContentType()` are called. No bytes are ever downloaded.

---

## 7. Blocklist Functions

### `isBlocked(sender)`
Reads `BLOCKLIST` from `UserProperties` (user-scoped — each Gmail user has a private store). Deserialises the JSON array and checks membership. Uses `extractEmail()` to normalise `"Display Name <user@domain.com>"` to `user@domain.com` before comparison.

### `toggleBlocklist(e)`
Called when the user clicks Block/Unblock. The sender email is passed as a button parameter (`e.parameters.senderEmail`) set when the card was built — no message re-fetch needed. Reads the array, splices or pushes, and writes back. Returns a toast notification via `ActionResponse`. The button label does not update in-place (a Gmail Add-on limitation); the panel must be closed and re-opened.

---

## 8. Scan History Functions

Scan history is stored in `UserProperties` (user-scoped, private to each Gmail user) under the key `SCAN_HISTORY`. Each entry is a small JSON object (~200 bytes); the array is capped at 20 entries, keeping the total well under the 50 KB per-key limit.

### `relativeTime(ts)`

```js
function relativeTime(ts) {
  var diff  = Date.now() - ts;
  var mins  = Math.floor(diff / 60000);
  if (mins < 1)  return 'just now';
  if (mins < 60) return mins + 'm ago';
  var hours = Math.floor(mins / 60);
  if (hours < 24) return hours + 'h ago';
  return Math.floor(hours / 24) + 'd ago';
}
```

Converts a Unix millisecond timestamp to a short human-readable string: `"just now"`, `"5m ago"`, `"2h ago"`, `"3d ago"`. Used when rendering history in the card UI.

### `getScanHistory()`

Reads `SCAN_HISTORY` from `UserProperties`, parses it as JSON, and returns an array (newest-first). Returns `[]` on missing key or parse failure — both are valid first-use states.

### `saveScanHistory(emailData, result)`

Prepends the current scan as a new entry and writes the array back, capped at 20 entries:

```js
history.unshift({
  ts:      new Date().getTime(),
  sender:  emailData.sender,
  subject: (emailData.subject || '(no subject)').slice(0, 60),
  score:   result.finalScore,
  verdict: result.verdict
});
PropertiesService.getUserProperties()
  .setProperty('SCAN_HISTORY', JSON.stringify(history.slice(0, 20)));
```

Called **after** `calculateScore()` completes so the current email is not included in the "Recent Scans" display — it is already shown in the Analysis Result section.

### `formatHistory(history, limit)`

```js
function formatHistory(history, limit) {
  if (!history || history.length === 0) return '‎No previous scans yet.';
  return history.slice(0, limit).map(function (h) {
    var icon = h.verdict === 'Safe' ? '✓' : h.verdict === 'Suspicious' ? '⚠' : '✗';
    return '‎' + icon + ' ' + h.score + '/100  ' + relativeTime(h.ts) + '\n   ' + h.sender.slice(0, 45);
  }).join('\n');
}
```

Renders a compact multi-line summary. Each line shows verdict emoji, score, relative timestamp, and truncated sender. The email card shows the last 3 previous scans; the homepage card shows the last 5. Every string begins with `‎` (U+200E) for LTR alignment.

---

## 9. `checkSafeBrowsing(urls)` — External API

```
checkSafeBrowsing(urls)
  │
  ├── Guard: empty URL list → return [] (saves latency for text-only emails)
  ├── Guard: missing API key → return [] (graceful degradation)
  │
  ├── Build cache key: MD5(sorted URLs joined by '|') → base64 → prefix 'sb_'
  ├── Cache hit? → return JSON.parse(cached)
  │
  └── POST to https://safebrowsing.googleapis.com/v4/threatMatches:find
          payload: { threatTypes: [MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE],
                     threatEntries: urls.slice(0, 500) }
          muteHttpExceptions: true
          │
          ├── HTTP != 200 → log error, return []
          └── Parse matches → deduplicate URLs → cache(6h) → return
```

**Cache key design**: URLs are sorted before hashing so order doesn't affect the key. MD5 produces 16 bytes; base64-encoded that is 24 characters, well within `CacheService`'s 250-byte key limit.

**`muteHttpExceptions: true`**: without this flag a non-200 response throws an unhandled exception that crashes `buildAddOn`. With it, the error is returned as a response object and checked via `getResponseCode()`.

**API key security**: `SAFE_BROWSING_API_KEY` is read from Script Properties (script-scoped) and never written to source code, logs, or return values.

**6-hour TTL**: phishing campaign URLs don't become benign within 6 hours. The TTL also matches typical Safe Browsing `cacheDuration` return values.

---

## 10. `calculateScore(emailData)` — The Scoring Engine

### Architecture: Confidence-Tiered Model

```
hmScore    = 0   ← HIGH/MEDIUM accumulator
lowScore   = 0   ← LOW accumulator
hmSignals  = []
lowSignals = []

[Evaluate all HIGH/MEDIUM signals → accumulate into hmScore + hmSignals]
[Evaluate all LOW signals → accumulate into lowScore + lowSignals]

Gate: hmScore <= -30 ?
  YES → score = 100 + hmScore + lowScore   (both tiers applied)
  NO  → score = 100 + hmScore              (LOW signals suppressed)
```

**Why −30 and not 0?**  
Mailing lists frequently break DKIM (AUTH_FAIL = −25) or trigger softfail (−12). A lone authentication failure on a newsletter should not unlock the LOW tier. A threshold of −30 means the gate opens only on at least one high-confidence structural signal (DISPLAY_NAME_SPOOF −35, DOMAIN_MISMATCH −30, TYPOSQUATTING −30) or multiple medium signals stacking past the threshold.

### HIGH/MEDIUM Signals (in evaluation order)

#### HOMOGLYPHS (−40)
```js
if (senderDomain && /[^\x00-\x7F]/.test(senderDomain))
```
Any non-ASCII character in the sender domain. RFC 5321 requires ASCII-only domain names. A domain using Cyrillic `а` (U+0430) instead of Latin `a` is pixel-identical to the eye but instantly detectable here. **Zero false-positive rate.**

#### AUTH_FAIL (−25) and AUTH_SOFTFAIL (−12)
```js
var authHardfail = auth.indexOf('spf=fail') !== -1 || auth.indexOf('dkim=fail') !== -1 || ...
var authSoftfail = !authHardfail && (auth.indexOf('spf=softfail') !== -1 || auth.indexOf('dmarc=none') !== -1);
```
Hard failure (−25): definitive server-side verdict that the email failed authentication.  
Softfail (−12, half penalty): the sending domain's policy is weak but not conclusive — common in misconfigured small businesses. The two are mutually exclusive; hardfail always takes precedence.

#### DISPLAY_NAME_SPOOF (−35)
```js
containsBrandWord(displayName, brand) && !isSenderFromBrand(senderDomain, BRAND_DOMAINS[brand])
```
Display name claims to be a known brand (word-boundary match) but the actual sender domain does not belong to that brand. `isSenderFromBrand()` handles exact matches, subdomains, and ccTLD variants (paypal.co.uk) to avoid false positives.

#### MESSAGE_ID_MISMATCH (−20)
```js
getBaseDomain(messageIdDomain) !== senderBaseDomain && !isEspDomain(messageIdDomain)
```
The `Message-ID` header contains the originating MTA's domain (`<unique@sendingdomain.com>`). Phishing kits routinely forge `From:` but neglect `Message-ID`, revealing the true infrastructure. Legitimate ESP MTAs (SES, SendGrid) are whitelisted.

#### DOMAIN_MISMATCH (−30)
```js
getBaseDomain(replyToDomain) !== senderBaseDomain          // Reply-To mismatch
getBaseDomain(returnPathDomain) !== senderBaseDomain && !isEspDomain(returnPathDomain)  // Return-Path mismatch
```
Compares **base domains (eTLD+1)** — not full hostnames. This means `mail.company.com` and `company.com` are treated as the same entity, eliminating the false positive where a company uses a subdomain for sending and a root domain for bounces. ESP Return-Path domains are whitelisted separately.

#### TYPOSQUATTING — Sender Domain (−30)
```js
senderStem = getBaseDomain(senderDomain).split('.')[0]
// For each brand:
brandStem = brandDomain.split('.')[0]
if (senderStem === brandStem) skip;  // ccTLD variant (paypal.co.uk)
if (levenshtein(senderStem, brandStem) <= 2) → fire
```
Levenshtein distance ≤ 2 between the sender's SLD and each known brand's SLD. `getBaseDomain()` ensures ccTLD senders (`paypa1.co.uk`) are correctly parsed — their SLD is `paypa1`, not `co`. Exact SLD matches are skipped (handled by SUSPICIOUS_TLD for wrong-TLD variants like `paypal.xyz`). Personal providers excluded.

#### TYPOSQUATTING — URL Domains (−30, independent)
```js
emailData.urls.some(function(url) {
  urlStem = getBaseDomain(extractUrlDomain(url)).split('.')[0]
  if (penalizedTyposquatStem && urlStem === penalizedTyposquatStem) return false; // dedup
  // same Levenshtein check as sender
})
```
Extends typosquatting detection to every URL in the email body. Modern phishing often uses a legitimate freemail sender (`user@gmail.com` — passes sender check) with a typosquatted link (`paypa1.com/login`). This pass catches that vector. Can fire independently of the sender-domain check, **but** is skipped for any URL whose SLD was already penalized by the sender check — preventing a double-jeopardy −60 deduction when sender and link share the same typosquatted domain (e.g., `paypa1.com` sender + `paypa1.com` link = −30 total, not −60).

#### ATTACHMENT_RISK (−20)
Checks attachment MIME type against a list and filename extension against `/\.(exe|bat|js|vbs|ps1|sh|cmd|scr|jar|msi)$/i`. **Only metadata is inspected — bytes are never downloaded.**

#### SPELLING_ERRORS (−10)
Fixed list of 10 specific phishing typos (`acount`, `updaet`, `securty`, `passwrd`, `verfiy`, `suspendd`, `loginng`, `veryfication`, `authorizaton`, `urgant`). These are precise enough to have near-zero false-positive rate on legitimate automated email.

#### SUSPICIOUS_URLS / Safe Browsing (−30)
Network call, always evaluated last in the HIGH/MEDIUM tier. Skipped if `emailData.urls.length === 0`. Results cached 6 hours. Gracefully degraded — a missing API key or network failure returns `[]` and scoring continues normally.

---

### LOW Signals (corroborating only, gate: hmScore <= −30)

#### BRAND_IMPERSONATION (−25)
Body or subject contains a brand keyword (word-boundary match) while sender domain doesn't belong to that brand. Personal providers excluded. High false-positive rate in isolation — legitimate newsletters constantly mention brands. Only meaningful as corroboration of a structural threat.

#### URGENCY_LANGUAGE (−10)
**High-precision keyword list only**: `'immediate action'`, `'account suspended'`, `'urgent action required'`, `'verify within 24 hours'`. Generic terms like `"verify"` and `"password"` were removed because they appear constantly in legitimate transactional email (registration flows, password resets, order confirmations).

#### URL_DOMAIN_MISMATCH (−10) + LINK_SHORTENER (−10)
Evaluated in a single URL loop. Each URL is classified as:
1. **Shortener** (e.g., `bit.ly`) → LINK_SHORTENER signal; shorteners are opaque and must not be trusted.
2. **Same base domain as sender** → ignored (legitimate).
3. **In trusted whitelist** → ignored.
4. **Everything else** → LINK_SHORTENER or URL_DOMAIN_MISMATCH.

Trusted whitelist covers ~30 major CDNs, ESPs, and SaaS platforms. Shorteners are explicitly absent from the whitelist.

#### SUSPICIOUS_TLD (−15)
High-abuse free TLDs (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz`, `.top`, `.click`, `.pw`, `.rest`, `.icu`, `.monster`). Applied to both sender domain and all URL domains. `.live` and `.work` intentionally excluded — Microsoft and live-streaming services use `.live` legitimately.

---

### Tier Combination

```js
var appliedLowScore   = hmScore <= -30 ? lowScore   : 0;
var appliedLowSignals = hmScore <= -30 ? lowSignals : [];
var allSignals        = hmSignals.concat(appliedLowSignals);
var score = Math.max(0, Math.min(100, 100 + hmScore + appliedLowScore));
var verdict = score >= 80 ? 'Safe' : score >= 50 ? 'Suspicious' : 'Malicious';
```

Only signals that contributed to the score are shown to the user (`allSignals`). When LOW signals are suppressed, they are simply not displayed — the card shows only the HIGH/MEDIUM findings.

---

## 11. `buildAddOn(e)` — Gmail Entry Point

```
buildAddOn(e)
  │
  ├── previousHistory = getScanHistory()
  │       Loaded BEFORE scoring so "Recent Scans" shows previous emails,
  │       not the one currently being analysed
  │
  ├── !e.gmail.messageId? → return homepage card
  │       Shows placeholder text + formatHistory(previousHistory, 5)
  │
  ├── setCurrentMessageAccessToken(e.gmail.accessToken)
  │       Required before getMessageById() — grants access to the specific message
  │
  ├── getEmailData(message) → emailData
  ├── calculateScore(emailData) → { finalScore, signals, verdict }
  ├── saveScanHistory(emailData, result)
  │       Persisted AFTER scoring
  │
  ├── console.log({ subject, sender, urlCount, headers, scoreResult })
  │       Never logs rawContent or body
  │
  └── CardService card (4 sections):
        1. Email Info:      From / Subject / Date (Asia/Jerusalem timezone)
        2. Analysis Result: Score / Verdict / Signal bullets
        3. Recent Scans:    formatHistory(previousHistory, 3)
        4. Actions:         Block/Unblock Sender button
```

**LTR enforcement**: Every `setText()` string begins with `‎` (Unicode U+200E, Left-to-Right Mark). The Gmail interface is Hebrew-locale, which renders RTL by default. The LTR mark instructs the bidirectional text algorithm to render the paragraph left-to-right.

**`setCurrentMessageAccessToken`**: The `accessToken` in the event object is a short-lived OAuth token scoped to the one currently open message. Without calling this first, `getMessageById` throws an authorisation error.

**Verdict labels**: `'Safe ✓'`, `'Suspicious ⚠'`, `'Malicious ✗'` — emoji provide instant visual scanning without needing to read the word.

---

## 12. End-to-End Code Flow

```
User opens an email in Gmail
       │
       ▼ Gmail fires contextualTrigger
buildAddOn(e)
       │
       ├── getScanHistory() → previousHistory
       │       Loaded first so the card shows previous scans, not current email
       │
       ├── e.gmail undefined? → homepage card (shows previousHistory last 5)
       │
       ├── setCurrentMessageAccessToken(e.gmail.accessToken)
       │
       ├── getEmailData(GmailApp.getMessageById(e.gmail.messageId))
       │       ├── getPlainBody()          → keyword + URL scan input
       │       ├── getBody()               → href URL extraction
       │       ├── parseHeaders(getRawContent())
       │       │       ├── split on first blank line (discard body)
       │       │       ├── unfold continuation lines
       │       │       └── extract: Authentication-Results, Reply-To,
       │       │                    Return-Path, Message-ID
       │       ├── extractUrls(plainBody) + extractUrls(htmlBody)
       │       │       ├── Pass A: href="..." regex (3 delimiter variants)
       │       │       ├── Pass B: bare https:// regex
       │       │       └── deduplicate, decode &amp;
       │       └── getAttachments() → [{ name, contentType }] (no bytes)
       │
       ├── calculateScore(emailData)
       │       │
       │       ├── isBlocked()? → 0/Malicious immediately
       │       │
       │       ├── ── HIGH/MEDIUM TIER (local) ──────────────────────────
       │       │   HOMOGLYPHS          /[^\x00-\x7F]/ on sender domain
       │       │   AUTH_FAIL           spf/dkim/dmarc=fail in Auth-Results
       │       │   AUTH_SOFTFAIL       spf=softfail / dmarc=none (½ penalty)
       │       │   DISPLAY_NAME_SPOOF  containsBrandWord + !isSenderFromBrand
       │       │   MESSAGE_ID_MISMATCH getBaseDomain(msgId) ≠ senderBase
       │       │   DOMAIN_MISMATCH     getBaseDomain(replyTo/returnPath) ≠ senderBase
       │       │   TYPOSQUATTING       levenshtein(senderStem, brandStem) ≤ 2
       │       │   TYPOSQUATTING (URL) same check on every URL domain
       │       │   ATTACHMENT_RISK     MIME type + filename extension
       │       │   SPELLING_ERRORS     10-word phishing typo list
       │       │
       │       ├── ── HIGH/MEDIUM TIER (network) ────────────────────────
       │       │   SUSPICIOUS_URLS     Safe Browsing API (cached 6h, skipped if no URLs)
       │       │
       │       ├── ── LOW TIER (always evaluated) ───────────────────────
       │       │   BRAND_IMPERSONATION  containsBrandWord in body/subject
       │       │   URGENCY_LANGUAGE     4 high-precision phishing phrases
       │       │   URL_DOMAIN_MISMATCH  external links vs trusted whitelist
       │       │   LINK_SHORTENER       bit.ly / t.co etc.
       │       │   SUSPICIOUS_TLD       .tk / .ml / .xyz etc.
       │       │
       │       └── Tier gate (hmScore <= -30?):
       │               YES → score = 100 + hmScore + lowScore
       │               NO  → score = 100 + hmScore
       │               clamp to [0, 100]
       │               verdict: ≥80 Safe, ≥50 Suspicious, else Malicious
       │
       ├── saveScanHistory(emailData, result)
       │       Persisted after scoring; capped at 20 entries in UserProperties
       │
       └── CardService.newCardBuilder()
               ├── Section "Email Info":      sender, subject, date
               ├── Section "Analysis Result": score, verdict, signal bullets
               ├── Section "Recent Scans":    formatHistory(previousHistory, 3)
               └── Section "Actions":         Block/Unblock button
                       → rendered in Gmail right sidebar
```

---

## 13. Worked Examples

### Example A — Legitimate SaaS Newsletter (must be Safe)

```
From: Updates <news@saas-company.com>
Subject: Verify your Google Workspace settings
Body: "...link to calendly.com... immediately take action..."
```

| Signal | Fires? | Why |
|--------|--------|-----|
| HOMOGLYPHS | No | ASCII domain |
| AUTH_FAIL | No | Properly signed |
| DISPLAY_NAME_SPOOF | No | "Updates" contains no brand keyword |
| MESSAGE_ID_MISMATCH | No | Message-ID from saas-company.com |
| DOMAIN_MISMATCH | No | No mismatched headers |
| TYPOSQUATTING (sender) | No | "saas-company" is not close to any brand |
| TYPOSQUATTING (URL) | No | calendly.com is not close to any brand |
| ATTACHMENT_RISK | No | No attachments |
| SPELLING_ERRORS | No | No phishing typos |
| SUSPICIOUS_URLS | No | calendly.com is not flagged |
| **hmScore = 0** | | Gate threshold not reached |
| BRAND_IMPERSONATION | Would fire | "google" in body |
| URGENCY_LANGUAGE | Would fire | "immediately" isn't in new precise list |
| URL_DOMAIN_MISMATCH | Would fire | calendly.com not in whitelist |
| **Gate: 0 > −30** | LOW suppressed | |
| **Score: 100 / Safe** | ✓ | |

### Example B — PayPal Phishing (must be Malicious)

```
From: PayPal Security <security@paypa1.com>
Authentication-Results: spf=fail
Message-ID: <abc@attacker-infra.net>
Body: "verify your paypal acount — immediate action required"
Link: https://paypa1.com/login
```

| Signal | Fires? | Deduction |
|--------|--------|-----------|
| AUTH_FAIL | Yes | −25 |
| DISPLAY_NAME_SPOOF | Yes | −35 |
| MESSAGE_ID_MISMATCH | Yes | −20 |
| TYPOSQUATTING (sender) | Yes (`paypa1` → `paypal`, dist 1) | −30 |
| TYPOSQUATTING (URL) | Skipped — same SLD as sender (dedup) | 0 |
| SPELLING_ERRORS | Yes (`acount`) | −10 |
| **hmScore = −120** | Gate: −120 ≤ −30 ✓ | LOW unlocked |
| BRAND_IMPERSONATION | Yes | −25 |
| URGENCY_LANGUAGE | Yes (`immediate action`) | −10 |
| **Total: 100 − 120 − 35 = −55** → clamped | **0 / Malicious** | ✓ |

### Example C — Mailing List Newsletter (DKIM broken, must be Suspicious not Malicious)

```
From: Dev Digest <digest@devdigest.io>
Authentication-Results: dkim=fail (mailing list footer modified body)
Body: "Top 10 AWS services this week..."
```

| Signal | Fires? | Deduction |
|--------|--------|-----------|
| AUTH_FAIL | Yes | −25 |
| (all others) | No | |
| **hmScore = −25** | Gate: −25 > −30 → LOW suppressed | |
| **Score: 75 / Suspicious** | Correctly flagged as Suspicious, not Malicious | |

The score is 75 (Suspicious) rather than Safe because AUTH_FAIL is a genuine structural finding — the body was modified in transit. But the LOW tier is suppressed, preventing a false Malicious verdict. The Suspicious rating appropriately prompts the user to review rather than auto-blocking.

---

## 14. Design Philosophy

The engine is built around one core insight:

> **No low-confidence signal is a reliable standalone indicator of phishing.**

An additive penalty model that subtracts points for every weak signal produces systematic false positives on legitimate email. The Confidence-Tiered Architecture enforces mathematically that LOW signals cannot generate a verdict on their own — they amplify an existing structural threat but cannot initiate one.

The HIGH/MEDIUM tier consists only of signals where the **structure** of the email itself is wrong:
- Non-ASCII in a domain (should be impossible in legitimate mail)
- Authentication failure from the receiving server
- Display name claims a brand the actual domain doesn't own
- Message-ID generated by a different infrastructure than the sender claims
- Reply/bounce paths routing to unrelated domains
- Sender or URL domain that is a typo-variant of a known brand

These are things a legitimate email does not do by accident. When they are absent, LOW signals are silenced regardless of how many of them fire — and legitimate email is scored accurately.
