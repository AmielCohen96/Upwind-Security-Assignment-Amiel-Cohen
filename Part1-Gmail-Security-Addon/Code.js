// ─── Signal Weights ────────────────────────────────────────────────────────────
//
// Confidence-Tiered Architecture:
//   HIGH/MEDIUM signals deduct from the score immediately.
//   LOW signals only apply when at least one HIGH/MEDIUM signal has already fired,
//   acting as corroborating evidence rather than standalone triggers.
//
//   This prevents a legitimate SaaS newsletter (mentioning "Google Workspace",
//   linking to Calendly, saying "verify your settings") from being flagged
//   as Malicious — none of those alone are HIGH/MEDIUM signals.

var SCORING_WEIGHTS = {
  // ── HIGH / MEDIUM confidence — deducted immediately ──────────────────────
  AUTH_FAIL:            -25,   // SPF/DKIM/DMARC failure from receiving server
  HOMOGLYPHS:           -40,   // Non-ASCII chars in sender domain (0 FP rate)
  DISPLAY_NAME_SPOOF:   -35,   // Display name claims a brand; domain does not
  MESSAGE_ID_MISMATCH:  -20,   // Message-ID domain differs from sender base domain
  DOMAIN_MISMATCH:      -30,   // Reply-To or Return-Path base domain mismatch
  TYPOSQUATTING:        -30,   // Sender SLD within Levenshtein-2 of a brand SLD
  ATTACHMENT_RISK:      -20,   // Executable or script attachment
  SPELLING_ERRORS:      -10,   // Classic phishing typos in body/subject
  SUSPICIOUS_URLS:      -30,   // Google Safe Browsing positive match

  // ── LOW confidence — corroborating only ──────────────────────────────────
  BRAND_IMPERSONATION:  -25,   // Body mentions a brand the sender doesn't own
  URGENCY_LANGUAGE:     -10,   // Phishing pressure-tactic keywords
  URL_DOMAIN_MISMATCH:  -10,   // External links not in trusted whitelist
  SUSPICIOUS_TLD:       -15,   // High-abuse TLD on sender or URL domain
  LINK_SHORTENER:       -10    // Opaque shortener hides the true destination
};

// Known brands → canonical sender domain.
// Single source of truth for DISPLAY_NAME_SPOOF, BRAND_IMPERSONATION, TYPOSQUATTING.
var BRAND_DOMAINS = {
  paypal:     'paypal.com',
  google:     'google.com',
  microsoft:  'microsoft.com',
  apple:      'apple.com',
  amazon:     'amazon.com',
  facebook:   'facebook.com',
  instagram:  'instagram.com',
  netflix:    'netflix.com',
  docusign:   'docusign.com',
  dropbox:    'dropbox.com',
  wetransfer: 'wetransfer.com'
};

// Personal/consumer providers excluded from BRAND_IMPERSONATION body scanning.
var PERSONAL_EMAIL_PROVIDERS = [
  'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk',
  'hotmail.com', 'hotmail.co.uk', 'outlook.com', 'live.com',
  'icloud.com', 'me.com', 'protonmail.com', 'aol.com', 'mail.com'
];

// ESP bounce/routing domains — whitelisted in DOMAIN_MISMATCH and MESSAGE_ID_MISMATCH.
// These services legitimately use their own domains for bounce tracking.
var ESP_BOUNCE_DOMAINS = [
  'amazonses.com', 'sendgrid.net', 'mailgun.org',
  'rs.campaign-monitor.com', 'bounces.amazon.com',
  'exacttarget.com', 'mailchimp.com'
];

// URL shorteners are opaque by design and must NOT be trusted.
// Intentionally absent from trustedDomains; flagged as LINK_SHORTENER instead.
var LINK_SHORTENER_DOMAINS = [
  'bit.ly', 't.co', 'ow.ly', 'buff.ly', 'tinyurl.com', 'rb.gy', 'short.io'
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Standard DP Levenshtein edit distance.
 */
function levenshtein(a, b) {
  var m = a.length, n = b.length;
  var dp = [];
  for (var i = 0; i <= m; i++) {
    dp[i] = [i];
    for (var j = 1; j <= n; j++) {
      dp[i][j] = i === 0 ? j :
        a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] :
        1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

/**
 * Returns the effective base domain (eTLD+1) of a hostname.
 *
 * Handles country-code second-level domains (.co.uk, .com.au, .co.il, etc.)
 * so that mail.company.com and company.com share the same base domain,
 * and paypal.co.uk is correctly identified as a 3-part ccTLD domain.
 *
 * @param {string} domain
 * @returns {string|null}
 */
function getBaseDomain(domain) {
  if (!domain) return null;
  var parts = domain.split('.');
  if (parts.length < 2) return domain;
  // Detect ccSLD patterns: the second-to-last label is a short word AND
  // the last label is a 2-letter country code (e.g. co.uk, com.au, co.il).
  var secondToLast = parts[parts.length - 2];
  var tld          = parts[parts.length - 1];
  if (parts.length >= 3 && tld.length === 2 &&
      ['co', 'com', 'net', 'org', 'gov', 'edu', 'ac'].indexOf(secondToLast) !== -1) {
    return parts.slice(-3).join('.');  // e.g. mail.paypal.co.uk → paypal.co.uk
  }
  return parts.slice(-2).join('.');    // e.g. mail.company.com → company.com
}

/**
 * Tests whether text contains a brand name as a whole word.
 * Prevents "Snapple" from matching "apple" or "Dropboxing" from matching "dropbox".
 * Uses character-class boundaries instead of lookbehind for broadest V8 compatibility.
 *
 * @param {string} text
 * @param {string} brand  — lowercase brand keyword
 * @returns {boolean}
 */
function containsBrandWord(text, brand) {
  return new RegExp('(^|[^a-z])' + brand + '($|[^a-z])', 'i').test(text);
}

/**
 * Returns true when senderDomain legitimately belongs to brandDomain.
 * Accepts exact match, subdomain, and ccTLD variants (paypal.co.uk vs paypal.com).
 *
 * @param {string|null} senderDomain
 * @param {string}      brandDomain   — e.g. 'paypal.com'
 * @returns {boolean}
 */
function isSenderFromBrand(senderDomain, brandDomain) {
  if (!senderDomain) return false;
  if (senderDomain === brandDomain) return true;
  if (senderDomain.endsWith('.' + brandDomain)) return true;
  // ccTLD variant: paypal.co.uk → SLD 'paypal' matches brand SLD 'paypal'
  var senderSld = getBaseDomain(senderDomain).split('.')[0];
  var brandSld  = brandDomain.split('.')[0];
  return senderSld === brandSld;
}

/**
 * Returns true if domain is a known ESP bounce/routing domain.
 *
 * @param {string|null} domain
 * @returns {boolean}
 */
function isEspDomain(domain) {
  if (!domain) return false;
  return ESP_BOUNCE_DOMAINS.some(function (esp) {
    return domain === esp || domain.endsWith('.' + esp);
  });
}

/**
 * Extracts the domain portion from an email address or angle-bracket header value.
 * @param {string} str
 * @returns {string|null}
 */
function extractDomain(str) {
  if (!str) return null;
  var match = str.match(/@([^>@\s]+)/);
  return match ? match[1].toLowerCase() : null;
}

/**
 * Extracts the hostname from an HTTP/HTTPS URL, excluding port numbers.
 * @param {string} url
 * @returns {string|null}
 */
function extractUrlDomain(url) {
  if (!url) return null;
  var m = url.match(/^https?:\/\/([^/?#:]+)/i);
  return m ? m[1].toLowerCase() : null;
}

/**
 * Extracts a normalised email address from "Display Name <user@domain>" or bare form.
 * @param {string} str
 * @returns {string|null}
 */
function extractEmail(str) {
  if (!str) return null;
  var angle = str.match(/<([^>]+)>/);
  if (angle) return angle[1].toLowerCase().trim();
  var bare = str.match(/[\w.+\-]+@[\w.\-]+\.[a-z]{2,}/i);
  return bare ? bare[0].toLowerCase() : null;
}

/**
 * Returns unique, entity-decoded HTTP/HTTPS URLs found in text.
 *
 * Pass A — href attributes (double-quote, single-quote, unquoted variants).
 * Pass B — bare URLs in plain text, trimmed of trailing punctuation.
 * &amp; / &#38; decoded so Safe Browsing receives clean URLs.
 *
 * @param {string} text
 * @returns {string[]}
 */
function extractUrls(text) {
  if (!text) return [];
  var raw = [];

  var hrefRe = /href\s*=\s*"(https?:\/\/[^"]+)"|href\s*=\s*'(https?:\/\/[^']+)'|href\s*=\s*(https?:\/\/[^\s>"']+)/gi;
  var m;
  while ((m = hrefRe.exec(text)) !== null) {
    var url = m[1] || m[2] || m[3];
    if (url) raw.push(url);
  }

  var bare = text.match(/https?:\/\/[^\s"<>]+/g) || [];
  bare.forEach(function (url) { raw.push(url.replace(/[),.'"\]>]+$/, '')); });

  return Array.from(new Set(
    raw.map(function (u) { return u.replace(/&amp;/gi, '&').replace(/&#38;/gi, '&'); })
  ));
}

/**
 * Parses Authentication-Results, Reply-To, Return-Path, and Message-ID from
 * a raw RFC 2822 message. Only the header block (before the first blank line)
 * is scanned; the full raw content is discarded after this call.
 *
 * @param {string} rawContent
 * @returns {{ authenticationResults, replyTo, returnPath, messageId }}
 */
function parseHeaders(rawContent) {
  var result = {
    authenticationResults: null,
    replyTo:               null,
    returnPath:            null,
    messageId:             null
  };
  if (!rawContent) return result;

  var headerBlock = rawContent.split(/\r?\n\r?\n/)[0];
  var unfolded    = headerBlock.replace(/\r?\n[ \t]+/g, ' ');
  var lines       = unfolded.split(/\r?\n/);

  for (var i = 0; i < lines.length; i++) {
    var lower = lines[i].toLowerCase();
    var value = lines[i].split(':').slice(1).join(':').trim();
    if (result.authenticationResults === null && lower.indexOf('authentication-results:') === 0) {
      result.authenticationResults = value;
    } else if (result.replyTo === null && lower.indexOf('reply-to:') === 0) {
      result.replyTo = value;
    } else if (result.returnPath === null && lower.indexOf('return-path:') === 0) {
      result.returnPath = value;
    } else if (result.messageId === null && lower.indexOf('message-id:') === 0) {
      result.messageId = value;
    }
  }
  return result;
}

/**
 * Extracts structured data from a GmailMessage object.
 * rawContent and htmlBody are consumed locally — neither is returned.
 *
 * @param {GmailApp.GmailMessage} message
 * @returns {Object}
 */
function getEmailData(message) {
  var plainBody = message.getPlainBody();
  var htmlBody  = message.getBody();
  var headers   = parseHeaders(message.getRawContent());

  var allUrls = Array.from(new Set(
    extractUrls(plainBody).concat(extractUrls(htmlBody))
  ));

  var attachments = message.getAttachments().map(function (a) {
    return { name: a.getName(), contentType: a.getContentType() };
  });

  return {
    subject:     message.getSubject(),
    sender:      message.getFrom(),
    date:        message.getDate(),
    plainBody:   plainBody,
    attachments: attachments,
    urls:        allUrls,
    headers:     headers
  };
}

// ─── Scan History ────────────────────────────────────────────────────────────

/**
 * Returns a human-readable relative timestamp ("2h ago", "3d ago").
 * @param {number} ts — Unix ms timestamp
 * @returns {string}
 */
function relativeTime(ts) {
  var diff  = Date.now() - ts;
  var mins  = Math.floor(diff / 60000);
  if (mins  < 1)  return 'just now';
  if (mins  < 60) return mins + 'm ago';
  var hours = Math.floor(mins / 60);
  if (hours < 24) return hours + 'h ago';
  return Math.floor(hours / 24) + 'd ago';
}

/**
 * Reads the persisted scan history from UserProperties.
 * Returns an array (newest-first) of up to 20 entries.
 * Each entry: { ts, sender, subject, score, verdict }
 *
 * @returns {Array}
 */
function getScanHistory() {
  var raw = PropertiesService.getUserProperties().getProperty('SCAN_HISTORY');
  if (!raw) return [];
  try { return JSON.parse(raw); } catch (e) { return []; }
}

/**
 * Prepends the current scan result to the persisted history and saves it.
 * Subjects are truncated to 60 characters.
 * Capped at 20 entries to stay within UserProperties size limits (~4 KB).
 *
 * @param {Object} emailData
 * @param {{ finalScore: number, verdict: string }} result
 */
function saveScanHistory(emailData, result) {
  var history = getScanHistory();
  history.unshift({
    ts:      new Date().getTime(),
    sender:  emailData.sender,
    subject: (emailData.subject || '(no subject)').slice(0, 60),
    score:   result.finalScore,
    verdict: result.verdict
  });
  PropertiesService.getUserProperties()
    .setProperty('SCAN_HISTORY', JSON.stringify(history.slice(0, 20)));
}

// ─── Blocklist ────────────────────────────────────────────────────────────────

/**
 * Returns true if sender is on the user's personal blocklist.
 * Stored as a JSON array in UserProperties under key "BLOCKLIST".
 */
function isBlocked(sender) {
  var email = extractEmail(sender);
  if (!email) return false;
  var raw = PropertiesService.getUserProperties().getProperty('BLOCKLIST');
  if (!raw) return false;
  try { return JSON.parse(raw).indexOf(email) !== -1; } catch (e) { return false; }
}

/**
 * Action handler: toggles sender on/off the blocklist and returns a toast.
 */
function toggleBlocklist(e) {
  var email = extractEmail(e.parameters.senderEmail);
  if (!email) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText('Could not parse sender email address.'))
      .build();
  }

  var props = PropertiesService.getUserProperties();
  var raw   = props.getProperty('BLOCKLIST');
  var list  = [];
  try { list = raw ? JSON.parse(raw) : []; } catch (err) { list = []; }

  var idx        = list.indexOf(email);
  var nowBlocked = idx === -1;
  if (nowBlocked) { list.push(email); } else { list.splice(idx, 1); }
  props.setProperty('BLOCKLIST', JSON.stringify(list));

  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText(
      nowBlocked ? email + ' added to your blocklist.' : email + ' removed from your blocklist.'
    ))
    .build();
}

// ─── External Enrichment ──────────────────────────────────────────────────────

/**
 * Checks URLs against the Google Safe Browsing v4 API.
 *
 * Results are cached in ScriptCache for 6 hours, keyed by an MD5 hash of
 * the sorted URL list. Repeated panel opens for the same email return instantly.
 * Degrades gracefully — returns [] on missing key, HTTP error, or exception.
 *
 * @param {string[]} urls
 * @returns {string[]} matched malicious URLs
 */
function checkSafeBrowsing(urls) {
  if (!urls || urls.length === 0) return [];

  var apiKey = PropertiesService.getScriptProperties().getProperty('SAFE_BROWSING_API_KEY');
  if (!apiKey) {
    console.warn('checkSafeBrowsing: SAFE_BROWSING_API_KEY not set — skipping.');
    return [];
  }

  var cache    = CacheService.getScriptCache();
  var cacheKey = 'sb_' + Utilities.base64Encode(
    Utilities.computeDigest(Utilities.DigestAlgorithm.MD5, urls.slice().sort().join('|'))
  );
  var cached = cache.get(cacheKey);
  if (cached !== null) {
    console.log('checkSafeBrowsing: cache hit');
    return JSON.parse(cached);
  }

  var endpoint = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' + apiKey;
  var payload  = JSON.stringify({
    client: { clientId: 'penguwave-gmail-addon', clientVersion: '1.0.0' },
    threatInfo: {
      threatTypes:      ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
      platformTypes:    ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries:    urls.slice(0, 500).map(function (u) { return { url: u }; })
    }
  });

  try {
    var response = UrlFetchApp.fetch(endpoint, {
      method:             'post',
      contentType:        'application/json',
      payload:            payload,
      muteHttpExceptions: true
    });

    var code = response.getResponseCode();
    if (code !== 200) {
      console.error('checkSafeBrowsing: HTTP ' + code + ' — ' + response.getContentText());
      return [];
    }

    var data    = JSON.parse(response.getContentText());
    var matched = (!data.matches || data.matches.length === 0) ? [] :
      Array.from(new Set(data.matches.map(function (m) { return m.threat.url; })));

    cache.put(cacheKey, JSON.stringify(matched), 21600); // 6-hour TTL
    return matched;

  } catch (err) {
    console.error('checkSafeBrowsing: request failed — ' + err.message);
    return [];
  }
}

// ─── Scoring Engine ───────────────────────────────────────────────────────────

/**
 * Scores an email using a Confidence-Tiered Architecture.
 *
 * HIGH/MEDIUM signals (AUTH_FAIL, HOMOGLYPHS, DISPLAY_NAME_SPOOF,
 * MESSAGE_ID_MISMATCH, DOMAIN_MISMATCH, TYPOSQUATTING, ATTACHMENT_RISK,
 * SPELLING_ERRORS, SUSPICIOUS_URLS) deduct points immediately.
 *
 * LOW signals (BRAND_IMPERSONATION, URGENCY_LANGUAGE, URL_DOMAIN_MISMATCH,
 * SUSPICIOUS_TLD, LINK_SHORTENER) are evaluated unconditionally but only
 * applied to the final score when at least one HIGH/MEDIUM signal has fired.
 * This prevents low-signal combinations from generating false positives on
 * legitimate email that happens to mention a brand, contain an external link,
 * or use urgency-adjacent wording.
 *
 * @param {Object} emailData — output of getEmailData()
 * @returns {{ finalScore: number, signals: string[], verdict: string }}
 */
function calculateScore(emailData) {
  // ── Blocklist hard override ───────────────────────────────────────────────
  if (isBlocked(emailData.sender)) {
    return { finalScore: 0, signals: ['Sender is on your personal blocklist'], verdict: 'Malicious' };
  }

  var hmScore    = 0;  // HIGH/MEDIUM penalty accumulator (0 or negative)
  var lowScore   = 0;  // LOW penalty accumulator (0 or negative)
  var hmSignals  = []; // Messages for signals that deducted in the HM tier
  var lowSignals = []; // Messages for signals that deducted in the LOW tier

  // Shared pre-computations
  var senderDomain     = extractDomain(emailData.sender);
  var senderBaseDomain = getBaseDomain(senderDomain);
  var textToScan       = ((emailData.subject || '') + ' ' + (emailData.plainBody || '')).toLowerCase();

  // ════════════════════════════════════════════════════════════════════════════
  // HIGH / MEDIUM TIER
  // ════════════════════════════════════════════════════════════════════════════

  // ── HOMOGLYPHS ────────────────────────────────────────────────────────────
  // RFC 5321/5322 domain names are ASCII-only. Any non-ASCII character in
  // the sender domain is a Unicode homograph attack — e.g. Cyrillic 'а'
  // (U+0430) replacing Latin 'a'. Zero false-positive rate on real mail.
  if (senderDomain && /[^\x00-\x7F]/.test(senderDomain)) {
    hmScore += SCORING_WEIGHTS.HOMOGLYPHS;
    hmSignals.push('Non-ASCII characters in sender domain (homoglyph attack)');
  }

  // ── AUTH_FAIL ─────────────────────────────────────────────────────────────
  // SPF, DKIM, or DMARC hard failure as recorded by the final receiving
  // server in the topmost Authentication-Results header.
  // Softfail (spf=softfail, dmarc=none) applies half the penalty: the policy
  // is weak but not conclusive. Only one branch fires — hardfail takes
  // precedence and suppresses the softfail check.
  var auth        = (emailData.headers.authenticationResults || '').toLowerCase();
  var authHardfail = auth && (auth.indexOf('spf=fail')   !== -1 ||
                              auth.indexOf('dkim=fail')  !== -1 ||
                              auth.indexOf('dmarc=fail') !== -1);
  var authSoftfail = !authHardfail && auth &&
                     (auth.indexOf('spf=softfail') !== -1 ||
                      auth.indexOf('dmarc=none')   !== -1);
  if (authHardfail) {
    hmScore += SCORING_WEIGHTS.AUTH_FAIL;
    hmSignals.push('Authentication failure detected (SPF/DKIM/DMARC)');
  } else if (authSoftfail) {
    hmScore += Math.round(SCORING_WEIGHTS.AUTH_FAIL / 2); // −12
    hmSignals.push('Weak authentication policy detected (SPF softfail / DMARC none)');
  }

  // ── DISPLAY_NAME_SPOOF ────────────────────────────────────────────────────
  // Display name claims to be a known brand but the actual sending domain
  // does not belong to that brand. Word-boundary matching prevents substring
  // collisions ("Snapple" → "apple", "Dropboxing" → "dropbox").
  // isSenderFromBrand() handles ccTLD variants (paypal.co.uk is legitimate).
  var displayName  = emailData.sender.replace(/<[^>]+>/, '').toLowerCase().trim();
  var spoofedBrand = null;
  Object.keys(BRAND_DOMAINS).forEach(function (brand) {
    if (spoofedBrand) return;
    if (containsBrandWord(displayName, brand) &&
        !isSenderFromBrand(senderDomain, BRAND_DOMAINS[brand])) {
      spoofedBrand = brand;
    }
  });
  if (spoofedBrand) {
    hmScore += SCORING_WEIGHTS.DISPLAY_NAME_SPOOF;
    hmSignals.push('Display name spoofing: claims to be ' +
      spoofedBrand.charAt(0).toUpperCase() + spoofedBrand.slice(1));
  }

  // ── MESSAGE_ID_MISMATCH ───────────────────────────────────────────────────
  // The Message-ID header is generated by the originating MTA and contains
  // its domain (<unique-id@sendingdomain.com>). Phishing kits frequently
  // forge the From: address but neglect the Message-ID, leaving a structural
  // inconsistency detectable here. Legitimate ESPs use their own MTA domains
  // (e.g. amazonses.com) intentionally and are whitelisted.
  var messageIdDomain = extractDomain(emailData.headers.messageId);
  if (messageIdDomain && senderBaseDomain &&
      getBaseDomain(messageIdDomain) !== senderBaseDomain &&
      !isEspDomain(messageIdDomain)) {
    hmScore += SCORING_WEIGHTS.MESSAGE_ID_MISMATCH;
    hmSignals.push('Message-ID domain does not match sender domain');
  }

  // ── DOMAIN_MISMATCH ───────────────────────────────────────────────────────
  // Compares base domains (eTLD+1) so that mail.company.com and company.com
  // are treated as the same entity. This eliminates the false positive where
  // a company uses a subdomain for sending and a root domain for bounces.
  // Return-Path ESP domains are whitelisted for the same reason.
  var replyToDomain    = extractDomain(emailData.headers.replyTo);
  var returnPathDomain = extractDomain(emailData.headers.returnPath);
  var replyMismatch    = !!replyToDomain &&
    getBaseDomain(replyToDomain) !== senderBaseDomain;
  var returnMismatch   = !!returnPathDomain &&
    getBaseDomain(returnPathDomain) !== senderBaseDomain &&
    !isEspDomain(returnPathDomain);
  if (replyMismatch || returnMismatch) {
    hmScore += SCORING_WEIGHTS.DOMAIN_MISMATCH;
    hmSignals.push('Sender domain does not match Reply-To or Return-Path');
  }

  // ── TYPOSQUATTING ─────────────────────────────────────────────────────────
  // Levenshtein distance between the sender's SLD and each known brand's SLD.
  // getBaseDomain() ensures ccTLD domains (paypa1.co.uk) are correctly parsed.
  // Domains whose SLD is an exact match for a brand SLD are skipped — they are
  // either the legitimate brand or a suspicious-TLD variant caught by SUSPICIOUS_TLD.
  // penalizedTyposquatStem records the sender SLD that was penalized so the URL
  // pass can skip that exact SLD and avoid double-jeopardy (-60) for the same domain.
  var penalizedTyposquatStem = null;
  if (senderDomain && PERSONAL_EMAIL_PROVIDERS.indexOf(senderDomain) === -1) {
    var senderStem = senderBaseDomain ? senderBaseDomain.split('.')[0] : '';
    if (senderStem.length > 3) {
      var isTyposquat = Object.keys(BRAND_DOMAINS).some(function (brand) {
        var brandDomain = BRAND_DOMAINS[brand];
        if (senderDomain === brandDomain || senderDomain.endsWith('.' + brandDomain)) return false;
        var brandStem = brandDomain.split('.')[0];
        if (senderStem === brandStem) return false; // ccTLD variant (paypal.co.uk)
        return levenshtein(senderStem, brandStem) <= 2;
      });
      if (isTyposquat) {
        penalizedTyposquatStem = senderStem;
        hmScore += SCORING_WEIGHTS.TYPOSQUATTING;
        hmSignals.push('Sender domain resembles a known brand (possible typosquatting)');
      }
    }
  }

  // ── TYPOSQUATTING — URL domains ───────────────────────────────────────────
  // Modern phishing often uses a freemail sender (gmail.com) that passes
  // the sender-domain check, then embeds a link to a typosquatted domain
  // (e.g. paypa1.com/login). This pass extends the same Levenshtein check
  // to every URL extracted from the email body.
  // If the sender SLD was already penalized, any URL sharing that SLD is skipped
  // to avoid double-jeopardy: paypa1.com sender + paypa1.com link = -30 once, not -60.
  var urlTyposquatFound = emailData.urls.some(function (url) {
    var urlDom  = extractUrlDomain(url);
    var urlBase = getBaseDomain(urlDom);
    if (!urlBase) return false;
    var urlStem = urlBase.split('.')[0];
    if (urlStem.length <= 3) return false;
    if (penalizedTyposquatStem && urlStem === penalizedTyposquatStem) return false;
    return Object.keys(BRAND_DOMAINS).some(function (brand) {
      var brandDomain = BRAND_DOMAINS[brand];
      if (urlDom === brandDomain || urlDom.endsWith('.' + brandDomain)) return false;
      var brandStem = brandDomain.split('.')[0];
      if (urlStem === brandStem) return false; // same SLD — legitimate ccTLD variant
      return levenshtein(urlStem, brandStem) <= 2;
    });
  });
  if (urlTyposquatFound) {
    hmScore += SCORING_WEIGHTS.TYPOSQUATTING;
    hmSignals.push('Malicious look-alike URL detected (typosquatting)');
  }

  // ── ATTACHMENT_RISK ───────────────────────────────────────────────────────
  // Executable and script MIME types / filename extensions. Only metadata
  // is inspected — attachment bytes are never downloaded.
  var riskyMime = ['application/x-msdownload', 'application/x-executable',
                   'application/bat', 'application/x-sh', 'application/javascript'];
  var riskyExt  = /\.(exe|bat|js|vbs|ps1|sh|cmd|scr|jar|msi)$/i;
  if (emailData.attachments.some(function (a) {
    return riskyMime.indexOf(a.contentType) !== -1 || riskyExt.test(a.name);
  })) {
    hmScore += SCORING_WEIGHTS.ATTACHMENT_RISK;
    hmSignals.push('Potentially dangerous attachment type detected');
  }

  // ── SPELLING_ERRORS ───────────────────────────────────────────────────────
  // Deliberate typos that are a classic phishing indicator and rarely appear
  // in legitimate automated email from real organisations.
  var phishingTypos = ['acount', 'updaet', 'securty', 'passwrd', 'verfiy',
                       'suspendd', 'loginng', 'veryfication', 'authorizaton', 'urgant'];
  if (phishingTypos.some(function (t) { return textToScan.indexOf(t) !== -1; })) {
    hmScore += SCORING_WEIGHTS.SPELLING_ERRORS;
    hmSignals.push('Common phishing spelling errors detected');
  }

  // ── SUSPICIOUS_URLS — Safe Browsing ──────────────────────────────────────
  // Network call is always last in the HIGH/MEDIUM tier. Skipped when there
  // are no URLs (text-only emails) to save latency and API quota.
  // Results are cached 6 hours — repeated panel opens are instant.
  if (emailData.urls.length > 0) {
    var maliciousUrls = checkSafeBrowsing(emailData.urls);
    if (maliciousUrls.length > 0) {
      hmScore += SCORING_WEIGHTS.SUSPICIOUS_URLS;
      hmSignals.push('Malicious URLs detected by Safe Browsing: ' + maliciousUrls.join(', '));
    }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // LOW TIER  (always evaluated; only applied to score when hmScore < 0)
  // ════════════════════════════════════════════════════════════════════════════

  // ── BRAND_IMPERSONATION ───────────────────────────────────────────────────
  // Body or subject mentions a known brand while sender is from an unrelated
  // domain. Word-boundary matching prevents false positives from casual brand
  // mentions ("instagram-style", "google-like"). Personal providers excluded
  // because individual users legitimately mention brands in conversation.
  var fromPersonalProvider = PERSONAL_EMAIL_PROVIDERS.some(function (p) {
    return senderDomain === p || (senderDomain && senderDomain.endsWith('.' + p));
  });
  if (!fromPersonalProvider) {
    var impersonatedBrand = null;
    Object.keys(BRAND_DOMAINS).forEach(function (brand) {
      if (impersonatedBrand) return;
      if (containsBrandWord(textToScan, brand) &&
          !isSenderFromBrand(senderDomain, BRAND_DOMAINS[brand])) {
        impersonatedBrand = brand;
      }
    });
    if (impersonatedBrand) {
      lowScore += SCORING_WEIGHTS.BRAND_IMPERSONATION;
      lowSignals.push('Brand impersonation detected (' +
        impersonatedBrand.charAt(0).toUpperCase() + impersonatedBrand.slice(1) + ')');
    }
  }

  // ── URGENCY_LANGUAGE ──────────────────────────────────────────────────────
  // Only high-precision terms that are near-exclusive to phishing. Generic
  // words like "verify" and "password" appear constantly in legitimate
  // transactional mail and are intentionally excluded.
  var urgencyKeywords = ['immediate action', 'account suspended',
                         'urgent action required', 'verify within 24 hours'];
  var foundKeywords = urgencyKeywords.filter(function (kw) { return textToScan.indexOf(kw) !== -1; });
  if (foundKeywords.length > 0) {
    lowScore += SCORING_WEIGHTS.URGENCY_LANGUAGE;
    lowSignals.push('Urgency or phishing language detected: ' + foundKeywords.join(', '));
  }

  // ── URL_DOMAIN_MISMATCH + LINK_SHORTENER ─────────────────────────────────
  // Trusted whitelist covers major CDNs, ESPs, and SaaS platforms.
  // Link shorteners are intentionally absent — they are flagged separately
  // because they hide the true destination and must never be trusted blindly.
  var trustedDomains = [
    // Consumer and B2B services
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com',
    'instagram.com', 'twitter.com', 'x.com', 'linkedin.com', 'youtube.com',
    'github.com', 'dropbox.com', 'icloud.com', 'live.com', 'outlook.com',
    'office.com', 'wetransfer.com', 'zoom.us', 'slack.com', 'notion.so',
    'spotify.com', 'netflix.com', 'adobe.com', 'docusign.com', 'paypal.com',
    // Email service providers
    'sendgrid.net', 'mailchimp.com', 'hubspot.com', 'salesforce.com',
    'marketo.com', 'constantcontact.com', 'klaviyo.com', 'brevo.com',
    // CDNs and cloud infrastructure
    'cloudflare.com', 'akamai.net', 'amazonaws.com', 'cloudfront.net',
    'fastly.net', 'azureedge.net', 'googleusercontent.com', 'gstatic.com'
  ];

  var hasShortener    = false;
  var hasExternalLink = false;

  if (senderDomain) {
    emailData.urls.forEach(function (url) {
      var urlDom = extractUrlDomain(url);
      if (!urlDom) return;

      // Shortener check takes priority — these are opaque regardless of context
      if (LINK_SHORTENER_DOMAINS.some(function (s) {
            return urlDom === s || urlDom.endsWith('.' + s);
          })) {
        hasShortener = true;
        return;
      }

      // Same sender domain or base domain → not external
      if (urlDom === senderDomain || urlDom.endsWith('.' + senderDomain)) return;
      if (getBaseDomain(urlDom) === senderBaseDomain) return;

      // Trusted domain → not flagged
      if (trustedDomains.some(function (td) {
            return urlDom === td || urlDom.endsWith('.' + td);
          })) return;

      hasExternalLink = true;
    });
  }

  if (hasShortener) {
    lowScore += SCORING_WEIGHTS.LINK_SHORTENER;
    lowSignals.push('Opaque link shortener detected (true destination hidden)');
  }
  if (hasExternalLink) {
    lowScore += SCORING_WEIGHTS.URL_DOMAIN_MISMATCH;
    lowSignals.push('External link domain mismatch');
  }

  // ── SUSPICIOUS_TLD ────────────────────────────────────────────────────────
  // High-abuse TLDs disproportionately used in phishing due to low/zero
  // registration cost. Applied to sender domain and all URL domains.
  var suspiciousTlds = ['.xyz', '.top', '.click', '.tk', '.ml', '.ga',
                        '.cf', '.gq', '.pw', '.rest', '.icu', '.monster'];
  var domainsToCheck = [senderDomain].concat(emailData.urls.map(extractUrlDomain)).filter(Boolean);
  if (domainsToCheck.some(function (d) {
    return suspiciousTlds.some(function (tld) { return d.endsWith(tld); });
  })) {
    lowScore += SCORING_WEIGHTS.SUSPICIOUS_TLD;
    lowSignals.push('Suspicious domain TLD detected');
  }

  // ── Tier combination ──────────────────────────────────────────────────────
  // LOW signals are only applied when hmScore <= -30. A threshold of 0 would
  // unlock the LOW tier on a single DKIM failure (−12 softfail or −25 hardfail),
  // which is common on mailing lists. Requiring −30 means the gate only opens
  // on at least one high-confidence structural threat (e.g. DISPLAY_NAME_SPOOF
  // −35, TYPOSQUATTING −30, DOMAIN_MISMATCH −30) or multiple medium signals
  // stacking above the threshold.
  var appliedLowScore   = hmScore <= -30 ? lowScore   : 0;
  var appliedLowSignals = hmScore <= -30 ? lowSignals : [];
  var allSignals        = hmSignals.concat(appliedLowSignals);

  var score   = Math.max(0, Math.min(100, 100 + hmScore + appliedLowScore));
  var verdict = score >= 80 ? 'Safe' : score >= 50 ? 'Suspicious' : 'Malicious';
  return { finalScore: score, signals: allSignals, verdict: verdict };
}

// ─── Entry Point ──────────────────────────────────────────────────────────────

/**
 * Entry point for the Gmail Add-on contextual trigger.
 * @param {Object} e — event object provided by Gmail
 * @returns {CardService.Card}
 */
/**
 * Formats a history array into a compact multi-line string for the card UI.
 * Shows verdict emoji, score, relative time, and truncated sender.
 * @param {Array}  history — entries from getScanHistory()
 * @param {number} limit   — max entries to render
 * @returns {string}
 */
function formatHistory(history, limit) {
  if (!history || history.length === 0) return '‎No previous scans yet.';
  return history.slice(0, limit).map(function (h) {
    var icon = h.verdict === 'Safe' ? '✓' : h.verdict === 'Suspicious' ? '⚠' : '✗';
    return '‎' + icon + ' ' + h.score + '/100  ' + relativeTime(h.ts) + '\n   ' + h.sender.slice(0, 45);
  }).join('\n');
}

function buildAddOn(e) {
  // Load existing history before the current scan so the display shows
  // previous results rather than the email currently being analysed.
  var previousHistory = getScanHistory();

  // Homepage trigger: no email is open yet — show history as the home view
  if (!e.gmail || !e.gmail.messageId) {
    return CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle('PenguWave Scanner'))
      .addSection(
        CardService.newCardSection()
          .addWidget(CardService.newTextParagraph()
            .setText('‎Please select an email to start the security analysis.'))
      )
      .addSection(
        CardService.newCardSection()
          .setHeader('Recent Scans')
          .addWidget(CardService.newTextParagraph()
            .setText(formatHistory(previousHistory, 5)))
      )
      .build();
  }

  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  var message   = GmailApp.getMessageById(e.gmail.messageId);
  var emailData = getEmailData(message);
  var result    = calculateScore(emailData);

  // Persist this scan to history (after scoring, before building the card)
  saveScanHistory(emailData, result);

  console.log({
    subject:     emailData.subject,
    sender:      emailData.sender,
    date:        emailData.date,
    urlCount:    emailData.urls.length,
    headers:     emailData.headers,
    scoreResult: result
  });

  var formattedDate = Utilities.formatDate(emailData.date, 'Asia/Jerusalem', 'dd MMM yyyy, HH:mm');

  var verdictLabel = result.verdict === 'Safe'      ? 'Safe ✓'      :
                     result.verdict === 'Suspicious' ? 'Suspicious ⚠' : 'Malicious ✗';

  var signalText = result.signals.length > 0
    ? result.signals.map(function (s) { return '‎• ' + s; }).join('\n')
    : '‎All clear — no threats detected.';

  var blocked       = isBlocked(emailData.sender);
  var blockBtnLabel = '‎' + (blocked ? 'Unblock Sender' : 'Block Sender');
  var blockAction   = CardService.newAction()
    .setFunctionName('toggleBlocklist')
    .setParameters({ senderEmail: emailData.sender });

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('PenguWave Email Scanner'))

    .addSection(
      CardService.newCardSection()
        .setHeader('Email Info')
        .addWidget(CardService.newTextParagraph().setText(
          '‎From:    ' + emailData.sender  + '<br>' +
          'Subject: '       + emailData.subject + '<br>' +
          'Date:    '       + formattedDate
        ))
    )

    .addSection(
      CardService.newCardSection()
        .setHeader('Analysis Result')
        .addWidget(CardService.newTextParagraph().setText(
          '‎Score:   ' + result.finalScore + ' / 100<br>' +
          'Verdict: '       + verdictLabel      + '<br><br>' +
          'Signals:<br>'    + signalText
        ))
    )

    .addSection(
      CardService.newCardSection()
        .setHeader('Recent Scans')
        .addWidget(CardService.newTextParagraph()
          .setText(formatHistory(previousHistory, 3)))
    )

    .addSection(
      CardService.newCardSection()
        .setHeader('Actions')
        .addWidget(
          CardService.newTextButton()
            .setText(blockBtnLabel)
            .setOnClickAction(blockAction)
        )
    )

    .build();
}
