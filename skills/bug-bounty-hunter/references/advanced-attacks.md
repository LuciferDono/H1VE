# Advanced Attack Techniques Reference

## Table of Contents
1. [HTTP Request Smuggling](#http-request-smuggling)
2. [Web Cache Poisoning](#web-cache-poisoning)
3. [Prototype Pollution](#prototype-pollution)
4. [DNS Rebinding](#dns-rebinding)
5. [Host Header Injection](#host-header-injection)
6. [CORS Misconfiguration](#cors-misconfiguration)
7. [WebSocket Attacks](#websocket-attacks)
8. [Deserialization Attacks](#deserialization-attacks)
9. [Clickjacking](#clickjacking)
10. [PostMessage Vulnerabilities](#postmessage-vulnerabilities)

---

## HTTP Request Smuggling

### Detection

**CL.TE** (front-end: Content-Length, back-end: Transfer-Encoding): Send request where CL covers partial body, TE processes chunks. Time delay = vulnerable.

**TE.CL** (reverse): Test CL.TE first, then TE.CL. In Burp Repeater, uncheck "Update Content-Length".

**H2.CL / H2.TE**: HTTP/2 downgrade smuggling when proxy downgrades to HTTP/1.1.

Use HTTP Request Smuggler Burp extension for automated detection.

### Exploitation

- Capture other users' requests (poison next request)
- Bypass front-end security controls (access /admin)
- Cache poisoning via smuggled request
- Credential theft via reflected request smuggling

---

## Web Cache Poisoning

### Detection

Use Param Miner Burp extension to discover unkeyed parameters/headers.

Common unkeyed headers: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, `X-Rewrite-URL`, `X-Host`

### Exploitation

If unkeyed header affects response (e.g., reflected in script src) and response is cached, all users receive poisoned response.

**Cache deception**: trick cache into storing private responses (e.g., `/my-account/profile.css` - server returns profile data, cache stores as CSS).

**Next.js cache poisoning**: abuse `__nextDataReq` parameter or RSC headers. Selected as 7th best web research in PortSwigger Top 10 2025.

One researcher earned $40,000 for 70 cache poisoning bugs.

---

## Prototype Pollution

### Client-Side

Detection via URL: `?__proto__[polluted]=true` or `?constructor[prototype][polluted]=true`

Check in console: `Object.prototype.polluted` - if returns value, pollution exists.

XSS gadgets: `?__proto__[innerHTML]=<img/src/onerror=alert(1)>`, `?__proto__[srcdoc]=...`

### Server-Side (Node.js)

Via JSON body: `{"__proto__": {"isAdmin": true}}`

Can escalate to RCE in certain Node.js configurations via shell/argv0 manipulation.

---

## DNS Rebinding

Attack flow: victim visits attacker.com -> DNS resolves to attacker IP (serves JS) -> JS makes same-origin request -> DNS now resolves to 127.0.0.1 -> request hits internal service.

Targets: internal admin panels, databases, Docker/K8s API, IoT devices.

Tools: rbndr.us, Singularity, whonow

---

## Host Header Injection

**Password reset poisoning**: set Host to attacker domain in forgot-password request. Reset link uses attacker domain, victim clicks and leaks token.

Variations: X-Forwarded-Host, duplicate Host headers, Host with @ character.

**Cache poisoning**: if Host reflected in response links and cached.

---

## CORS Misconfiguration

### Detection

Test reflected origin: `curl -H "Origin: https://evil.com" -I target.com/api` - check Access-Control-Allow-Origin

Test null origin, subdomain matching, prefix/suffix matching.

### Exploitation

If origin reflected with credentials allowed: create page that makes authenticated cross-origin request and exfiltrates response data.

Null origin exploit: use sandboxed iframe with data: URI.

---

## WebSocket Attacks

### Cross-Site WebSocket Hijacking (CSWSH)

If WebSocket handshake uses only cookies (no CSRF token): create malicious page that opens WebSocket to target, sends commands, receives data.

Note: Firefox's Total Cookie Protection prevents this. Chrome remains vulnerable.

### WebSocket Injection

Test for XSS and SQLi through WebSocket messages. Test for path traversal in action parameters.

---

## Deserialization Attacks

**Java**: look for magic bytes AC ED 00 05 (binary) or rO0AB (base64). Use ysoserial for payload generation.

**PHP**: look for serialize/unserialize. Exploit via __wakeup, __destruct, __toString magic methods.

**Python**: look for pickle.loads() or yaml.load(). Exploit via __reduce__ method.

**.NET**: ViewState deserialization, BinaryFormatter, JSON.NET type handling.

---

## Clickjacking

Test: check for missing X-Frame-Options and Content-Security-Policy frame-ancestors.

PoC: transparent iframe overlaying a button. Frame-busting scripts bypassable with sandbox attribute.

---

## PostMessage Vulnerabilities

Look for message event listeners without origin validation. If no origin check: attacker page can send crafted messages leading to XSS, open redirect, or data manipulation.

Exploit: create iframe targeting vulnerable page, use postMessage to send payload after load.
