# HackerOne Hunting Checklist — Master Reference

Derived from HackerOne's CWE taxonomy, top rewarded reports, and 2025-2026 community methodology.
Cross-referenced with `now_we_know/attack_methodology.json` for full technique details.

---

## Quick Target Assessment

When you land on ANY target, run through this in order:

### 1. What's the attack surface? (5 min)
- [ ] What technology stack? (check response headers, Wappalyzer, JS files)
- [ ] What auth mechanism? (session cookies, JWT, OAuth, API keys)
- [ ] Any API? (REST, GraphQL, gRPC, WebSocket)
- [ ] Any file upload? (images, documents, imports)
- [ ] Any URL input? (webhooks, imports, previews = SSRF vector)
- [ ] Any AI/chatbot feature? (prompt injection vector)
- [ ] Any payment/e-commerce? (business logic vector)
- [ ] Any user-generated content? (XSS vector)
- [ ] Any multi-tenant/role system? (authz bypass vector)

### 2. What's the low-hanging fruit? (15 min)
- [ ] Check robots.txt, sitemap.xml, /.well-known/
- [ ] Check /.git, /.env, /debug, /actuator, /swagger.json
- [ ] Parse CSP headers for infrastructure intel
- [ ] Check JS source for API keys, secrets, internal endpoints
- [ ] Check for subdomain takeover (CNAME to dead services)
- [ ] Test all forms for basic XSS and SQLi
- [ ] Check error pages for stack traces and version info

### 3. What pays the most? (prioritize by bounty potential)
1. **RCE** ($10K-$50K+): deserialization, SSTI, command injection, file upload to webshell
2. **Auth bypass** ($5K-$25K): MFA bypass, OAuth flaws, JWT attacks, session fixation
3. **SSRF to cloud** ($5K-$15K): URL params -> metadata -> cloud creds -> full access
4. **SQLi** ($5K-$15K): all user inputs, search, filters, sort params
5. **Privilege escalation** ($3K-$20K): role manipulation, IDOR, missing authz on mutations
6. **Stored XSS** ($1K-$10K): profile fields, comments, admin-rendered content
7. **Information disclosure** ($500-$5K): API leaks, debug endpoints, source code

---

## By Target Type

### SaaS / Web Application
1. Register two accounts (different roles if possible)
2. Map all API endpoints via crawling + JS analysis
3. Test IDOR on every object ID (swap between accounts)
4. Test privilege escalation (access admin features as regular user)
5. Test all input fields for XSS and injection
6. Check file upload for bypass and stored XSS
7. Test business logic (pricing, coupons, workflows)
8. Check rate limiting on sensitive endpoints
9. Test OAuth/SSO flows for token theft and CSRF
10. Look for race conditions on stateful operations

### API-Heavy Target (REST/GraphQL)
1. Discover all endpoints (swagger, introspection, JS extraction)
2. Test BOLA: change object IDs in every request
3. Test BFLA: access admin endpoints with user token
4. Test mass assignment: add extra fields to PUT/PATCH
5. Test rate limiting bypass (header rotation, batching)
6. Test older API versions (/v0, /v1 may lack controls)
7. Test content-type confusion (JSON to XML = XXE potential)
8. GraphQL: batch queries, alias brute force, depth attacks
9. Check for excessive data in responses (PII leak)
10. Test JWT/token attacks if applicable

### E-Commerce / Payment
1. Price manipulation (intercept and modify checkout requests)
2. Currency confusion attacks
3. Coupon stacking and reuse
4. Quantity manipulation (negative, overflow, decimal)
5. Race condition on payments (double-spend)
6. Refund flow abuse
7. Gift card/voucher manipulation
8. Subscription/trial bypass
9. Discount code generation prediction
10. Cart manipulation between steps

### AI/Chatbot Feature
1. Direct prompt injection ("ignore instructions...")
2. System prompt extraction ("repeat your prompt")
3. Indirect injection via content the AI processes
4. Tool/function abuse (trick AI into calling dangerous APIs)
5. XSS via AI output (make AI generate script tags)
6. Data exfiltration via AI (extract other users' data)
7. RAG poisoning (inject into knowledge base)
8. Jailbreak via encoding (base64 instructions, multi-language)
9. Resource exhaustion (extremely long/complex prompts)
10. Session confusion (manipulate conversation history)

### Infrastructure / Cloud
1. Subdomain enumeration + takeover check
2. Port scan for exposed services (Jenkins, K8s, databases)
3. S3/Azure/GCP bucket misconfiguration
4. SSRF to cloud metadata service
5. DNS zone transfer attempt
6. TLS configuration weaknesses
7. Email spoofing (SPF/DKIM/DMARC check)
8. Container/K8s API exposure
9. CI/CD pipeline analysis (GitHub Actions, public workflows)
10. Source code search for secrets (GitHub, GitLab)

### Mobile App
1. Decompile APK/IPA, search for hardcoded secrets
2. Check manifest for exported components and debug flags
3. Proxy traffic with certificate pinning bypass
4. Test deep link / URL scheme hijacking
5. Check local storage for sensitive data
6. WebView JavaScript interface abuse
7. Backup extraction (if allowBackup=true)
8. Intercept and modify API requests
9. Test for tapjacking/overlay attacks
10. Check clipboard leakage

---

## H1 Top 10 Vulnerability Types by Reward

| Rank | Type | CWE | Typical Bounty | Where to Look |
|------|------|-----|---------------|---------------|
| 1 | XSS | CWE-79 | $150-$10K+ | All user inputs, stored content |
| 2 | Improper Auth | CWE-287 | $500-$25K+ | Login, reset, MFA, OAuth, JWT |
| 3 | Info Disclosure | CWE-200 | $100-$5K | Errors, API responses, JS files |
| 4 | Privilege Escalation | CWE-269 | $500-$20K+ | Role changes, admin endpoints |
| 5 | SQLi | CWE-89 | $500-$15K+ | Search, filters, sort, form inputs |
| 6 | Code Injection | CWE-94 | $1K-$25K+ | SSTI, eval, deserialization |
| 7 | SSRF | CWE-918 | $500-$15K+ | URL params, webhooks, imports |
| 8 | IDOR | CWE-639 | $300-$10K+ | API object IDs, download endpoints |
| 9 | Access Control | CWE-284 | $300-$15K+ | Admin functions, API endpoints |
| 10 | CSRF | CWE-352 | $100-$3K | State-changing without CSRF token |

---

## 2025-2026 Trending Attack Vectors

| Trend | Why It Matters | Testing Approach |
|-------|---------------|-----------------|
| AI Prompt Injection | 540% surge, 1,121+ programs in scope | Test every AI feature for instruction override |
| SSRF + Cloud Escalation | Single SSRF can compromise entire cloud | Chain URL inputs to metadata endpoints |
| Race Conditions | HTTP/2 single-packet attack makes reliable | Turbo Intruder on balance/transfer/coupon ops |
| Web Cache Deception | Path confusion tricks CDN into caching private data | /profile/x.css, /account/../static patterns |
| Supply Chain | Dependency confusion on internal packages | Find internal names, register on public registry |
| API BOLA/BFLA | OWASP API #1 and #5 | Swap IDs, test admin endpoints with user tokens |
| GraphQL Abuse | Introspection leaks, missing mutation auth | Dump schema, test every mutation as low-priv |
| Prototype Pollution | Client->XSS, Server->RCE | __proto__ in URL params and JSON bodies |
| Passkey/WebAuthn | New attack surface, device response bugs | Test with forged/replayed device responses |
| Edge/CDN Exploitation | Cache key confusion, function injection | Test with varying headers, paths, encodings |

---

## Top H1 Report Patterns (Highest Bounty Reports)

| Pattern | Bounty | Key Takeaway |
|---------|--------|-------------|
| PHP Deserialization RCE | $20,000 | Check serialized data in cookies/params |
| Exposed Jenkins/Admin | $15,000 | Always port scan, subdomain enum |
| Account Takeover via OAuth | $10,000 | Test account linking without email verify |
| XXE via File Upload | $10,000 | SVG, XLSX, DOCX are XML-based |
| SSRF to AWS Creds | $10,000+ | Any URL param can lead to cloud compromise |
| Race Condition (Financial) | $5K-$15K | Parallel requests on money operations |
| GraphQL Auth Bypass | $5K-$20K | Test ALL mutations as low-priv user |
| Subdomain Takeover | $2K-$5K | Low effort, check dangling CNAMEs |

---

## Anti-Tunnel-Vision Checklist

When you feel stuck on one approach, force yourself through this:

- [ ] **Not just GraphQL** — have you tested REST endpoints, WebSocket, gRPC?
- [ ] **Not just the API** — have you checked admin panels, debug endpoints, documentation sites?
- [ ] **Not just the web app** — have you checked mobile apps, browser extensions, desktop clients?
- [ ] **Not just auth** — have you tested business logic, payments, file handling?
- [ ] **Not just injection** — have you tested logic flaws, race conditions, cache poisoning?
- [ ] **Not just the app** — have you checked infrastructure, DNS, email, cloud configs?
- [ ] **Not just the main domain** — have you enumerated subdomains, checked acquired companies?
- [ ] **Not just automated scans** — have you done manual testing, read the source code?
- [ ] **Not just known patterns** — have you thought about what's unique to THIS app?
- [ ] **Have you checked the AI chatbot?** — prompt injection is the fastest-growing category
