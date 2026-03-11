# API Security Testing Reference

## Table of Contents
1. [REST API Testing](#rest-api-testing)
2. [GraphQL Security](#graphql-security)
3. [OWASP API Top 10](#owasp-api-top-10)
4. [JWT & Token Attacks](#jwt--token-attacks)
5. [Mass Assignment](#mass-assignment)
6. [Rate Limiting Bypass](#rate-limiting-bypass)
7. [API Key Leakage](#api-key-leakage)

---

## REST API Testing

### Endpoint Discovery

Extract from JS: `katana -u https://target.com -jc -d 3 | grep -iE "/api/|/v[0-9]/"`

Common paths to fuzz: `/api/v1/`, `/api/internal/`, `/api/admin/`, `/api/debug/`, `/swagger.json`, `/openapi.json`, `/api-docs`, `/graphql`, `/graphiql`

Kiterunner: `kr scan https://target.com -w routes-large.kite`

Test all HTTP methods per endpoint: GET, POST, PUT, PATCH, DELETE, OPTIONS, TRACE

### Version Manipulation

Try older/newer API versions: `/api/v0/` (may lack controls), `/api/v2/`, `/api/beta/`, `/api/internal/`

### Content-Type Abuse

Test same endpoint with: application/json, application/xml (may enable XXE), application/x-www-form-urlencoded, multipart/form-data. May bypass WAF or validation.

---

## GraphQL Security

### Introspection Query

Full introspection to dump entire schema: types, queries, mutations, subscriptions, fields, args.

Simplified: `{__schema{types{name fields{name type{name}}}}}`

List queries: `{__schema{queryType{fields{name args{name type{name}}}}}}`

List mutations: `{__schema{mutationType{fields{name args{name type{name}}}}}}`

### GraphQL Attacks

**Batch query**: send array of queries in single request (bypass rate limiting)

**Alias batching**: `{a1:login(pass:"p1"){token} a2:login(pass:"p2"){token}}` - multiple operations in one request

**Query depth attack**: deeply nested queries for DoS

**Field suggestion**: misspelled fields may reveal valid field names via error suggestions

**SQL injection via GraphQL**: `{user(id:"1' OR '1'='1"){name}}`

**IDOR via GraphQL**: `{user(id:2){name email ssn}}`

### GraphQL Tools

graphw00f (fingerprinting), CrackQL (brute-force), Clairvoyance (schema recovery when introspection disabled), InQL (Burp extension)

---

## OWASP API Top 10

**BOLA (API1)**: access other users' objects by changing IDs. Test GET/PUT/DELETE on other user resources.

**Broken Auth (API2)**: no rate limiting on login, JWT weaknesses, API keys in URL.

**BOPLA (API3)**: mass assignment (add extra fields), excessive data exposure (response leaks sensitive fields).

**Unrestricted Resource Consumption (API4)**: no rate limiting, unbounded pagination `?limit=999999`, ReDoS.

**BFLA (API5)**: access admin functions with user token. POST/DELETE on admin endpoints.

---

## JWT & Token Attacks

### Analysis

Decode: `echo "eyJhbGc..." | cut -d. -f2 | base64 -d`

jwt_tool: crack secret (`-C -d wordlist`), alg:none (`-X a`), key confusion (`-X k -pk public.pem`), tamper (`-T`)

hashcat: `hashcat -a 0 -m 16500 jwt.txt rockyou.txt`

### Common Vulnerabilities

1. Algorithm confusion (RS256 to HS256)
2. None algorithm bypass
3. Weak signing secret
4. JKU/X5U header injection
5. KID path traversal
6. Missing expiration
7. Not invalidated on logout/password change

---

## Mass Assignment

### Detection

Step 1: GET user profile, note all response fields

Step 2: PUT/PATCH with extra fields: `{"name":"test","role":"admin","isAdmin":true,"credits":99999}`

Step 3: Check if unauthorized fields were updated

Common fields to try: role, isAdmin, permissions, credits, balance, verified, subscription, plan, premium, two_factor_enabled

---

## Rate Limiting Bypass

Header-based: `X-Forwarded-For`, `X-Originating-IP`, `X-Remote-IP`, `X-Client-IP`, `X-Real-IP`, `True-Client-IP` - rotate IP values

Case variation: `/api/login`, `/API/LOGIN`, `/Api/Login`

Path padding: `/api/login/`, `/api//login`, `/api/./login`, `/api/login%20`

Parameter pollution: add unique query params to each request

GraphQL batching: send multiple queries in one request

---

## API Key Leakage

### Where to Find

JS files, HTTP responses, public repos (GitHub/GitLab), mobile apps (decompile APK/IPA), browser storage, error messages.

### Key Patterns

```
AKIA[0-9A-Z]{16}          # AWS Access Key
sk_live_[a-zA-Z0-9]+       # Stripe Secret Key
AIza[0-9A-Za-z_-]{35}      # Google API Key
ghp_[a-zA-Z0-9]{36}        # GitHub PAT
glpat-[a-zA-Z0-9-_]{20}    # GitLab PAT
```
