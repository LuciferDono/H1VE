# Platform Strategy & Career Guide

## Platform Comparison

| Platform | Focus | Avg Payout | Top Payout | Best For |
|----------|-------|-----------|------------|----------|
| HackerOne | General | $500-5K | $100K+ | Largest, private invites |
| Bugcrowd | General | $300-3K | $50K+ | VRT, application to privates |
| Intigriti | European | $500-5K | $50K+ | EU programs, responsive |
| Immunefi | Web3/DeFi | $10K+ critical | $10M | Highest per-bug payouts |
| YesWeHack | Global/EU | $500-5K | $30K+ | Beginner friendly |
| Synack | Invite-only | $2K-10K | $100K+ | Consistent, vetted |
| Cobalt | Pentest | $1K-8K | N/A | Structured engagements |

### Direct Programs
Apple ($2M max), Microsoft ($17M/yr total), Google ($250K), Meta ($300K), Amazon ($25K), OpenAI ($100K), Shopify ($50K), GitHub ($30K).

---

## Getting Started

### Beginner (0-6 months)
Month 1-2: PortSwigger Academy, Burp Suite, HackTheBox/TryHackMe
Month 3-4: Join 2-3 public programs, focus on ONE vuln class (IDOR/XSS)
Month 5-6: Specialize, build recon automation, target newer programs

### Intermediate (6-18 months)
Expand vuln classes, chain bugs, get private invites, blog/contribute

### Expert (18+ months)
Deep specialization, original research, CVE discoveries, custom tools, conference talks

---

## Earning Strategies

### Maximizing Income
1. Target new programs (less competition)
2. Large scope = more surface
3. Don't spend >4hrs on initial recon per target
4. Move on after 8hrs without results
5. T-shaped: broad foundation, one deep specialty
6. 1 critical > 10 informational

### Revenue by Level
Beginner: $0-500/month (6-12 months)
Intermediate: $2K-5K/month
Advanced: $5K-15K/month
Elite: $15K-50K+/month
Top 1%: $100K+/year
Web3 multiplier: 3-10x for equivalent severity

---

## Building Reputation

### HackerOne
Valid report: +7 rep. N/A: -5. Invites start ~100+, top programs 500+.

### Bugcrowd
Performance-based, accuracy rate matters, manual curation for top programs.

### Tactics
1. Start with programs accepting all severities
2. Quality > quantity (protect accuracy)
3. Respond quickly to triage questions
4. Maintain consistent activity
5. Contribute to community

---

## Legal & Ethical Framework

### ALWAYS
Stay in scope, follow disclosure policy, report through platform, minimize data access, delete collected data, wait for fix.

### NEVER
Access real user data unnecessarily, DoS, test out-of-scope, social engineering, physical access, public disclosure before authorization, demand payment/threaten, sell vulnerabilities.

### Safe Harbor
Legal protection for good-faith research within program terms. Does NOT protect: intentional data theft, service disruption, out-of-scope, other law violations.

### Typical Out-of-Scope
Social engineering, physical attacks, DDoS, third-party services, self-XSS, missing headers without impact, login/logout CSRF, SPF/DKIM/DMARC.

---

## Case Studies

### Highest Payouts
$10M Wormhole (Immunefi), $6M Aurora (Immunefi), $2M Apple, $100K+ multiple HackerOne.

### Famous Finds
- GitHub Enterprise RCE (SSRF + deserialization chain)
- Facebook OAuth token theft (redirect_uri + fragment)
- Uber account takeover (subdomain takeover + cookie scope)
- Shopify admin takeover (exchange token race condition)

Key lesson: bug chaining multiplies impact exponentially.
