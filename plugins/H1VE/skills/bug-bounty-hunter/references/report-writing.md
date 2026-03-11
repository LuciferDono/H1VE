# Vulnerability Report Writing Reference

## Pentagon-Grade Report Format

```
# [Vulnerability Type] in [Component/Feature]

## Summary
One-paragraph executive summary: vulnerability, location, business impact.

## Severity
- CVSS Score: X.X (Critical/High/Medium/Low)
- CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Asset
- URL/Endpoint
- Parameter
- Component
- Version

## Vulnerability Details
### Root Cause
### Attack Vector

## Steps to Reproduce
1. Step-by-step instructions
2. With exact URLs and parameters
3. That anyone can follow

## Proof of Concept
- HTTP Request (exact, from Burp)
- HTTP Response (showing impact)
- Screenshots/Video (annotated)
- curl commands for easy reproduction

## Impact
### Business Impact (users affected, data exposed, compliance)
### Technical Impact (what can be done)
### Attack Scenario (realistic exploitation narrative)

## Remediation
### Recommended Fix (specific, actionable)
### Code Fix (if applicable)

## References
- OWASP links, CWE IDs
```

---

## CVSS 3.1 Quick Reference

Attack Vector: Network(N) Adjacent(A) Local(L) Physical(P)
Attack Complexity: Low(L) High(H)
Privileges Required: None(N) Low(L) High(H)
User Interaction: None(N) Required(R)
Scope: Unchanged(U) Changed(C)
Confidentiality/Integrity/Availability: None(N) Low(L) High(H)

### Typical Scores

| Vulnerability | CVSS Range |
|---------------|-----------|
| RCE (unauth) | 9.8-10.0 |
| SQLi (data access) | 8.6-9.8 |
| SSRF to cloud metadata | 7.5-9.1 |
| Stored XSS (admin) | 7.2-8.4 |
| IDOR (sensitive data) | 6.5-8.1 |
| Reflected XSS | 6.1 |
| CSRF (state change) | 4.3-6.5 |
| Open Redirect | 3.4-4.3 |

---

## Impact Assessment

Write impact in business terms, not just technical:
- Instead of "I found an IDOR": "Attacker can access all 2M user profiles including PII, violating GDPR"
- Instead of "There's XSS": "Stored XSS in product reviews affects 50K daily viewers, enabling session theft"

Address: Confidentiality, Integrity, Availability, Scope, Business, Regulatory.

---

## PoC Guidelines

DO: exact HTTP requests, annotated screenshots, curl commands, show impact, video for complex chains, test on own account only.

DON'T: access real user data beyond confirmation, destructive actions, automate at scale, share publicly before fix.

PoC by type: XSS (alert with document.domain), SQLi (show db version), SSRF (internal response), IDOR (other account data), RCE (id/whoami output).

---

## Getting Higher Payouts

1. **Chain vulnerabilities**: open redirect + OAuth = account takeover, SSRF + metadata = RCE
2. **Demonstrate maximum impact**: don't stop at "file read", show what files matter
3. **Include remediation**: shows expertise
4. **Write for non-technical readers**: triagers may not be security experts
5. **Respond quickly**: faster resolution = faster payout

---

## Platform-Specific Tips

### HackerOne
Markdown formatting, file attachments, select weakness from taxonomy, CVSS calculator, check for duplicates first. Signal and Impact metrics determine private invitations.

### Bugcrowd
VRT taxonomy (P1-P4), include all details upfront, Bugcrowd triages first. Apply to private programs based on performance.

### Immunefi
Critical/high smart contract bugs, Foundry/Hardhat PoC tests, demonstrate financial impact, show exact funds at risk, payouts often in crypto.
