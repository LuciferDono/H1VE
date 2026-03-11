---
name: recon
description: >
  Quick reconnaissance on a target domain. Runs subfinder, httpx, dnsx, katana pipeline
  without activating full swarm mode. Results go to data/recon/{handle}/.
  Usage: /recon <domain>
---

# Quick Recon

Run the RECON agent's pipeline as a standalone operation without full swarm activation.

## Steps

1. Check installed tools: `which subfinder httpx dnsx katana nuclei`
2. Create output directory: `mkdir -p data/recon/{handle}/`
3. Run the recon pipeline script if available, or execute manually:

```bash
# Subdomains
subfinder -d {domain} -all -recursive -o data/recon/{handle}/subdomains_raw.txt

# DNS resolution
dnsx -l data/recon/{handle}/subdomains_raw.txt -resp -a -aaaa -cname -o data/recon/{handle}/dns_records.txt

# HTTP probing
httpx -l data/recon/{handle}/subdomains_raw.txt -status-code -title -tech-detect -follow-redirects -json -o data/recon/{handle}/live_hosts.json

# Deep crawl
katana -list data/recon/{handle}/live_urls.txt -depth 3 -js-crawl -o data/recon/{handle}/endpoints_raw.txt
```

4. Summarize findings: total subdomains, live hosts, interesting hosts (admin, api, staging), tech stack
5. Save checkpoint to CONTEXT.md

## Fallback

If tools are not installed, fall back to:
- curl-based manual crawl
- DNS lookups via `nslookup` or `dig`
- H1 scope analysis via `h1_scopes {handle}`
