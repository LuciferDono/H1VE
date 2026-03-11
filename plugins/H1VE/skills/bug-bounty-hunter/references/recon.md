# Reconnaissance Reference

## Table of Contents
1. [Passive Reconnaissance](#passive-reconnaissance)
2. [Active Reconnaissance](#active-reconnaissance)
3. [Subdomain Enumeration](#subdomain-enumeration)
4. [Content Discovery](#content-discovery)
5. [Technology Fingerprinting](#technology-fingerprinting)
6. [OSINT Intelligence Gathering](#osint-intelligence-gathering)

---

## Passive Reconnaissance

### DNS Enumeration
```bash
# Subfinder - fast passive subdomain enumeration
subfinder -d target.com -all -o subs.txt

# Amass passive enum with all data sources
amass enum -passive -d target.com -o amass_subs.txt

# DNSx - resolve and filter live subdomains
cat subs.txt | dnsx -silent -a -resp -o resolved.txt

# Reverse DNS lookup
dnsx -l ips.txt -ptr -resp-only -o ptr_records.txt
```

### Certificate Transparency Logs
```bash
# Query crt.sh for certificates
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# CertSpotter
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true" | jq -r '.[].dns_names[]' | sort -u

# Censys certificates
censys search "parsed.names: target.com" --index-type certificates
```

### Google Dorking
```
# Find login pages
site:target.com inurl:login OR inurl:signin OR inurl:admin

# Exposed files
site:target.com ext:pdf OR ext:doc OR ext:xls OR ext:csv OR ext:sql OR ext:log

# Config files
site:target.com ext:xml OR ext:json OR ext:yaml OR ext:yml OR ext:env OR ext:ini OR ext:conf

# Error messages revealing info
site:target.com intext:"error" OR intext:"exception" OR intext:"stack trace"

# API endpoints
site:target.com inurl:api OR inurl:v1 OR inurl:v2 OR inurl:graphql OR inurl:rest

# Sensitive directories
site:target.com inurl:backup OR inurl:admin OR inurl:debug OR inurl:test OR inurl:staging

# Password/credential exposure
site:target.com intext:"password" OR intext:"api_key" OR intext:"secret" filetype:env

# S3 buckets
site:s3.amazonaws.com "target"
site:*.s3.amazonaws.com
```

### Shodan / Censys / FOFA
```bash
# Shodan CLI queries
shodan search "ssl.cert.subject.cn:target.com"
shodan search "hostname:target.com"
shodan search "org:'Target Corp'"
shodan search "http.title:'Target Application'"

# Censys search
censys search "services.tls.certificates.leaf.names: target.com"

# FOFA queries
host="target.com"
cert="target.com"
```

### Wayback Machine / Historical Data
```bash
# Waybackurls - fetch all URLs from Wayback Machine
echo "target.com" | waybackurls | sort -u > wayback_urls.txt

# GAU (GetAllUrls) - fetch from multiple archives
echo "target.com" | gau --threads 5 --o gau_urls.txt

# Waymore - comprehensive Wayback fetching
python3 waymore.py -i target.com -mode U -oU waymore_urls.txt

# Filter interesting endpoints from historical data
cat wayback_urls.txt | grep -iE "\.(php|asp|aspx|jsp|json|xml|cfg|conf|env|log|bak|old|sql|zip|tar|gz)$"
cat wayback_urls.txt | grep -iE "(admin|login|dashboard|api|token|key|secret|password|upload|debug)"
cat wayback_urls.txt | grep "=" | sort -u > parameterized_urls.txt
```

### GitHub Reconnaissance
```bash
# GitHub dorking (manual search)
# Search in organization repos:
"target.com" password
"target.com" api_key
"target.com" secret
"target.com" token
org:targetorg password
org:targetorg AWS_ACCESS_KEY
org:targetorg BEGIN RSA PRIVATE KEY

# Trufflehog - automated secret scanning
trufflehog github --org=targetorg --json

# GitDorker
python3 GitDorker.py -tf tokens.txt -q target.com -d dorks/alldorksv3

# gitleaks
gitleaks detect --source=. --report-format=json --report-path=gitleaks.json
```

---

## Active Reconnaissance

### Port Scanning
```bash
# Naabu - fast port scanner
naabu -host target.com -top-ports 1000 -o ports.txt

# Full port scan with service detection
naabu -host target.com -p - -o all_ports.txt

# Nmap service/version detection
nmap -sV -sC -p- -T4 -oA nmap_full target.com

# Nmap targeted scan with scripts
nmap -sV --script=default,vuln -p 80,443,8080,8443 target.com

# Masscan for large IP ranges
masscan -p1-65535 --rate=10000 -oJ masscan.json 10.0.0.0/8
```

### HTTP Probing
```bash
# httpx - probe for live HTTP services
cat subs.txt | httpx -silent -status-code -title -tech-detect -follow-redirects -o live_hosts.txt

# With detailed output
cat subs.txt | httpx -silent -sc -title -td -server -ip -cname -cdn -method -websocket -pipeline -http2 -o detailed_hosts.txt

# Filter by status code
cat subs.txt | httpx -silent -mc 200,301,302,403 -o filtered.txt
```

### Web Crawling
```bash
# Katana - fast web crawler
katana -u https://target.com -d 5 -jc -kf all -aff -o crawled.txt

# Crawl with headless browser mode
katana -u https://target.com -d 3 -headless -jc -o crawled_headless.txt

# Hakrawler
echo "https://target.com" | hakrawler -d 3 -plain | sort -u

# GoSpider
gospider -s "https://target.com" -d 3 -c 10 --other-source --include-subs -o gospider_output
```

---

## Subdomain Enumeration

### Combined Approach
```bash
# Step 1: Passive enumeration from multiple sources
subfinder -d target.com -all -o subfinder.txt
amass enum -passive -d target.com -o amass.txt
findomain -t target.com -q > findomain.txt
assetfinder --subs-only target.com > assetfinder.txt

# Step 2: Merge and deduplicate
cat subfinder.txt amass.txt findomain.txt assetfinder.txt | sort -u > all_subs.txt

# Step 3: DNS resolution / filter live
cat all_subs.txt | dnsx -silent -o resolved_subs.txt

# Step 4: HTTP probe
cat resolved_subs.txt | httpx -silent -o live_subs.txt

# Step 5: Screenshot for visual recon
gowitness file -f live_subs.txt -P screenshots/
```

### Subdomain Bruteforcing
```bash
# Puredns with a wordlist
puredns bruteforce wordlist.txt target.com -r resolvers.txt -o bruteforced.txt

# Shuffledns
shuffledns -d target.com -w wordlist.txt -r resolvers.txt -o shuffled.txt

# Altdns - subdomain permutation
altdns -i subs.txt -w words.txt -o altdns_output.txt
cat altdns_output.txt | dnsx -silent -o alt_resolved.txt
```

### Subdomain Takeover Detection
```bash
# Subjack
subjack -w subs.txt -t 100 -timeout 30 -o takeover.txt -ssl

# Nuclei subdomain takeover templates
nuclei -l subs.txt -t takeovers/ -o takeover_results.txt

# Manual checks - look for:
# - CNAME pointing to unregistered services (Heroku, GitHub Pages, AWS S3, Azure, etc.)
# - "There isn't a GitHub Pages site here" messages
# - NoSuchBucket (S3)
# - "Repository not found" (Bitbucket)
```

---

## Content Discovery

### Directory/File Bruteforcing
```bash
# ffuf - fast fuzzer
ffuf -u https://target.com/FUZZ -w /path/to/wordlist.txt -mc 200,301,302,403 -o ffuf_dirs.txt

# Recursive directory fuzzing
ffuf -u https://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 3

# File extension fuzzing
ffuf -u https://target.com/FUZZ -w wordlist.txt -e .php,.asp,.aspx,.jsp,.html,.js,.json,.xml,.bak,.old,.sql,.zip,.tar.gz,.env,.config

# Feroxbuster - recursive content discovery
feroxbuster -u https://target.com -w wordlist.txt --depth 3 --threads 50

# Dirsearch
dirsearch -u https://target.com -e php,asp,aspx,jsp,html,js -t 50
```

### Parameter Discovery
```bash
# Arjun - HTTP parameter discovery
arjun -u https://target.com/endpoint -m GET POST

# x8 - hidden parameter discovery
x8 -u "https://target.com/endpoint" -w params.txt

# ParamSpider
python3 paramspider.py -d target.com --output params.txt

# From Wayback URLs - extract parameters
cat wayback_urls.txt | grep "?" | unfurl keys | sort -u > param_names.txt
```

### JavaScript Analysis
```bash
# Extract JS files
cat crawled.txt | grep -iE "\.js$" | sort -u > js_files.txt

# LinkFinder - extract endpoints from JS
python3 linkfinder.py -i https://target.com/app.js -o cli

# SecretFinder - find secrets in JS
python3 SecretFinder.py -i https://target.com/app.js -o cli

# Nuclei JS exposure templates
nuclei -l js_files.txt -t exposures/ -o js_secrets.txt

# JSluice - extract URLs and secrets from JS
cat js_files.txt | jsluice urls
cat js_files.txt | jsluice secrets
```

---

## Technology Fingerprinting

### Stack Identification
```bash
# Wappalyzer via httpx
cat live_subs.txt | httpx -td -silent

# WhatWeb
whatweb -a 3 https://target.com

# Webanalyze
webanalyze -host https://target.com -crawl 2

# Check response headers for technology hints
curl -sI https://target.com | grep -iE "(server|x-powered|x-aspnet|x-generator|x-drupal|x-framework)"
```

### CMS Detection
```bash
# WPScan for WordPress
wpscan --url https://target.com --enumerate vp,vt,u --api-token YOUR_TOKEN

# Joomscan for Joomla
joomscan -u https://target.com

# Droopescan for Drupal/Silverstripe/WordPress
droopescan scan drupal -u https://target.com

# CMSeeK - multi-CMS detection
python3 cmseek.py -u https://target.com
```

---

## OSINT Intelligence Gathering

### Email/Employee Discovery
```bash
# theHarvester
theHarvester -d target.com -b all -f harvest.html

# Hunter.io API
curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=KEY"

# LinkedIn reconnaissance (manual)
# Search employees by company, identify roles, tech stack knowledge
```

### IP Range & ASN Discovery
```bash
# ASN lookup
whois -h whois.radb.net -- '-i origin AS12345'

# BGPView
curl "https://api.bgpview.io/asn/12345/prefixes"

# Amass intel for ASN
amass intel -org "Target Corp" -asn 12345

# Find related domains via shared infrastructure
amass intel -d target.com -whois
```

### Cloud Asset Discovery
```bash
# S3 bucket enumeration
python3 s3scanner.py --bucket-file wordlist.txt

# Cloud_enum - multi-cloud enumeration
python3 cloud_enum.py -k target -k targetcorp

# AzureHound for Azure
# ScoutSuite for multi-cloud
scout suite --provider aws --profile default
```
