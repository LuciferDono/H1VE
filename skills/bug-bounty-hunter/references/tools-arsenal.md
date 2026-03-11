# Bug Bounty Tools Arsenal

## Reconnaissance

| Tool | Purpose | Install |
|------|---------|---------|
| subfinder | Passive subdomain enumeration | go install projectdiscovery/subfinder |
| amass | Comprehensive subdomain enum | go install owasp-amass/amass |
| httpx | HTTP probing & tech detection | go install projectdiscovery/httpx |
| dnsx | DNS resolution & brute force | go install projectdiscovery/dnsx |
| naabu | Fast port scanner | go install projectdiscovery/naabu |
| katana | Web crawler | go install projectdiscovery/katana |
| gau | URLs from archives | go install lc/gau |
| waybackurls | Wayback Machine URLs | go install tomnomnom/waybackurls |
| waymore | Comprehensive URL fetching | pip install waymore |
| assetfinder | Asset discovery | go install tomnomnom/assetfinder |
| theHarvester | OSINT tool | pip install theHarvester |
| shodan | Internet scanning data | pip install shodan |
| gowitness | Web screenshots | go install sensepost/gowitness |

## Scanning & Fuzzing

| Tool | Purpose |
|------|---------|
| nuclei | Template-based vuln scanner |
| ffuf | Web fuzzer (dirs, params, vhosts) |
| feroxbuster | Recursive content discovery |
| dirsearch | Web path scanner |
| sqlmap | SQL injection automation |
| dalfox | XSS scanning |
| arjun | HTTP parameter discovery |
| wpscan | WordPress scanner |
| nikto | Web server scanner |
| whatweb | Tech fingerprinting |
| puredns | DNS resolution & bruteforce |

### Nuclei Quick Reference

Run all: `nuclei -u https://target.com`

By category: `-t cves/`, `-t vulnerabilities/`, `-t exposures/`, `-t misconfiguration/`, `-t takeovers/`

By severity: `-severity critical,high`

By tags: `-tags sqli,xss,ssrf,lfi,rce`

Update: `nuclei -update-templates`

## Exploitation

| Tool | Purpose |
|------|---------|
| sqlmap | SQLi exploitation |
| ysoserial | Java deserialization payloads |
| jwt_tool | JWT testing |
| CrackQL | GraphQL brute-force |
| Clairvoyance | GraphQL schema recovery |
| graphw00f | GraphQL fingerprinting |
| trufflehog | Secret scanning |
| gitleaks | Git secret scanning |
| LinkFinder | JS endpoint extraction |
| SecretFinder | Secrets in JS files |
| subjack | Subdomain takeover detection |

## Burp Suite Essential Extensions

- Autorize: automated authorization testing
- Param Miner: hidden parameter & cache poisoning discovery
- ActiveScan++: enhanced active scanning
- Burp Bounty: custom scan profiles
- Logger++: advanced logging
- Turbo Intruder: fast request sending (race conditions)
- HTTP Request Smuggler: smuggling detection
- JWT Editor: JWT manipulation
- InQL: GraphQL testing
- JS Link Finder: extract JS endpoints
- Retire.js: vulnerable JS library detection
- Collaborator Everywhere: OOB testing

## Mobile Testing

Frida (dynamic instrumentation), Objection (runtime), apktool/jadx (Android decompile), MobSF (framework), Drozer (Android assessment), class-dump (iOS), Ghidra (binary analysis)

## Cloud Security

ScoutSuite (multi-cloud audit), Pacu (AWS exploitation), Prowler (AWS assessment), s3scanner, cloud_enum, kube-hunter (K8s), trivy (container scanner)

## Wordlists

SecLists: directory-list-2.3-medium.txt, subdomains-top1million-5000.txt, special-chars.txt

Assetnote wordlists: wordlists.assetnote.io

FuzzDB: github.com/fuzzdb-project/fuzzdb

## ProjectDiscovery Pipeline

`subfinder -d target.com | dnsx -silent | httpx -silent -td | katana -d 3 -jc | nuclei -severity critical,high`
