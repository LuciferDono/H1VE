#!/bin/bash
# H1VE SWARM Recon Pipeline
# Usage: ./recon-pipeline.sh <domain> <handle>
#
# Outputs to data/recon/{handle}/ with SWARM-compatible filenames:
#   subdomains_raw.txt, resolved.txt, live_hosts.json, endpoints_full.json,
#   tech-stack.json, params.txt, nuclei_results.json
#
# Requires: subfinder, dnsx, httpx, katana, nuclei (checks before use)
# Sends bus messages to supervisor on completion.

set -euo pipefail

DOMAIN="${1:?Usage: $0 <domain> <handle>}"
HANDLE="${2:?Usage: $0 <domain> <handle>}"

# Sanitize handle
if [[ ! "$HANDLE" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "ERROR: Invalid handle '$HANDLE'. Use only alphanumeric, dash, underscore." >&2
    exit 1
fi

OUTPUT_DIR="data/recon/${HANDLE}"
mkdir -p "$OUTPUT_DIR"

echo "[H1VE RECON] Starting pipeline for: $DOMAIN (handle: $HANDLE)"
echo "[H1VE RECON] Output: $OUTPUT_DIR"
echo ""

# Track what tools are available
declare -A HAS_TOOL
for tool in subfinder dnsx httpx katana nuclei gau; do
    if command -v "$tool" &>/dev/null; then
        HAS_TOOL[$tool]=1
    else
        HAS_TOOL[$tool]=0
        echo "[WARN] $tool not found, skipping its phase"
    fi
done

TOTAL_SUBS=0
TOTAL_LIVE=0
TOTAL_URLS=0
TOTAL_PARAMS=0
TOTAL_VULNS=0

# Phase 1: Subdomain Enumeration
echo "[1/6] Subdomain enumeration..."
if [[ "${HAS_TOOL[subfinder]}" == "1" ]]; then
    subfinder -d "$DOMAIN" -all -silent -o "$OUTPUT_DIR/subdomains_raw.txt" 2>/dev/null || true
    TOTAL_SUBS=$(wc -l < "$OUTPUT_DIR/subdomains_raw.txt" 2>/dev/null || echo 0)
    echo "  Found $TOTAL_SUBS subdomains"
else
    # Fallback: basic DNS lookup
    echo "$DOMAIN" > "$OUTPUT_DIR/subdomains_raw.txt"
    TOTAL_SUBS=1
    echo "  Fallback: using root domain only"
fi

# Phase 2: DNS Resolution
echo "[2/6] DNS resolution..."
if [[ "${HAS_TOOL[dnsx]}" == "1" ]] && [[ -s "$OUTPUT_DIR/subdomains_raw.txt" ]]; then
    cat "$OUTPUT_DIR/subdomains_raw.txt" | dnsx -silent -o "$OUTPUT_DIR/resolved.txt" 2>/dev/null || true
    echo "  Resolved $(wc -l < "$OUTPUT_DIR/resolved.txt" 2>/dev/null || echo 0) subdomains"
else
    cp "$OUTPUT_DIR/subdomains_raw.txt" "$OUTPUT_DIR/resolved.txt" 2>/dev/null || true
    echo "  Skipped DNS resolution (dnsx not available)"
fi

# Phase 3: HTTP Probing (outputs JSON for SWARM compatibility)
echo "[3/6] HTTP probing..."
if [[ "${HAS_TOOL[httpx]}" == "1" ]] && [[ -s "$OUTPUT_DIR/resolved.txt" ]]; then
    cat "$OUTPUT_DIR/resolved.txt" | httpx -silent -sc -title -td -json -o "$OUTPUT_DIR/live_hosts.json" 2>/dev/null || true
    TOTAL_LIVE=$(wc -l < "$OUTPUT_DIR/live_hosts.json" 2>/dev/null || echo 0)
    echo "  Found $TOTAL_LIVE live hosts"

    # Extract tech stack into separate file for SCAN agent
    python3 -c "
import json, sys
techs = {}
with open('$OUTPUT_DIR/live_hosts.json') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            host = json.loads(line)
            url = host.get('url', host.get('input', ''))
            tech_list = host.get('tech', [])
            if url and tech_list:
                techs[url] = tech_list
        except json.JSONDecodeError:
            continue
json.dump(techs, open('$OUTPUT_DIR/tech-stack.json', 'w'), indent=2)
" 2>/dev/null || true
    echo "  Tech stack extracted to tech-stack.json"

    # Also extract plain URLs for tools that need them
    python3 -c "
import json
with open('$OUTPUT_DIR/live_hosts.json') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            host = json.loads(line)
            url = host.get('url', host.get('input', ''))
            if url: print(url)
        except json.JSONDecodeError:
            continue
" > "$OUTPUT_DIR/live_urls.txt" 2>/dev/null || true
else
    echo "  Skipped (httpx not available)"
fi

# Phase 4: URL Collection
echo "[4/6] URL collection..."
> "$OUTPUT_DIR/endpoints_full.json" 2>/dev/null || true

if [[ "${HAS_TOOL[katana]}" == "1" ]] && [[ -s "$OUTPUT_DIR/live_urls.txt" ]]; then
    head -50 "$OUTPUT_DIR/live_urls.txt" | while read -r host; do
        katana -u "$host" -d 3 -jc -silent -json 2>/dev/null
    done >> "$OUTPUT_DIR/endpoints_full.json" 2>/dev/null || true
    TOTAL_URLS=$(wc -l < "$OUTPUT_DIR/endpoints_full.json" 2>/dev/null || echo 0)
    echo "  Crawled $TOTAL_URLS endpoints via katana"
fi

if [[ "${HAS_TOOL[gau]}" == "1" ]]; then
    echo "$DOMAIN" | gau --threads 5 2>/dev/null | while read -r url; do
        printf '{"url":"%s","source":"gau"}\n' "$url"
    done >> "$OUTPUT_DIR/endpoints_full.json" 2>/dev/null || true
    TOTAL_URLS=$(wc -l < "$OUTPUT_DIR/endpoints_full.json" 2>/dev/null || echo 0)
    echo "  Total endpoints: $TOTAL_URLS (including gau archives)"
fi

# Phase 5: Parameter Extraction
echo "[5/6] Extracting parameterized URLs..."
python3 -c "
import json
params = set()
with open('$OUTPUT_DIR/endpoints_full.json') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            entry = json.loads(line)
            url = entry.get('url', entry.get('endpoint', ''))
            if '=' in url:
                params.add(url)
        except json.JSONDecodeError:
            if '=' in line:
                params.add(line)
with open('$OUTPUT_DIR/params.txt', 'w') as f:
    for p in sorted(params):
        f.write(p + '\n')
" 2>/dev/null || true
TOTAL_PARAMS=$(wc -l < "$OUTPUT_DIR/params.txt" 2>/dev/null || echo 0)
echo "  Found $TOTAL_PARAMS parameterized URLs"

# Phase 6: Nuclei Scanning (JSON output for SWARM)
echo "[6/6] Nuclei vulnerability scanning..."
if [[ "${HAS_TOOL[nuclei]}" == "1" ]] && [[ -s "$OUTPUT_DIR/live_urls.txt" ]]; then
    mkdir -p "data/scan/${HANDLE}"
    nuclei -list "$OUTPUT_DIR/live_urls.txt" \
        -severity critical,high,medium \
        -json \
        -o "$OUTPUT_DIR/nuclei_results.json" \
        -silent 2>/dev/null || true
    TOTAL_VULNS=$(wc -l < "$OUTPUT_DIR/nuclei_results.json" 2>/dev/null || echo 0)
    echo "  Found $TOTAL_VULNS potential vulnerabilities"
else
    echo "  Skipped (nuclei not available or no live URLs)"
fi

echo ""
echo "[H1VE RECON] Pipeline complete!"
echo ""
echo "Summary:"
echo "  Subdomains:     $TOTAL_SUBS"
echo "  Live hosts:     $TOTAL_LIVE"
echo "  Endpoints:      $TOTAL_URLS"
echo "  Param URLs:     $TOTAL_PARAMS"
echo "  Vulns found:    $TOTAL_VULNS"
echo ""
echo "Files:"
echo "  $OUTPUT_DIR/subdomains_raw.txt"
echo "  $OUTPUT_DIR/resolved.txt"
echo "  $OUTPUT_DIR/live_hosts.json"
echo "  $OUTPUT_DIR/tech-stack.json"
echo "  $OUTPUT_DIR/live_urls.txt"
echo "  $OUTPUT_DIR/endpoints_full.json"
echo "  $OUTPUT_DIR/params.txt"
echo "  $OUTPUT_DIR/nuclei_results.json"

# Send bus message to supervisor if bus is initialized
if [ -d "data/bus/inbox" ]; then
    python3 scripts/bus.py send \
        --from recon --to supervisor --type DONE \
        --subject "Recon complete for $DOMAIN" \
        --payload "{\"handle\": \"$HANDLE\", \"subdomains\": $TOTAL_SUBS, \"live_hosts\": $TOTAL_LIVE, \"endpoints\": $TOTAL_URLS, \"vulns\": $TOTAL_VULNS}" \
        2>/dev/null || true
fi
