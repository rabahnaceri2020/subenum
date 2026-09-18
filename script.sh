#!/usr/bin/env bash
# subenum pipeline: enumerate subdomains, diff new ones, then httpx -> katana -> nuclei.

BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOMAIN_LIST="$BASE/domains.txt"
SUBENUM_SCRIPT="$BASE/subenum.sh"
RECON_DIR="$BASE/Recon"
OUT_DIR="$BASE/data"

# subenum flags, e.g. "--deep" or "--only sub_passive,sub_crt"
SUBENUM_OPTS=""

# httpx
HTTPX_TIMEOUT=5
HTTPX_EXTRA_OPTS="-sc -title -cl -wc -td -nc"

# katana
KATANA_DEPTH=1
KATANA_REGEX="\.js$"
KATANA_EXTRA_OPTS="-nc -silent"

# nuclei
NUCLEI_TEMPLATES="/opt/nuclei-templates/"
NUCLEI_STATS_INTERVAL=60
NUCLEI_EXCLUDE_TAGS="ssl"
NUCLEI_EXCLUDE_SEVERITY="info"
NUCLEI_EXCLUDE_IDS="wp-user-enum,erlang-daemon,CVE-2017-5487,git-mailmap,missing-csp,dns-rebinding,self-signed-ssl,mismatched-ssl,expired-ssl,weak-cipher-suites,unauthenticated-varnish-cache-purge"
NUCLEI_EXTRA_OPTS="-silent -stats -nc"

# notify
NOTIFY_ID_HTTPX="httpx"
NOTIFY_ID_TOKENS="tokens"
NOTIFY_ID_BUGS="bugs"

mkdir -p "$OUT_DIR" || { echo "ERROR: Cannot create output directory: $OUT_DIR" >&2; exit 1; }
if [[ ! -f "$DOMAIN_LIST" ]]; then
    echo "ERROR: domain list not found: $DOMAIN_LIST" >&2
    exit 1
fi

for domain in $(cat "$DOMAIN_LIST"); do
    echo "Working on $domain"

    # Clean up bug files at the START of each domain iteration
    rm -f "$OUT_DIR/$domain.httpx" "$OUT_DIR/$domain.nuclei" "$OUT_DIR/$domain.jsurls" "$OUT_DIR/$domain.tokens" 2>/dev/null || true

    # Remove .called_fn file so subenum re-runs all methods
    rm -rf -- "$RECON_DIR/$domain/.called_fn" 2>/dev/null || true

    # Run subenum
    echo -n "Running subenum... "
    start_time=$(date +%s)
    LOG_FILE="/var/log/recon.log"
    if [[ ! -w /var/log ]]; then
        LOG_FILE="$BASE/logs/recon.log"
        mkdir -p "$BASE/logs"
    fi
    echo "========================================" >> "$LOG_FILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting subenum for $domain" >> "$LOG_FILE"
    echo "========================================" >> "$LOG_FILE"
    bash "$SUBENUM_SCRIPT" -d "$domain" $SUBENUM_OPTS >> "$LOG_FILE" 2>&1
    elapsed=$(($(date +%s) - start_time))
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Completed in ${elapsed}s" >> "$LOG_FILE"
    echo "time took ${elapsed}s (log: $LOG_FILE)"

    subfile="$RECON_DIR/$domain/subdomains/subdomains.txt"
    if [[ ! -f "$subfile" ]]; then
        echo "WARNING: Subdomains file not found: $subfile"
        echo "Skipping $domain..."
        continue
    fi

    echo -n "Checking for new subdomains... "
    out_all="$OUT_DIR/$domain.txt.all"
    out_new="$OUT_DIR/$domain.txt.new"
    start_time=$(date +%s)
    anew "$out_all" < "$subfile" > "$out_new"
    elapsed=$(($(date +%s) - start_time))
    new_count=$(wc -l < "$out_new" 2>/dev/null || echo 0)
    echo "found ${new_count} new subdomains (${elapsed}s)"

    # Skip if no new subdomains
    if [[ ! -s "$out_new" ]]; then
        echo "No new subdomains found for $domain, skipping..."
        continue
    fi

    # Run HTTPX
    echo -n "Running httpx (timeout: ${HTTPX_TIMEOUT}s)... "
    start_time=$(date +%s)
    httpx -silent -timeout "$HTTPX_TIMEOUT" $HTTPX_EXTRA_OPTS 2>/dev/null < "$out_new" > "$OUT_DIR/$domain.httpx"
    elapsed=$(($(date +%s) - start_time))
    alive_count=$(wc -l < "$OUT_DIR/$domain.httpx" 2>/dev/null || echo 0)
    echo "found ${alive_count} alive hosts - time took ${elapsed}s"

    # Deduplicate: keep the first full line for each unique combination of all fields after the URL
    if [[ -s "$OUT_DIR/$domain.httpx" ]]; then
        awk '/^https?:\/\// {rest=substr($0, index($0, " ") + 1); if (!seen[rest]++) print $0}' \
            "$OUT_DIR/$domain.httpx" > "$OUT_DIR/$domain.httpx.tmp"
        mv "$OUT_DIR/$domain.httpx.tmp" "$OUT_DIR/$domain.httpx"
        notify -data "$OUT_DIR/$domain.httpx" -id "$NOTIFY_ID_HTTPX" -bulk
    fi

    # Run Katana
    if [[ -s "$OUT_DIR/$domain.httpx" ]]; then
        echo -n "Finding JS files with katana (depth: ${KATANA_DEPTH})... "
        start_time=$(date +%s)
        cut -d " " -f 1 "$OUT_DIR/$domain.httpx" | katana $KATANA_EXTRA_OPTS -d "$KATANA_DEPTH" -mr "$KATANA_REGEX" 2>/dev/null | sort -u > "$OUT_DIR/$domain.jsurls"
        elapsed=$(($(date +%s) - start_time))
        js_count=$(wc -l < "$OUT_DIR/$domain.jsurls" 2>/dev/null || echo 0)
        echo "found ${js_count} JS files - time took ${elapsed}s"
    else
        echo "Skipping katana (no httpx results)"
    fi

    # Run Nuclei Credentials Scan
    if [[ -s "$OUT_DIR/$domain.jsurls" ]]; then
        echo "Scanning for credentials with nuclei..."
        start_time=$(date +%s)
        nuclei -silent -nc -l "$OUT_DIR/$domain.jsurls" -id credentials-disclosure | tee "$OUT_DIR/$domain.tokens"
        elapsed=$(($(date +%s) - start_time))
        echo "Credentials scan completed - time took ${elapsed}s"
        if [[ -s "$OUT_DIR/$domain.tokens" ]]; then
            notify -data "$OUT_DIR/$domain.tokens" -id "$NOTIFY_ID_TOKENS" -bulk
        fi
    else
        echo "Skipping credentials scan (no JS files found)"
    fi

    # Run Full Nuclei Scan
    if [[ -s "$OUT_DIR/$domain.httpx" ]]; then
        echo "Running full nuclei scan..."
        start_time=$(date +%s)
        cut -d " " -f 1 "$OUT_DIR/$domain.httpx" | nuclei -t "$NUCLEI_TEMPLATES" $NUCLEI_EXTRA_OPTS -si "$NUCLEI_STATS_INTERVAL" -etags "$NUCLEI_EXCLUDE_TAGS" -es "$NUCLEI_EXCLUDE_SEVERITY" -eid "$NUCLEI_EXCLUDE_IDS" | tee "$OUT_DIR/$domain.nuclei"
        elapsed=$(($(date +%s) - start_time))
        echo "Full nuclei scan completed - time took ${elapsed}s"
        if [[ -s "$OUT_DIR/$domain.nuclei" ]]; then
            notify -data "$OUT_DIR/$domain.nuclei" -id "$NOTIFY_ID_BUGS" -bulk
        fi
    else
        echo "Skipping full nuclei scan (no httpx results)"
    fi
done
