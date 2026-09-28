#!/usr/bin/env bash
# subenum pipeline: enumerate subdomains, diff new ones, then httpx -> katana -> nuclei.
# Usage: script.sh [-l <domain-list-file>]
# Progress is printed live; subenum output is streamed to the terminal and logged.

BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOMAIN_LIST="$BASE/domains.txt"
SUBENUM_SCRIPT="$BASE/subenum.sh"
RECON_DIR="$BASE/Recon"
OUT_DIR="$BASE/data"

# subenum flags, e.g. "--deep" or "--only sub_passive,sub_crt"
SUBENUM_OPTS=""

# heartbeat while a step runs (seconds); override with HEARTBEAT_INTERVAL=10
HEARTBEAT_INTERVAL="${HEARTBEAT_INTERVAL:-30}"

# httpx
HTTPX_TIMEOUT=5
HTTPX_EXTRA_OPTS="-sc -title -wc -nc"

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

# Skip notify calls silently when the binary is not installed
notify_file() { command -v notify >/dev/null 2>&1 && notify "$@"; }

# Timestamped progress line
log() { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }

# Wait for PID, printing a heartbeat every HEARTBEAT_INTERVAL seconds
wait_with_heartbeat() {
    local pid="$1" label="$2" start="$3"
    local next=$(( $(date +%s) + HEARTBEAT_INTERVAL ))
    while kill -0 "$pid" 2>/dev/null; do
        sleep 1
        kill -0 "$pid" 2>/dev/null || break
        if (( $(date +%s) >= next )); then
            log "$label still running (elapsed $(( $(date +%s) - start ))s)"
            next=$(( $(date +%s) + HEARTBEAT_INTERVAL ))
        fi
    done
    wait "$pid" 2>/dev/null || true
}

# -l <file>: use a specific domain list (default: $BASE/domains.txt)
while [[ $# -gt 0 ]]; do
    case "$1" in
        -l)
            if [[ -z "${2:-}" ]]; then
                echo "ERROR: -l requires a file argument" >&2
                exit 1
            fi
            DOMAIN_LIST="$2"
            shift 2
            ;;
        *)
            echo "ERROR: unknown argument: $1 (usage: $0 [-l <domain-list-file>])" >&2
            exit 1
            ;;
    esac
done

mkdir -p "$OUT_DIR" || { echo "ERROR: Cannot create output directory: $OUT_DIR" >&2; exit 1; }
if [[ ! -f "$DOMAIN_LIST" ]]; then
    echo "ERROR: domain list not found: $DOMAIN_LIST (use -l <file>)" >&2
    exit 1
fi

log "Target list: $DOMAIN_LIST"

# Make sure the brute wordlist exists (the vendored .gz is expanded on first run)
WORDLIST_FILE="$BASE/resources/wordlists/subdomains.txt"
if [[ ! -s "$WORDLIST_FILE" && -s "${WORDLIST_FILE}.gz" ]]; then
    log "Expanding subdomains wordlist (first run)..."
    gzip -dc "${WORDLIST_FILE}.gz" > "$WORDLIST_FILE"
fi

for domain in $(cat "$DOMAIN_LIST"); do
    log "Working on $domain"

    # Clean up bug files at the START of each domain iteration
    rm -f "$OUT_DIR/$domain.httpx" "$OUT_DIR/$domain.nuclei" "$OUT_DIR/$domain.jsurls" "$OUT_DIR/$domain.tokens" 2>/dev/null || true

    # Remove .called_fn file so subenum re-runs all methods
    rm -rf -- "$RECON_DIR/$domain/.called_fn" 2>/dev/null || true

    # Run subenum (streamed live to the terminal and appended to the log)
    LOG_FILE="/var/log/recon.log"
    if [[ ! -w /var/log ]]; then
        LOG_FILE="$BASE/logs/recon.log"
        mkdir -p "$BASE/logs"
    fi
    log "Running subenum (log: $LOG_FILE)"
    start_time=$(date +%s)
    {
        echo "========================================"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting subenum for $domain"
        echo "========================================"
    } >> "$LOG_FILE"
    ( bash "$SUBENUM_SCRIPT" -d "$domain" $SUBENUM_OPTS 2>&1 | tee -a "$LOG_FILE" ) &
    wait_with_heartbeat $! "subenum" "$start_time"
    elapsed=$(($(date +%s) - start_time))
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Completed in ${elapsed}s" >> "$LOG_FILE"
    log "subenum finished in ${elapsed}s"

    subfile="$RECON_DIR/$domain/subdomains/subdomains.txt"
    if [[ ! -f "$subfile" ]]; then
        log "WARNING: subdomains file not found: $subfile - skipping $domain"
        continue
    fi

    log "Checking for new subdomains..."
    out_all="$OUT_DIR/$domain.txt.all"
    out_new="$OUT_DIR/$domain.txt.new"
    anew "$out_all" < "$subfile" > "$out_new"
    new_count=$(wc -l < "$out_new" 2>/dev/null || echo 0)
    log "Found ${new_count} new subdomains"

    # Skip if no new subdomains
    if [[ ! -s "$out_new" ]]; then
        log "No new subdomains found for $domain, skipping..."
        continue
    fi

    # Run HTTPX
    log "Running httpx (timeout: ${HTTPX_TIMEOUT}s)..."
    start_time=$(date +%s)
    httpx -silent -timeout "$HTTPX_TIMEOUT" $HTTPX_EXTRA_OPTS 2>/dev/null < "$out_new" > "$OUT_DIR/$domain.httpx" &
    wait_with_heartbeat $! "httpx" "$start_time"
    elapsed=$(($(date +%s) - start_time))
    alive_count=$(wc -l < "$OUT_DIR/$domain.httpx" 2>/dev/null || echo 0)
    log "httpx: ${alive_count} alive hosts (${elapsed}s)"

    # Deduplicate: keep the first full line for each unique combination of all fields after the URL
    if [[ -s "$OUT_DIR/$domain.httpx" ]]; then
        awk '{ key=$0; sub(/^[^ \t]+[ \t]+/, "", key); if (!seen[key]++) print }' \
            "$OUT_DIR/$domain.httpx" > "$OUT_DIR/$domain.httpx.tmp"
        mv "$OUT_DIR/$domain.httpx.tmp" "$OUT_DIR/$domain.httpx"
        notify_file -data "$OUT_DIR/$domain.httpx" -id "$NOTIFY_ID_HTTPX" -bulk
    fi

    # Run Katana
    if [[ -s "$OUT_DIR/$domain.httpx" ]]; then
        log "Finding JS files with katana (depth: ${KATANA_DEPTH})..."
        start_time=$(date +%s)
        cut -d " " -f 1 "$OUT_DIR/$domain.httpx" | katana $KATANA_EXTRA_OPTS -d "$KATANA_DEPTH" -mr "$KATANA_REGEX" 2>/dev/null | sort -u > "$OUT_DIR/$domain.jsurls" &
        wait_with_heartbeat $! "katana" "$start_time"
        elapsed=$(($(date +%s) - start_time))
        js_count=$(wc -l < "$OUT_DIR/$domain.jsurls" 2>/dev/null || echo 0)
        log "katana: ${js_count} JS files (${elapsed}s)"
    else
        log "Skipping katana (no httpx results)"
    fi

    # Run Nuclei Credentials Scan (findings stream live via tee)
    if [[ -s "$OUT_DIR/$domain.jsurls" ]]; then
        log "Scanning for credentials with nuclei..."
        start_time=$(date +%s)
        nuclei -silent -nc -l "$OUT_DIR/$domain.jsurls" -id credentials-disclosure | tee "$OUT_DIR/$domain.tokens" &
        wait_with_heartbeat $! "nuclei credentials" "$start_time"
        elapsed=$(($(date +%s) - start_time))
        log "Credentials scan completed (${elapsed}s)"
        if [[ -s "$OUT_DIR/$domain.tokens" ]]; then
            notify_file -data "$OUT_DIR/$domain.tokens" -id "$NOTIFY_ID_TOKENS" -bulk
        fi
    else
        log "Skipping credentials scan (no JS files found)"
    fi

    # Run Full Nuclei Scan (findings stream live via tee)
    if [[ ! -s "$OUT_DIR/$domain.httpx" ]]; then
        log "Skipping full nuclei scan (no httpx results)"
    elif [[ ! -d "$NUCLEI_TEMPLATES" ]]; then
        log "WARNING: nuclei templates not found at $NUCLEI_TEMPLATES - skipping full nuclei scan"
    else
        log "Running full nuclei scan..."
        start_time=$(date +%s)
        cut -d " " -f 1 "$OUT_DIR/$domain.httpx" | nuclei -t "$NUCLEI_TEMPLATES" $NUCLEI_EXTRA_OPTS -si "$NUCLEI_STATS_INTERVAL" -etags "$NUCLEI_EXCLUDE_TAGS" -es "$NUCLEI_EXCLUDE_SEVERITY" -eid "$NUCLEI_EXCLUDE_IDS" | tee "$OUT_DIR/$domain.nuclei" &
        wait_with_heartbeat $! "nuclei" "$start_time"
        elapsed=$(($(date +%s) - start_time))
        log "Full nuclei scan completed (${elapsed}s)"
        if [[ -s "$OUT_DIR/$domain.nuclei" ]]; then
            notify_file -data "$OUT_DIR/$domain.nuclei" -id "$NOTIFY_ID_BUGS" -bulk
        fi
    fi
done
