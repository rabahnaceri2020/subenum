#!/usr/bin/env bash
# subenum pipeline: enumerate subdomains, diff new ones, then httpx -> katana -> nuclei.
# Usage: script.sh [--deep] [-l <domain-list-file>]
# Progress and results stream live: HTTPX hosts, Katana URLs, and Nuclei findings.
# Results are also saved under data/; subenum output is streamed and logged.

BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOMAIN_LIST="$BASE/domains.txt"
SUBENUM_SCRIPT="$BASE/subenum.sh"
RECON_DIR="$BASE/Recon"
OUT_DIR="$BASE/data"

# Additional subenum flags, e.g. "--only sub_passive,sub_crt".
# The wrapper's --deep option overrides method selection with all methods.
SUBENUM_OPTS=""
SUBENUM_CLI_OPTS=()
DEEP_MODE=false

# heartbeat while a step runs (seconds); override with HEARTBEAT_INTERVAL=10
HEARTBEAT_INTERVAL="${HEARTBEAT_INTERVAL:-30}"

# run `git pull` in the subenum repo after the domain loop finishes
GIT_PULL_AFTER_RUN=true

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

# Wait for PID, printing a heartbeat every HEARTBEAT_INTERVAL seconds.
# When a target is given, report the last enumeration stage from its log.
wait_with_heartbeat() {
    local pid="$1" label="$2" start="$3" domain="${4:-}"
    local next=$(( $(date +%s) + HEARTBEAT_INTERVAL ))
    while kill -0 "$pid" 2>/dev/null; do
        sleep 1
        kill -0 "$pid" 2>/dev/null || break
        if (( $(date +%s) >= next )); then
            local stage=""
            if [[ -n "$domain" ]]; then
                local target_log
                target_log=$(ls -t "$RECON_DIR/$domain/.log/"*.txt 2>/dev/null | head -1 || true)
                if [[ -n "$target_log" && -r "$target_log" ]]; then
                    stage=$(grep -aE 'Start subfunction|End subfunction' "$target_log" 2>/dev/null | tail -1 | sed 's/^\[[^]]*\] //' || true)
                fi
            fi
            [[ -n "$stage" ]] && stage=", current: ${stage}"
            log "$label still running (elapsed $(( $(date +%s) - start ))s)${stage}"
            next=$(( $(date +%s) + HEARTBEAT_INTERVAL ))
        fi
    done
    wait "$pid" 2>/dev/null
}

show_help() {
    printf 'Usage: bash %s [--deep] [-l <domain-list-file>]\n\n' "$0"
    printf '%s\n' \
        '  --deep       Enable every enumeration method, deep budgets, and the huge wordlist.' \
        '  -l <file>    Use a domain list (default: domains.txt beside this script).' \
        '  -h, --help   Show this help without running tools.' \
        '' \
        'Without --deep, the existing fast enumeration profile is unchanged.' \
        'Deep runs require the big wordlist and all enumeration dependencies; they can take hours.'
}

# Parse options before creating output files or running any tools.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --deep)
            DEEP_MODE=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        -l)
            if [[ -z "${2:-}" || "$2" == -* ]]; then
                echo "ERROR: -l requires a file argument" >&2
                exit 1
            fi
            DOMAIN_LIST="$2"
            shift 2
            ;;
        *)
            echo "ERROR: unknown argument: $1 (usage: $0 [--deep] [-l <domain-list-file>])" >&2
            exit 1
            ;;
    esac
done

if [[ "$DEEP_MODE" == true ]]; then
    SUBENUM_CLI_OPTS=(--deep --only all --check-tools)
fi

# One pipeline at a time: concurrent runs halve each other's DNS throughput.
LOCK_FILE="$BASE/.pipeline.lock"
if command -v flock >/dev/null 2>&1; then
    exec 9>"$LOCK_FILE" || { echo "ERROR: cannot open lock file: $LOCK_FILE" >&2; exit 1; }
    if ! flock -n 9; then
        echo "ERROR: another subenum pipeline run is already active (lock: $LOCK_FILE)." >&2
        echo "Wait for it to finish, or stop the running wrapper first." >&2
        exit 1
    fi
fi

mkdir -p "$OUT_DIR" || { echo "ERROR: Cannot create output directory: $OUT_DIR" >&2; exit 1; }
if [[ ! -f "$DOMAIN_LIST" ]]; then
    echo "ERROR: domain list not found: $DOMAIN_LIST (use -l <file>)" >&2
    exit 1
fi

log "Target list: $DOMAIN_LIST"
if [[ "$DEEP_MODE" == true ]]; then
    log "Deep enumeration: all methods, huge wordlist, extended budgets (may take hours)"
fi

# Make sure the brute wordlist exists (the vendored .gz is expanded on first run)
WORDLIST_FILE="$BASE/resources/wordlists/subdomains.txt"
if [[ ! -s "$WORDLIST_FILE" && -s "${WORDLIST_FILE}.gz" ]]; then
    log "Expanding subdomains wordlist (first run)..."
    gzip -dc "${WORDLIST_FILE}.gz" > "$WORDLIST_FILE"
fi

pipeline_status=0
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
    ( set -o pipefail; bash "$SUBENUM_SCRIPT" -d "$domain" $SUBENUM_OPTS "${SUBENUM_CLI_OPTS[@]}" 2>&1 | tee -a "$LOG_FILE" ) &
    if wait_with_heartbeat $! "subenum" "$start_time" "$domain"; then
        :
    else
        enum_status=$?
        log "ERROR: subenum failed for $domain (exit ${enum_status}); downstream stages not started"
        printf '%s - Failed with exit %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$enum_status" >> "$LOG_FILE"
        pipeline_status=1
        continue
    fi
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
        continue
    fi

    # Stream and save the first full line for each unique combination of fields after the URL.
    # Flush awk after each result so piping through tee does not delay terminal output.
    log "Running httpx (timeout: ${HTTPX_TIMEOUT}s)..."
    start_time=$(date +%s)
    httpx -silent -timeout "$HTTPX_TIMEOUT" $HTTPX_EXTRA_OPTS 2>/dev/null < "$out_new" \
        | awk '{ key=$0; sub(/^[^ \t]+[ \t]+/, "", key); if (!seen[key]++) { print; fflush(); } }' \
        | tee "$OUT_DIR/$domain.httpx" &
    wait_with_heartbeat $! "httpx" "$start_time"
    elapsed=$(($(date +%s) - start_time))
    alive_count=$(wc -l < "$OUT_DIR/$domain.httpx" 2>/dev/null || echo 0)
    log "httpx: ${alive_count} unique responses (${elapsed}s)"

    if [[ -s "$OUT_DIR/$domain.httpx" ]]; then
        notify_file -data "$OUT_DIR/$domain.httpx" -id "$NOTIFY_ID_HTTPX" -bulk
    fi

    # Run Katana
    if [[ -s "$OUT_DIR/$domain.httpx" ]]; then
        log "Finding JS files with katana (depth: ${KATANA_DEPTH})..."
        start_time=$(date +%s)
        cut -d " " -f 1 "$OUT_DIR/$domain.httpx" \
            | katana $KATANA_EXTRA_OPTS -d "$KATANA_DEPTH" -mr "$KATANA_REGEX" 2>/dev/null \
            | awk '!seen[$0]++ { print; fflush(); }' \
            | tee "$OUT_DIR/$domain.jsurls" &
        wait_with_heartbeat $! "katana" "$start_time"
        # Sort only after streaming: sort in the live pipeline would wait for EOF.
        sort -u "$OUT_DIR/$domain.jsurls" -o "$OUT_DIR/$domain.jsurls"
        elapsed=$(($(date +%s) - start_time))
        js_count=$(wc -l < "$OUT_DIR/$domain.jsurls" 2>/dev/null || echo 0)
        log "katana: ${js_count} JS files (${elapsed}s)"
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
    fi

    # Run Full Nuclei Scan (findings stream live via tee)
    if [[ -s "$OUT_DIR/$domain.httpx" && ! -d "$NUCLEI_TEMPLATES" ]]; then
        log "WARNING: nuclei templates not found at $NUCLEI_TEMPLATES - skipping full nuclei scan"
    elif [[ -s "$OUT_DIR/$domain.httpx" ]]; then
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

# Pull the latest subenum changes after the run
if [[ "$GIT_PULL_AFTER_RUN" == "true" ]]; then
    if git -C "$BASE" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        log "Pulling latest changes (git pull)..."
        if ! git -C "$BASE" pull; then
            log "git pull failed - run it manually in $BASE"
        fi
    else
        log "Skipping git pull ($BASE is not a git repository)"
    fi
fi

exit "$pipeline_status"
