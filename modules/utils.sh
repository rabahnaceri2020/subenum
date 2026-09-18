#!/bin/bash
# subenum - Utility functions module
# Trimmed from reconFTW (modules/utils.sh) to only what subdomain enumeration needs.
# This file is sourced by subenum.sh - do not execute directly
[[ -z "${SCRIPTPATH:-}" ]] && {
    echo "Error: This module must be sourced by subenum.sh" >&2
    exit 1
}

###############################################################################################################
########################################## OPTIONS & MGMT #####################################################
###############################################################################################################

# Remove out-of-scope entries from a file.
# Usage: deleteOutScoped <oos_file> <target_file>
function deleteOutScoped() {
    if [[ -s "$1" ]]; then
        while IFS= read -r outscoped; do
            [[ -z "$outscoped" ]] && continue
            # Escape regex metacharacters including / to prevent sed delimiter injection
            local escaped
            escaped=$(printf '%s' "$outscoped" | sed 's/[.[\*^$()+?{|/\\]/\\&/g')
            if grep -q "^[*]" <<<"$outscoped"; then
                escaped=$(printf '%s' "${outscoped:1}" | sed 's/[.[\*^$()+?{|/\\]/\\&/g')
                sed_i "/${escaped}$/d" "$2"
            else
                sed_i "/${escaped}/d" "$2"
            fi
        done <"$1"
    fi
}

function cleanup_on_exit() {
    local exit_code="${1:-130}"
    printf "\n%b[%s] Interrupted. Cleaning up...%b\n" "$bred" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"

    # Kill any background processes we spawned (safely)
    local pids
    pids=$(jobs -p 2>/dev/null) || true
    if [[ -n "$pids" ]]; then
        echo "$pids" | while read -r pid; do
            [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
        done
    fi

    # Log the interruption
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Interrupted by signal (exit code: $exit_code)" >>"${LOGFILE:-/dev/null}"

    exit "$exit_code"
}

# Remove stale .inprogress_<fn> sentinels on EXIT (clean-exit only).
function _cleanup_inprogress() {
    [[ "${_RECON_CLEAN_EXIT:-false}" == "true" ]] || return 0
    [[ -n "${called_fn_dir:-}" ]] && rm -f "${called_fn_dir}"/.inprogress_* 2>/dev/null
    return 0
}

function rotate_logs() {
    local log_dir="$1"
    local max_logs="${2:-10}"
    local max_age_days="${3:-30}"

    [[ ! -d "$log_dir" ]] && return 0

    # Delete logs older than max_age_days
    find "$log_dir" -name "*.txt" -type f -mtime +"${max_age_days}" -delete 2>/dev/null || true

    # If still too many, keep only the newest max_logs
    local count
    count=$(find "$log_dir" -name "*.txt" -type f 2>/dev/null | wc -l)
    if [[ $count -gt $max_logs ]]; then
        find "$log_dir" -name "*.txt" -type f -printf '%T@ %p\n' 2>/dev/null \
            | sort -n | head -n $((count - max_logs)) | cut -d' ' -f2- \
            | xargs -r rm -f -- 2>/dev/null || true
    fi
}

function validate_config() {
    local warnings=0
    local errors=0

    # Validate numeric thread/rate variables
    for var in DNSX_THREADS DNSX_RATE_LIMIT TLSX_THREADS PERMUTATIONS_SHORT_THRESHOLD DNSTAKE_THREADS; do
        if [[ -n "${!var:-}" && ! "${!var}" =~ ^[0-9]+$ ]]; then
            print_errorf "%s must be numeric, got: %s" "$var" "${!var}"
            errors=$((errors + 1))
        fi
    done

    if [[ -n "${PERMUTATIONS_WORDLIST_MODE:-}" ]]; then
        case "${PERMUTATIONS_WORDLIST_MODE}" in
            auto|full|short) : ;;
            *)
                print_warnf "PERMUTATIONS_WORDLIST_MODE invalid: '%s' (use auto|full|short)" "${PERMUTATIONS_WORDLIST_MODE}"
                warnings=$((warnings + 1))
                ;;
        esac
    fi
    if [[ -n "${DNS_RESOLVER:-}" ]]; then
        case "${DNS_RESOLVER}" in
            auto|puredns|dnsx) : ;;
            *)
                print_warnf "DNS_RESOLVER invalid: '%s' (use auto|puredns|dnsx)" "${DNS_RESOLVER}"
                warnings=$((warnings + 1))
                ;;
        esac
    fi

    if [[ $errors -gt 0 ]]; then
        print_errorf "Configuration has %d error(s). Please fix before running." "$errors"
        return $E_CONFIG
    fi
    if [[ $warnings -gt 0 ]]; then
        print_notice INFO "config" "Configuration has ${warnings} warning(s)."
    fi
    return 0
}

# Auto-tune concurrency knobs according to host resources and PERF_PROFILE.
# Usage: apply_performance_profile
function apply_performance_profile() {
    # shellcheck disable=SC2034  # Thread/rate vars are consumed by sourced modules at runtime
    local profile="${PERF_PROFILE:-balanced}"
    local cores mem_gb

    cores=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        mem_gb=$(( $(sysctl -n hw.memsize 2>/dev/null || echo 8589934592) / 1024 / 1024 / 1024 ))
    else
        mem_gb=$(( $(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 8388608) / 1024 / 1024 ))
    fi
    [[ "$cores" =~ ^[0-9]+$ ]] || cores=4
    [[ "$mem_gb" =~ ^[0-9]+$ ]] || mem_gb=8

    case "$profile" in
        low)
            PARALLEL_MAX_JOBS=${PARALLEL_MAX_JOBS:-2}
            ;;
        max)
            PARALLEL_MAX_JOBS=${PARALLEL_MAX_JOBS:-$((cores > 2 ? cores - 1 : 2))}
            ;;
        *)
            PARALLEL_MAX_JOBS=${PARALLEL_MAX_JOBS:-$((cores > 1 ? cores / 2 : 1))}
            ;;
    esac

    # Clamp aggressive defaults for low-memory hosts.
    if [[ "$mem_gb" -lt 6 ]]; then
        ((PARALLEL_MAX_JOBS > 2)) && PARALLEL_MAX_JOBS=2
    fi

    ((PARALLEL_MAX_JOBS < 1)) && PARALLEL_MAX_JOBS=1
    PERF_PROFILE_INFO="PERF_PROFILE=${profile} | cores=${cores} mem=${mem_gb}GB | jobs=${PARALLEL_MAX_JOBS}"
}

function getElapsedTime {
    # Sets $runtime (for backward compat) and also prints to stdout
    runtime=""
    local T=$(($2 - $1))
    local D=$((T / 60 / 60 / 24))
    local H=$((T / 60 / 60 % 24))
    local M=$((T / 60 % 60))
    local S=$((T % 60))
    ((D > 0)) && runtime="${runtime}${D} days, "
    ((H > 0)) && runtime="${runtime}${H} hours, "
    ((M > 0)) && runtime="${runtime}${M} minutes, "
    runtime="${runtime}${S} seconds."
}

# Lightweight log helper for non-fatal explanations
# Usage: log_note "message" [function] [line]
function log_note() {
    local msg="$1"
    local fn="${2:-main}"
    local ln="${3:-0}"
    local ts
    ts="$(date +'%Y-%m-%d %H:%M:%S')"
    echo "[$ts] NOTE @ ${fn}:${ln} :: ${msg}" >>"${LOGFILE:-/dev/null}"
}

# Explain common non-fatal ERRs (e.g., anew -q with no new lines)
# Usage: explain_err <rc> <cmd> <func> <line>
function explain_err() {
    local rc="$1"
    local cmd="$2"
    local fn="$3"
    local ln="$4"

    [[ $rc -ne 1 ]] && return 0

    # Detect 'anew -q <target>' and emit a helpful note
    if [[ $cmd =~ \banew[[:space:]]+-q[[:space:]]+([^[:space:]]+) ]]; then
        local target="${BASH_REMATCH[1]}"

        # Strip quotes
        target="${target%\"}"
        target="${target#\"}"
        target="${target%\'}"
        target="${target#\'}"

        if [[ -z "$target" ]]; then
            log_note "anew returned no new lines (target unresolved)" "$fn" "$ln"
        elif [[ ! -e "$target" ]]; then
            log_note "anew target missing: $target (likely upstream produced no data)" "$fn" "$ln"
        elif [[ ! -s "$target" ]]; then
            log_note "anew target empty: $target (no new lines to add)" "$fn" "$ln"
        else
            log_note "anew returned no new lines for $target" "$fn" "$ln"
        fi
        return 0
    fi

    # Generic note for wc -l failures (often from missing input in pipelines)
    if [[ $cmd =~ \bwc[[:space:]]+-l\b ]]; then
        log_note "wc -l failed (likely upstream pipeline had no input or a missing file)" "$fn" "$ln"
        return 0
    fi
}

# Check available disk space
# Usage: check_disk_space <required_gb> <path>
# Returns 0 if enough space, 1 otherwise
function check_disk_space() {
    local required_gb="$1"
    local check_path="${2:-.}"

    # Get available space in GB (portable across macOS/Linux).
    local available_gb
    available_gb=$(df -Pk "$check_path" 2>/dev/null | awk 'NR==2 {print int($4 / 1024 / 1024)}')

    if [ -z "$available_gb" ] || [ "$available_gb" -lt "$required_gb" ]; then
        DISK_SPACE_INFO="Disk space LOW: required ${required_gb}GB, available ${available_gb:-0}GB at ${check_path}"
        return 1
    fi

    DISK_SPACE_INFO="Disk space OK: ${available_gb}GB available at ${check_path}"
    return 0
}

# Mid-run disk-full check: thin wrapper around check_disk_space using MIN_DISK_SPACE_GB.
function _check_disk_mid_run() {
    check_disk_space "${MIN_DISK_SPACE_GB:-5}" "${dir:-.}"
    return $?
}

# Hard-abort the run on disk-full mid-run detection.
function _abort_disk_full() {
    _print_error "disk_full: aborting (${DISK_SPACE_INFO:-disk space exhausted})"
    exit 1
}

# Execute command in dry-run mode if enabled
# Usage: run_command <command> [args...]
function run_command() {
    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        # Extract tool name (first word, strip path)
        local tool_name="${1##*/}"
        local full_cmd="$*"
        local redacted_cmd="$full_cmd"

        if declare -F redact_secrets >/dev/null 2>&1; then
            redacted_cmd=$(redact_secrets "$redacted_cmd")
        fi

        # Track command for module summary
        if declare -F ui_dryrun_track >/dev/null 2>&1; then
            ui_dryrun_track "$tool_name" "$redacted_cmd"
        else
            printf "%b[DRY-RUN] Would execute: %s%b\n" "$yellow" "$redacted_cmd" "$reset"
        fi
        return 0
    fi

    if [[ -n "${DEBUG_LOG:-}" ]]; then
        if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
            "$@" 2> >(tee -a "$DEBUG_LOG" >&2)
        else
            "$@" 2>>"$DEBUG_LOG"
        fi
    else
        "$@"
    fi
}

# Cross-platform sed_i wrapper
# Usage: sed_i 's/old/new/g' file.txt
function sed_i() {
    if [[ $# -lt 2 ]]; then
        echo "Usage: sed_i 'pattern' file" >&2
        return 1
    fi

    local pattern="$1"
    local file="$2"

    if sed --version >/dev/null 2>&1; then
        # GNU sed (Linux or installed via brew on macOS)
        sed -i "$pattern" "$file"
    else
        # BSD sed (default macOS)
        sed -i '' "$pattern" "$file"
    fi
}

###############################################################################################################
####################################### SECURITY ##############################################################
###############################################################################################################

# Sanitize domain input to prevent command injection.
# Accepts bare domains, URLs (strips scheme/userinfo/path/query/fragment/port),
# and IPv4 addresses (validated inline — octets > 255 rejected).
# Usage: sanitize_domain <domain_or_url>
# Returns: sanitized domain (lowercase) or IPv4
function sanitize_domain() {
    local input_domain="$1"
    local working="$input_domain"

    # 1) Strip scheme (scheme://)
    if [[ "$working" =~ ^[a-zA-Z][a-zA-Z0-9+.-]*:// ]]; then
        working="${working#*://}"
    fi

    # 2) Cut at first / ? # (path / query / fragment).
    working="${working%%[/?#]*}"

    # 3) Strip userinfo (user:pass@host)
    if [[ "$working" == *@* ]]; then
        working="${working##*@}"
    fi

    # 4) Strip :port
    working="${working%%:*}"

    # 5) IPv4 post-normalization: redirect to inline octet validation.
    if [[ "$working" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        local -a _octs
        IFS='.' read -ra _octs <<<"$working"
        local _o
        for _o in "${_octs[@]}"; do
            if (( _o > 255 )); then
                print_errorf "Invalid IP octet in '%s'" "$input_domain"
                return 1
            fi
        done
        echo "$working"
        return 0
    fi

    # 6) Hardening: char whitelist + lowercase + trim leading/trailing dots/hyphens
    local sanitized
    sanitized=$(echo "$working" | tr -cd 'a-zA-Z0-9.-')
    sanitized=$(echo "$sanitized" | tr '[:upper:]' '[:lower:]')
    sanitized=$(echo "$sanitized" | sed 's/^[.-]*//; s/[.-]*$//')

    if [[ -z "$sanitized" ]]; then
        print_errorf "Invalid domain after sanitization: '%s'" "$input_domain"
        return 1
    fi

    if [[ ! "$sanitized" =~ \. ]]; then
        print_warnf "Domain '%s' has no TLD, may be invalid" "$sanitized" >&2
    fi

    echo "$sanitized"
    return 0
}

# Validate and sanitize IP/CIDR input
# Usage: sanitize_ip <ip_or_cidr>
function sanitize_ip() {
    local input="$1"
    local sanitized

    sanitized=$(echo "$input" | tr -cd '0-9./,')
    if [[ -z "$sanitized" ]]; then
        print_errorf "Invalid IP/CIDR after sanitization: '%s'" "$input"
        return 1
    fi

    echo "$sanitized"
    return 0
}

# Sanitize a single entry from a -l list file.
# Usage: domain=$(_sanitize_list_entry "$raw") || continue
_sanitize_list_entry() {
    local raw="$1"
    if [[ "$raw" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
        sanitize_ip "$raw"
    else
        sanitize_domain "$raw"
    fi
}

###############################################################################################################
####################################### DEEP HELPERS ##########################################################
###############################################################################################################

# Check if we should run in DEEP mode based on flag or item count
# Usage: should_run_deep <count> [limit]
function should_run_deep() {
    local count="${1:-0}"
    local limit="${2:-$DEEP_LIMIT}"

    [[ "$DEEP" == true ]] && return 0
    [[ "$count" -le "$limit" ]] && return 0
    return 1
}

function should_run_deep2() {
    local count="${1:-0}"
    should_run_deep "$count" "${DEEP_LIMIT2:-500}"
}

###############################################################################################################
####################################### RESOURCE CACHE ########################################################
###############################################################################################################

CACHE_DIR="${SCRIPTPATH}/.cache"
CACHE_MAX_AGE_DAYS="${CACHE_MAX_AGE_DAYS:-30}"

function cache_init() {
    mkdir -p "$CACHE_DIR"/{wordlists,resolvers,tools}
}

# Resolve TTL per cache type.
function cache_max_age_for_type() {
    case "${1:-tools}" in
        resolvers) echo "${CACHE_MAX_AGE_DAYS_RESOLVERS:-${CACHE_MAX_AGE_DAYS:-30}}" ;;
        wordlists) echo "${CACHE_MAX_AGE_DAYS_WORDLISTS:-${CACHE_MAX_AGE_DAYS:-30}}" ;;
        tools|*) echo "${CACHE_MAX_AGE_DAYS_TOOLS:-${CACHE_MAX_AGE_DAYS:-30}}" ;;
    esac
}

# Check if cached file is still valid
# Usage: cache_is_valid <cache_file> [cache_type]
function cache_is_valid() {
    local cache_file="$1"
    local cache_type="${2:-tools}"
    local max_age_days
    max_age_days=$(cache_max_age_for_type "$cache_type")

    [[ ! -f "$cache_file" ]] && return 1
    [[ "${CACHE_REFRESH:-false}" == "true" ]] && return 1

    local file_mtime
    if [[ "$(uname -s)" == "Darwin" ]]; then
        file_mtime=$(stat -f "%m" "$cache_file" 2>/dev/null)
    else
        file_mtime=$(stat -c "%Y" "$cache_file" 2>/dev/null)
    fi

    if [[ -z "$file_mtime" ]] || ! [[ "$file_mtime" =~ ^[0-9]+$ ]]; then
        return 1
    fi

    local current_time
    current_time=$(date +%s)
    local file_age_seconds=$((current_time - file_mtime))
    local file_age_days=$((file_age_seconds / 86400))

    if [ "$file_age_days" -lt "$max_age_days" ]; then
        return 0
    else
        return 1
    fi
}

# Download file with caching support
function cached_download() {
    cached_download_typed "$1" "$2" "${3:-$(basename "$1")}" "tools"
}

# Download file with typed cache support
# Usage: cached_download_typed <url> <destination> [cache_name] [cache_type]
function cached_download_typed() {
    local url="$1"
    local destination="$2"
    local cache_name="${3:-$(basename "$url")}"
    local cache_type="${4:-tools}"
    local cache_file="$CACHE_DIR/$cache_type/$cache_name"
    local -a curl_cmd

    cache_init

    # Check if we have valid cached version
    if cache_is_valid "$cache_file" "$cache_type"; then
        cp "$cache_file" "$destination"
        return 0
    fi

    mkdir -p "$(dirname "$cache_file")"
    mkdir -p "$(dirname "$destination")" 2>/dev/null || true

    curl_cmd=(curl -sL "$url" -o "$destination")
    if [[ "$cache_type" == "resolvers" ]]; then
        curl_cmd=(
            curl -fsSL
            --connect-timeout "${RESOLVER_DOWNLOAD_CONNECT_TIMEOUT:-10}"
            --max-time "${RESOLVER_DOWNLOAD_MAX_TIME:-120}"
            --retry "${RESOLVER_DOWNLOAD_RETRY:-2}"
            --retry-delay "${RESOLVER_DOWNLOAD_RETRY_DELAY:-2}"
            --retry-connrefused
            "$url" -o "$destination"
        )
    fi

    if run_command "${curl_cmd[@]}"; then
        # Save to cache for future use
        cp "$destination" "$cache_file" 2>/dev/null || true
        return 0
    else
        printf "%b[%s] Download failed: %s%b\n" \
            "$bred" "$(date +'%Y-%m-%d %H:%M:%S')" "$url" "$reset" >&2
        return 1
    fi
}

# Clear old cache files
function cache_clean() {
    local max_age="${1:-${CACHE_MAX_AGE_DAYS:-30}}"

    [[ ! -d "$CACHE_DIR" ]] && return 0

    local cleaned=0
    local current_time
    current_time=$(date +%s)

    while IFS= read -r -d '' file; do
        local file_mtime
        if [[ "$(uname -s)" == "Darwin" ]]; then
            file_mtime=$(stat -f "%m" "$file" 2>/dev/null)
        else
            file_mtime=$(stat -c "%Y" "$file" 2>/dev/null)
        fi

        [[ -z "$file_mtime" ]] || ! [[ "$file_mtime" =~ ^[0-9]+$ ]] && continue

        local file_age_seconds=$((current_time - file_mtime))
        local file_age_days=$((file_age_seconds / 86400))

        if [ $file_age_days -gt $max_age ]; then
            rm -f "$file"
            cleaned=$((cleaned + 1))
        fi
    done < <(find "$CACHE_DIR" -type f -print0 2>/dev/null)

    if [ $cleaned -gt 0 ]; then
        printf "%b[%s] Cleaned %d expired cache files%b\n" \
            "$bgreen" "$(date +'%Y-%m-%d %H:%M:%S')" "$cleaned" "$reset"
    fi
}

###############################################################################################################
####################################### WORDLIST HELPERS ######################################################
###############################################################################################################

# Ensure a plaintext wordlist exists; if missing, try to expand a sibling .gz file.
# Usage: ensure_wordlist_file <path>
function ensure_wordlist_file() {
    local file="$1"
    local gz_file="${file}.gz"

    # Prefer existing plaintext.
    [[ -s "$file" ]] && return 0
    [[ ! -s "$gz_file" ]] && return 1

    command -v gzip >/dev/null 2>&1 || return 1

    mkdir -p "$(dirname "$file")" 2>/dev/null || true

    local tmp
    if command -v mktemp >/dev/null 2>&1; then
        tmp="$(mktemp "${file}.tmp.XXXXXX" 2>/dev/null || true)"
    fi
    [[ -z "${tmp:-}" ]] && tmp="${file}.tmp.$$"

    if gzip -dc "$gz_file" >"$tmp" 2>/dev/null; then
        mv -f "$tmp" "$file"
        return 0
    fi

    rm -f "$tmp" 2>/dev/null || true
    return 1
}

###############################################################################################################
########################################## DNS RESOLVER AUTO-DETECTION ########################################
###############################################################################################################

# Get the primary local IP address (cross-platform: macOS + Linux).
_get_local_ip() {
    local ip=""
    if [[ "$(uname)" == "Darwin" ]]; then
        local iface
        iface=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
        [[ -n "$iface" ]] && ip=$(ipconfig getifaddr "$iface" 2>/dev/null)
    else
        ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1); exit}')
        [[ -z "$ip" ]] && ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
    echo "$ip"
}

# Cached resolver selection for this run when DNS_RESOLVER=auto.
DNS_RESOLVER_SELECTED="${DNS_RESOLVER_SELECTED:-}"

# Return 0 if the IP looks like a publicly routable IPv4 address.
_ip_is_public_ipv4() {
    local ip="$1"
    [[ -z "$ip" ]] && return 1

    local -a parts
    IFS='.' read -ra parts <<<"$ip"
    [[ ${#parts[@]} -ne 4 ]] && return 1

    local o1="${parts[0]}" o2="${parts[1]}" o3="${parts[2]}" o4="${parts[3]}"

    local o
    for o in "$o1" "$o2" "$o3" "$o4"; do
        [[ "$o" =~ ^[0-9]+$ ]] || return 1
        [[ "$o" -ge 0 ]] && [[ "$o" -le 255 ]] || return 1
    done

    [[ "$o1" -eq 0 ]] && return 1
    [[ "$o1" -eq 10 ]] && return 1
    [[ "$o1" -eq 127 ]] && return 1
    [[ "$o1" -eq 169 ]] && [[ "$o2" -eq 254 ]] && return 1
    [[ "$o1" -eq 172 ]] && [[ "$o2" -ge 16 ]] && [[ "$o2" -le 31 ]] && return 1
    [[ "$o1" -eq 192 ]] && [[ "$o2" -eq 168 ]] && return 1
    [[ "$o1" -eq 100 ]] && [[ "$o2" -ge 64 ]] && [[ "$o2" -le 127 ]] && return 1
    [[ "$o1" -ge 224 ]] && return 1

    return 0
}

# Check if a cloud metadata endpoint is reachable.
_is_cloud_vps() {
    [[ "${DRY_RUN:-false}" == "true" ]] && return 1
    curl -sf --max-time 2 -o /dev/null http://169.254.169.254/ 2>/dev/null && return 0
    return 1
}

# Determine if puredns is safe to use (public network / cloud VPS).
_can_use_puredns() {
    local ip="$1"
    _ip_is_public_ipv4 "$ip" && return 0
    _is_cloud_vps && return 0
    return 1
}

# Return 0 when the host is behind NAT/CGNAT (use dnsx), 1 otherwise.
_is_behind_nat() {
    if [[ -n "${RECON_BEHIND_NAT:-}" ]]; then
        [[ "$RECON_BEHIND_NAT" == "yes" ]]
        return $?
    fi
    local ip
    ip=$(_get_local_ip)
    if _can_use_puredns "$ip"; then
        return 1
    fi
    return 0
}

# Initialize and cache DNS resolver selection (evaluate once per run).
# Must be called after config is loaded.
init_dns_resolver() {
    local mode="${DNS_RESOLVER:-auto}"
    local ip
    ip=$(_get_local_ip)

    RECON_LOCAL_IP="${ip:-}"
    RECON_BEHIND_NAT="yes"
    if _can_use_puredns "$ip"; then
        RECON_BEHIND_NAT="no"
    fi
    export RECON_LOCAL_IP RECON_BEHIND_NAT

    DNS_RESOLVER_SELECTED=""
    case "$mode" in
        puredns|dnsx)
            DNS_RESOLVER_SELECTED="$mode"
            ;;
        auto|"")
            if [[ "$RECON_BEHIND_NAT" == "no" ]]; then
                DNS_RESOLVER_SELECTED="puredns"
            else
                DNS_RESOLVER_SELECTED="dnsx"
            fi
            ;;
        *)
            print_warnf "DNS_RESOLVER invalid: '%s' (use auto|puredns|dnsx). Defaulting to auto." "$mode"
            if [[ "$RECON_BEHIND_NAT" == "no" ]]; then
                DNS_RESOLVER_SELECTED="puredns"
            else
                DNS_RESOLVER_SELECTED="dnsx"
            fi
            ;;
    esac

    export DNS_RESOLVER_SELECTED
    printf "[%s] DNS resolver selected: %s (DNS_RESOLVER=%s, local_ip=%s, behind_nat=%s)\n" \
        "$(date +'%Y-%m-%d %H:%M:%S')" "$DNS_RESOLVER_SELECTED" "${DNS_RESOLVER:-auto}" "${ip:-}" "$RECON_BEHIND_NAT" >>"${LOGFILE:-/dev/null}"
}

# Select DNS resolver based on DNS_RESOLVER config and NAT detection.
# Returns "puredns" or "dnsx".
_select_dns_resolver() {
    local mode="${DNS_RESOLVER:-auto}"
    case "$mode" in
        puredns) echo "puredns" ;;
        dnsx)    echo "dnsx" ;;
        auto|"")
            if [[ -n "${DNS_RESOLVER_SELECTED:-}" ]]; then
                echo "$DNS_RESOLVER_SELECTED"
            elif _is_behind_nat; then
                echo "dnsx"
            else
                echo "puredns"
            fi
            ;;
        *)
            if [[ -n "${DNS_RESOLVER_SELECTED:-}" ]]; then
                echo "$DNS_RESOLVER_SELECTED"
            elif _is_behind_nat; then
                echo "dnsx"
            else
                echo "puredns"
            fi
            ;;
    esac
}

# Return 0 when timeout should be enforced, 1 when disabled.
_dns_timeout_enabled() {
    case "${1:-0}" in
        "" | 0 | 0s | 0m | 0h | 0d) return 1 ;;
        *) return 0 ;;
    esac
}

# Ensure resolver files required by the selected resolver mode are present.
_ensure_dns_resolver_files() {
    local resolver_mode="$1"

    case "$resolver_mode" in
        dnsx)
            if [[ ! -s "$resolvers_trusted" ]]; then
                print_errorf "Missing required trusted resolvers file for dnsx: %s" "$resolvers_trusted"
                return 1
            fi
            ;;
        puredns)
            if [[ ! -s "$resolvers" ]]; then
                print_errorf "Missing required resolvers file for puredns: %s" "$resolvers"
                return 1
            fi
            if [[ ! -s "$resolvers_trusted" ]]; then
                print_errorf "Missing required trusted resolvers file for puredns: %s" "$resolvers_trusted"
                return 1
            fi
            ;;
        *)
            print_errorf "Unsupported DNS resolver mode: %s" "$resolver_mode"
            return 1
            ;;
    esac

    return 0
}

# Execute DNS command with heartbeat and optional hard-timeout.
_run_dns_with_heartbeat() {
    local label="$1"
    local timeout_value="$2"
    shift 2

    local heartbeat_interval="${DNS_HEARTBEAT_INTERVAL_SECONDS:-20}"
    [[ "$heartbeat_interval" =~ ^[0-9]+$ ]] || heartbeat_interval=20

    if _dns_timeout_enabled "$timeout_value"; then
        if [[ -n "${TIMEOUT_CMD:-}" ]]; then
            run_with_heartbeat "$label" "$heartbeat_interval" "$TIMEOUT_CMD" -k 10s "$timeout_value" "$@"
        else
            warn_once "dns-timeout-command-missing" "DNS timeout requested but timeout command is unavailable; continuing without hard timeout."
            run_with_heartbeat "$label" "$heartbeat_interval" "$@"
        fi
    else
        run_with_heartbeat "$label" "$heartbeat_interval" "$@"
    fi
}

# Resolve a list of domains using the auto-selected resolver.
# Usage: _resolve_domains <input_file> <output_file>
_resolve_domains() {
    local input_file="$1"
    local output_file="$2"
    local resolver
    resolver=$(_select_dns_resolver)

    _ensure_dns_resolver_files "$resolver" || return 1

    if [[ "$resolver" == "dnsx" ]]; then
        local raw_output_file="${output_file}.dnsx.raw"
        if ! _run_dns_with_heartbeat "dns resolve (${resolver})" "${DNS_RESOLVE_TIMEOUT:-0}" \
            dnsx -l "$input_file" -silent -retry 2 \
            -t "${DNSX_THREADS:-25}" -rl "${DNSX_RATE_LIMIT:-100}" \
            -r "$resolvers_trusted" -wt 5 -o "$raw_output_file"; then
            rm -f "$raw_output_file" 2>/dev/null || true
            return 1
        fi
        if [[ -s "$raw_output_file" ]]; then
            cut -d' ' -f1 "$raw_output_file" | sort -u >"$output_file"
        else
            : >"$output_file"
        fi
        rm -f "$raw_output_file" 2>/dev/null || true
    else
        _run_dns_with_heartbeat "dns resolve (${resolver})" "${DNS_RESOLVE_TIMEOUT:-0}" \
            puredns resolve "$input_file" -w "$output_file" \
            -r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
            -l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
            --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" \
            --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
            || return 1
    fi
}

# Bruteforce subdomains using the auto-selected resolver.
# Usage: _bruteforce_domains <wordlist> <target_domain> <output_file>
_bruteforce_domains() {
    local wordlist="$1"
    local target_domain="$2"
    local output_file="$3"
    local resolver
    resolver=$(_select_dns_resolver)

    _ensure_dns_resolver_files "$resolver" || return 1

    if [[ "$resolver" == "dnsx" ]]; then
        local raw_output_file="${output_file}.dnsx.raw"
        if ! _run_dns_with_heartbeat "dns bruteforce (${resolver})" "${DNS_BRUTE_TIMEOUT:-0}" \
            dnsx -d "$target_domain" -w "$wordlist" -silent -retry 2 \
            -t "${DNSX_THREADS:-25}" -rl "${DNSX_RATE_LIMIT:-100}" \
            -r "$resolvers_trusted" -wt 5 -o "$raw_output_file"; then
            rm -f "$raw_output_file" 2>/dev/null || true
            return 1
        fi
        if [[ -s "$raw_output_file" ]]; then
            cut -d' ' -f1 "$raw_output_file" | sort -u >"$output_file"
        else
            : >"$output_file"
        fi
        rm -f "$raw_output_file" 2>/dev/null || true
    else
        _run_dns_with_heartbeat "dns bruteforce (${resolver})" "${DNS_BRUTE_TIMEOUT:-0}" \
            puredns bruteforce "$wordlist" "$target_domain" \
            -w "$output_file" -r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
            -l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
            --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" \
            --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
            || return 1
    fi
}
