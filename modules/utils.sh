#!/bin/bash
# subenum - utility module: file mgmt, sanitization, downloads, DNS resolver
# selection, domain resolution/bruteforce.
# This file is sourced by subenum.sh - do not execute directly
[[ -z "${SCRIPTPATH:-}" ]] && {
    echo "Error: This module must be sourced by subenum.sh" >&2
    exit 1
}

# Remove out-of-scope entries from a file.
# Usage: deleteOutScoped <oos_file> <target_file>
function deleteOutScoped() {
    if [[ -s "$1" ]]; then
        while IFS= read -r outscoped; do
            [[ -z "$outscoped" ]] && continue
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

    local pids
    pids=$(jobs -p 2>/dev/null) || true
    if [[ -n "$pids" ]]; then
        echo "$pids" | while read -r pid; do
            [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
        done
    fi

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

    find "$log_dir" -name "*.txt" -type f -mtime +"${max_age_days}" -delete 2>/dev/null || true

    local count
    count=$(find "$log_dir" -name "*.txt" -type f 2>/dev/null | wc -l)
    if [[ $count -gt $max_logs ]]; then
        find "$log_dir" -name "*.txt" -type f -printf '%T@ %p\n' 2>/dev/null \
            | sort -n | head -n $((count - max_logs)) | cut -d' ' -f2- \
            | xargs -r rm -f -- 2>/dev/null || true
    fi
}

# Sets $runtime (and prints it to stdout).
function getElapsedTime {
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

# Append a note to the run log.
function log_note() {
    local msg="$1"
    local fn="${2:-main}"
    local ln="${3:-0}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] NOTE @ ${fn}:${ln} :: ${msg}" >>"${LOGFILE:-/dev/null}"
}

# Explain common non-fatal ERRs (anew/wc returning 1 with no output).
# Usage: explain_err <rc> <cmd> <func> <line>
function explain_err() {
    local rc="$1"
    local cmd="$2"
    local fn="$3"
    local ln="$4"

    [[ $rc -ne 1 ]] && return 0

    if [[ $cmd =~ \banew[[:space:]]+-q[[:space:]]+([^[:space:]]+) ]]; then
        local target="${BASH_REMATCH[1]}"
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

    if [[ $cmd =~ \bwc[[:space:]]+-l\b ]]; then
        log_note "wc -l failed (likely upstream pipeline had no input or a missing file)" "$fn" "$ln"
        return 0
    fi
}

# Execute a command (dry-run aware, stderr routed to the debug log).
function run_command() {
    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        local tool_name="${1##*/}"
        if declare -F ui_dryrun_track >/dev/null 2>&1; then
            ui_dryrun_track "$tool_name" "$*"
        else
            printf "%b[DRY-RUN] Would execute: %s%b\n" "$yellow" "$*" "$reset"
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

# Cross-platform sed -i wrapper.
function sed_i() {
    if [[ $# -lt 2 ]]; then
        echo "Usage: sed_i 'pattern' file" >&2
        return 1
    fi
    if sed --version >/dev/null 2>&1; then
        sed -i "$1" "$2"
    else
        sed -i '' "$1" "$2"
    fi
}

# Sanitize domain/URL input to prevent command injection.
# Accepts bare domains, URLs and IPv4 addresses.
function sanitize_domain() {
    local input_domain="$1"
    local working="$input_domain"

    [[ "$working" =~ ^[a-zA-Z][a-zA-Z0-9+.-]*:// ]] && working="${working#*://}"
    working="${working%%[/?#]*}"
    [[ "$working" == *@* ]] && working="${working##*@}"
    working="${working%%:*}"

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

# Validate and sanitize IP/CIDR input.
function sanitize_ip() {
    local sanitized
    sanitized=$(echo "$1" | tr -cd '0-9./,')
    if [[ -z "$sanitized" ]]; then
        print_errorf "Invalid IP/CIDR after sanitization: '%s'" "$1"
        return 1
    fi
    echo "$sanitized"
    return 0
}

# Sanitize a single entry from a -l list file.
_sanitize_list_entry() {
    if [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
        sanitize_ip "$1"
    else
        sanitize_domain "$1"
    fi
}

# Ensure a plaintext wordlist exists; expand a sibling .gz if needed.
function ensure_wordlist_file() {
    local file="$1"
    local gz_file="${file}.gz"

    [[ -s "$file" ]] && return 0
    [[ ! -s "$gz_file" ]] && return 1
    command -v gzip >/dev/null 2>&1 || return 1

    mkdir -p "$(dirname "$file")" 2>/dev/null || true

    local tmp
    tmp="$(mktemp "${file}.tmp.XXXXXX" 2>/dev/null || true)"
    [[ -z "${tmp:-}" ]] && tmp="${file}.tmp.$$"

    if gzip -dc "$gz_file" >"$tmp" 2>/dev/null; then
        mv -f "$tmp" "$file"
        return 0
    fi
    rm -f "$tmp" 2>/dev/null || true
    return 1
}

# Download a file (resolvers use stricter timeout/retry settings).
# Usage: _download_file <url> <destination> [resolvers]
function _download_file() {
    local url="$1"
    local dest="$2"
    local kind="${3:-tools}"
    mkdir -p "$(dirname "$dest")" 2>/dev/null || true

    if [[ "$kind" == "resolvers" ]]; then
        run_command curl -fsSL \
            --connect-timeout "${RESOLVER_DOWNLOAD_CONNECT_TIMEOUT:-10}" \
            --max-time "${RESOLVER_DOWNLOAD_MAX_TIME:-120}" \
            --retry "${RESOLVER_DOWNLOAD_RETRY:-2}" \
            --retry-delay "${RESOLVER_DOWNLOAD_RETRY_DELAY:-2}" \
            --retry-connrefused "$url" -o "$dest"
    else
        run_command curl -sL "$url" -o "$dest"
    fi
}

# Refresh resolvers.txt / resolvers_trusted.txt when missing or older than 1 day.
function resolvers_update() {
    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        _print_msg INFO "Dry-run: resolver refresh skipped"
        return 0
    fi

    local need_refresh=false
    local resolvers_stale=false
    local resolvers_trusted_stale=false

    if [[ -s "$resolvers" ]] && [[ -n "$(find "$resolvers" -mtime +1 -print 2>/dev/null)" ]]; then
        resolvers_stale=true
    fi
    if [[ -s "$resolvers_trusted" ]] && [[ -n "$(find "$resolvers_trusted" -mtime +1 -print 2>/dev/null)" ]]; then
        resolvers_trusted_stale=true
    fi
    if [[ ! -s "$resolvers" ]] || [[ ! -s "$resolvers_trusted" ]] || [[ "$resolvers_stale" == true ]] || [[ "$resolvers_trusted_stale" == true ]]; then
        need_refresh=true
    fi

    if [[ $generate_resolvers == true ]]; then
        if [[ "$need_refresh" == true ]]; then
            _print_msg WARN "Resolvers seem older than 1 day. Generating custom resolvers..."
            {
                rm -f -- "$resolvers"
                run_command dnsvalidator -tL https://public-dns.info/nameservers.txt -threads "$DNSVALIDATOR_THREADS" -o "$resolvers" >/dev/null || return 1
                run_command dnsvalidator -tL https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt -threads "$DNSVALIDATOR_THREADS" -o tmp_resolvers >/dev/null
            } 2>>"$LOGFILE"
            [ -s "tmp_resolvers" ] && cat tmp_resolvers | anew -q "$resolvers"
            [ -s "tmp_resolvers" ] && rm -f tmp_resolvers 2>>"$LOGFILE" >/dev/null
            if [[ ! -s "$resolvers" ]] && ! run_command wget -q -O - "${resolvers_url}" >"$resolvers"; then
                _print_msg WARN "Unable to download resolvers from ${resolvers_url}"
                return 1
            fi
            if [[ ! -s "$resolvers_trusted" ]] && ! run_command wget -q -O - "${resolvers_trusted_url}" >"$resolvers_trusted"; then
                _print_msg WARN "Unable to download trusted resolvers from ${resolvers_trusted_url}"
                return 1
            fi
            if [[ ! -s "$resolvers" ]] || [[ ! -s "$resolvers_trusted" ]]; then
                _print_msg WARN "Resolver files are missing or empty after update"
                return 1
            fi
            _print_msg OK "Updated resolvers"
        fi
        generate_resolvers=false
    else
        if [[ "$need_refresh" == true ]]; then
            _print_msg WARN "Resolvers seem older than 1 day. Downloading new resolvers..."
            _download_file "${resolvers_url}" "$resolvers" resolvers || return 1
            _download_file "${resolvers_trusted_url}" "$resolvers_trusted" resolvers || return 1
            if [[ ! -s "$resolvers" ]] || [[ ! -s "$resolvers_trusted" ]]; then
                _print_msg WARN "Resolver files are missing or empty after update"
                return 1
            fi
            _print_msg OK "Resolvers updated"
        fi
    fi
}

function resolvers_optimize_local() {
    sort -u "$resolvers" -o "$resolvers" 2>/dev/null || true
    sort -u "$resolvers_trusted" -o "$resolvers_trusted" 2>/dev/null || true
}

# Get the primary local IP address (macOS + Linux).
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

# Return 0 when a cloud metadata endpoint is reachable.
_is_cloud_vps() {
    [[ "${DRY_RUN:-false}" == "true" ]] && return 1
    curl -sf --max-time 2 -o /dev/null http://169.254.169.254/ 2>/dev/null && return 0
    return 1
}

# Return 0 when puredns is safe to use (public network / cloud VPS).
_can_use_puredns() {
    _ip_is_public_ipv4 "$1" && return 0
    _is_cloud_vps && return 0
    return 1
}

# Return 0 when the host is behind NAT/CGNAT (use dnsx), 1 otherwise.
_is_behind_nat() {
    if [[ -n "${RECON_BEHIND_NAT:-}" ]]; then
        [[ "$RECON_BEHIND_NAT" == "yes" ]]
        return $?
    fi
    _can_use_puredns "$(_get_local_ip)" && return 1
    return 0
}

# Evaluate and cache the DNS resolver selection once per run.
init_dns_resolver() {
    local mode="${DNS_RESOLVER:-auto}"
    local ip
    ip=$(_get_local_ip)

    RECON_LOCAL_IP="${ip:-}"
    RECON_BEHIND_NAT="yes"
    _can_use_puredns "$ip" && RECON_BEHIND_NAT="no"
    export RECON_LOCAL_IP RECON_BEHIND_NAT

    DNS_RESOLVER_SELECTED=""
    case "$mode" in
        puredns|dnsx)
            DNS_RESOLVER_SELECTED="$mode"
            ;;
        *)
            [[ "$mode" != "auto" && -n "$mode" ]] && \
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

# Return "puredns" or "dnsx" based on config and NAT detection.
_select_dns_resolver() {
    local mode="${DNS_RESOLVER:-auto}"
    case "$mode" in
        puredns) echo "puredns" ;;
        dnsx)    echo "dnsx" ;;
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

# Return 0 when a timeout should be enforced, 1 when disabled.
_dns_timeout_enabled() {
    case "${1:-0}" in
        "" | 0 | 0s | 0m | 0h | 0d) return 1 ;;
        *) return 0 ;;
    esac
}

# Ensure the resolver files required by the selected mode are present.
_ensure_dns_resolver_files() {
    case "$1" in
        dnsx)
            if [[ ! -s "$resolvers_trusted" ]]; then
                print_errorf "Missing required trusted resolvers file for dnsx: %s" "$resolvers_trusted"
                return 1
            fi
            ;;
        puredns)
            if [[ ! -s "$resolvers" ]] || [[ ! -s "$resolvers_trusted" ]]; then
                print_errorf "Missing required resolvers files for puredns: %s" "$resolvers"
                return 1
            fi
            ;;
        *)
            print_errorf "Unsupported DNS resolver mode: %s" "$1"
            return 1
            ;;
    esac
    return 0
}

# Execute a DNS command with heartbeat and optional hard timeout.
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
