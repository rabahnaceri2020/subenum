#!/bin/bash
# subenum - Core framework module (trimmed from reconFTW modules/core.sh)
# Contains: secret redaction, banner, tools check, logging, notifications,
#           lifecycle (start_func/end_func), check_inscope
# This file is sourced by subenum.sh - do not execute directly

# shellcheck disable=SC2154  # Variables defined in subenum.cfg

[[ -z "${SCRIPTPATH:-}" ]] && {
    echo "Error: This module must be sourced by subenum.sh" >&2
    exit 1
}

# pt_header kept as no-op for backward compatibility (used by help())
pt_header() { :; }

# Ensure a safe default for early log redirections
: "${LOGFILE:=/dev/null}"

# Values (not names) registered at runtime from config files or CLI parsing.
REGISTERED_SECRETS=()

# register_secret(): Adds a raw secret VALUE to REGISTERED_SECRETS.
function register_secret() {
    local value="$1"
    [[ -z "$value" || ${#value} -le 4 ]] && return 0

    local existing
    for existing in "${REGISTERED_SECRETS[@]}"; do
        [[ "$existing" == "$value" ]] && return 0
    done
    REGISTERED_SECRETS+=("$value")
}

# redact_secrets(): Redacts registered secrets from a string.
function redact_secrets() {
    local text="$1"
    local redacted="$text"
    local secret

    for secret in "${REGISTERED_SECRETS[@]}"; do
        if [[ -n "$secret" && ${#secret} -gt 4 ]]; then
            redacted="${redacted//$secret/[REDACTED]}"
        fi
    done

    echo "$redacted"
}

###############################################################################################################
################################################### BANNER ####################################################
###############################################################################################################

function banner() {
    printf "\n"
    printf "%b" "${bgreen:-}"
    cat <<'EOF'
                 _                      _
  ___ _   _ ___| |__  ___ _ __  _   _ _ __ ___
 / __| | | / __| '_ \/ _ \ '_ \| | | | '_ ` _ \
 \__ \ |_| \__ \ |_) |  __/ | | | |_| | | | | | |
 |___/\__,_|___/_.__/ \___|_| |_|\__,_|_| |_| |_|

EOF
    printf "%b" "${reset:-}"
    printf "  %bsubdomain enumeration only%b - powered by reconFTW methods\n" "${bblue:-}" "${reset:-}"
    printf "\n"
}

###############################################################################################################
################################################### TOOLS #####################################################
###############################################################################################################

# Check critical dependencies required for basic operation
function check_critical_dependencies() {
    local critical_tools=(
        "bash:Bash shell"
        "python3:Python 3"
        "curl:Curl"
        "jq:JQ JSON processor"
        "anew:anew"
        "unfurl:unfurl"
        "subfinder:subfinder"
        "dnsx:dnsx"
    )

    local missing_critical=()

    for item in "${critical_tools[@]}"; do
        local tool="${item%%:*}"
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_critical+=("$tool")
        fi
    done

    if (( ${#missing_critical[@]} > 0 )); then
        _print_msg WARN "Missing critical dependencies: ${missing_critical[*]}"
        _print_msg WARN "Run ./install.sh to install the required subdomain enumeration tools."
        return 1
    fi

    return 0
}

# Check all tools/wordlists used by subdomain enumeration.
# Usage: tools_installed
function tools_installed() {
    local all_installed=true
    local missing_tools=()

    # Some vendored wordlists are stored compressed to keep the repo small.
    # Expand them on-demand before checking tool/file presence.
    ensure_wordlist_file "${subs_wordlist:-}" || true

    # Check environment variables
    local env_vars=("GOPATH" "GOROOT" "PATH")
    for var in "${env_vars[@]}"; do
        if [[ -z ${!var} ]]; then
            _print_status FAIL "${var} variable"
            all_installed=false
            missing_tools+=("$var environment variable")
        fi
    done

    declare -A tools_files=(
        ["subs_wordlist"]="$subs_wordlist"
        ["resolvers"]="$resolvers"
        ["resolvers_trusted"]="$resolvers_trusted"
    )
    if [[ "${DEEP:-false}" == "true" ]]; then
        tools_files["subs_wordlist_big"]="$subs_wordlist_big"
    fi
    if [[ "${SUBREGEXPERMUTE:-false}" == "true" ]]; then
        tools_files["regulator"]="${tools}/regulator/main.py"
        tools_files["regulator_python"]="${tools}/regulator/venv/bin/python3"
    fi

    declare -A tools_commands=(
        ["python3"]="python3"
        ["curl"]="curl"
        ["wget"]="wget"
        ["gzip"]="gzip"
        ["dig"]="dig"
        ["timeout"]="${TIMEOUT_CMD:-timeout}"
        ["anew"]="anew"
        ["unfurl"]="unfurl"
        ["subfinder"]="subfinder"
        ["puredns"]="puredns"
        ["dnsx"]="dnsx"
        ["dsieve"]="dsieve"
        ["gotator"]="gotator"
        ["analyticsrelationships"]="analyticsrelationships"
        ["csprecon"]="csprecon"
        ["tlsx"]="tlsx"
        ["hakip2host"]="hakip2host"
        ["mapcidr"]="mapcidr"
        ["urlfinder"]="urlfinder"
        ["httpx"]="httpx"
    )
    # massdns is only required by the puredns resolver path.
    if [[ "${DNS_RESOLVER_SELECTED:-}" == "puredns" ]] || [[ "${DNS_RESOLVER:-auto}" == "puredns" ]]; then
        tools_commands["massdns"]="massdns"
    fi
    # Optional/conditional tools
    if [[ "${INSCOPE:-false}" == "true" ]]; then
        tools_commands["inscope"]="inscope"
    fi
    if [[ "${SUBIAPERMUTE:-false}" == "true" ]]; then
        tools_commands["subwiz"]="subwiz"
    fi
    if [[ "${generate_resolvers:-false}" == "true" ]]; then
        tools_commands["dnsvalidator"]="dnsvalidator"
    fi

    for tool in "${!tools_files[@]}"; do
        if [[ ! -s ${tools_files[$tool]} ]]; then
            all_installed=false
            missing_tools+=("$tool")
        fi
    done

    for tool in "${!tools_commands[@]}"; do
        if ! command -v "${tools_commands[$tool]}" >/dev/null 2>&1; then
            all_installed=false
            missing_tools+=("$tool")
        fi
    done

    if [[ $all_installed == true ]]; then
        : # Tools check OK, no output
    else
        local joined=""
        printf -v joined "%s, " "${missing_tools[@]}"
        joined="${joined%, }"
        _print_msg WARN "Pending tools: ${joined}"
    fi

    if [[ ${CHECK_TOOLS_OR_EXIT:-false} == true && $all_installed != true ]]; then
        exit 2
    fi
}

###############################################################################################################
####################################### LOGGING ###############################################################
###############################################################################################################

# Structured JSON logging (optional, controlled by STRUCTURED_LOGGING config)
STRUCTURED_LOGGING=${STRUCTURED_LOGGING:-false}
STRUCTURED_LOG_FILE=""

function log_init() {
    [[ "$STRUCTURED_LOGGING" != "true" ]] && return 0

    STRUCTURED_LOG_FILE="${dir}/.log/structured_$(date +%Y%m%d_%H%M%S).jsonl"
    mkdir -p "$(dirname "$STRUCTURED_LOG_FILE")"

    _print_status OK "Structured logging enabled" "$STRUCTURED_LOG_FILE"
}

# Log structured JSON event
# Usage: log_json <level> <function> <message> [key1=val1] ...
function log_json() {
    [[ "$STRUCTURED_LOGGING" != "true" ]] && return 0
    [[ -z "$STRUCTURED_LOG_FILE" ]] && return 0

    local level="$1"
    local function="$2"
    local message="$3"
    shift 3

    local -a jq_args=(
        --arg ts "$(date -Iseconds)"
        --arg lvl "$level"
        --arg fn "$function"
        --arg msg "$message"
        --arg domain "${domain:-N/A}"
    )
    local jq_expr='{timestamp:$ts, level:$lvl, function:$fn, message:$msg, domain:$domain'
    local idx=0
    for kv in "$@"; do
        if [[ "$kv" =~ ^([^=]+)=(.+)$ ]]; then
            idx=$((idx + 1))
            jq_args+=(--arg "k${idx}" "${BASH_REMATCH[1]}" --arg "v${idx}" "${BASH_REMATCH[2]}")
            jq_expr+=", \"${BASH_REMATCH[1]}\": \$v${idx}"
        fi
    done
    jq_expr+='}'

    jq -cn "${jq_args[@]}" "$jq_expr" >>"$STRUCTURED_LOG_FILE" 2>/dev/null || true
}

# Enable bash xtrace to the current LOGFILE when SHOW_COMMANDS=true.
function enable_command_trace() {
    if [[ ${SHOW_COMMANDS:-false} != true ]]; then
        return
    fi
    [[ -z ${LOGFILE:-} ]] && return

    if [[ -n ${TRACE_FD:-} ]]; then
        exec {TRACE_FD}>&- 2>/dev/null || true
    fi

    if ! exec {TRACE_FD}> >(
        while IFS= read -r line; do
            if declare -F redact_secrets >/dev/null 2>&1; then
                line=$(redact_secrets "$line")
            fi
            printf '%s\n' "$line"
        done >>"$LOGFILE"
    ); then
        return
    fi
    export BASH_XTRACEFD=$TRACE_FD
    export PS4='+ ${BASH_SOURCE##*/}:${LINENO}: '
    set -x
}

###############################################################################################################
####################################### NOTIFICATIONS #########################################################
###############################################################################################################

function notification() {
    if [[ -n $1 ]] && [[ -n $2 ]]; then
        local level="INFO"
        case $2 in
            info) level="INFO" ;;
            warn) level="WARN" ;;
            error) level="FAIL" ;;
            good) level="OK" ;;
        esac

        if declare -F ui_log_jsonl >/dev/null 2>&1; then
            local ui_level="INFO"
            case "$2" in
                info) ui_level="INFO" ;;
                warn) ui_level="WARN" ;;
                error) ui_level="ERROR" ;;
                good) ui_level="SUCCESS" ;;
            esac
            ui_log_jsonl "$ui_level" "${FUNCNAME[1]:-main}" "$1"
        fi

        local should_print=false
        case "$2" in
            error)      should_print=true ;;
            warn)       [[ "${OUTPUT_VERBOSITY:-1}" -ge 1 ]] && should_print=true ;;
            info|good)  [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && should_print=true ;;
        esac

        if [[ "$should_print" != true ]]; then
            return 0
        fi

        print_notice "$level" "${FUNCNAME[1]:-notice}" "$1"
        if [[ "$level" == "WARN" || "$level" == "FAIL" ]]; then
            record_incident "$level" "${FUNCNAME[1]:-notice}" "$1"
        fi
    fi
}

###############################################################################################################
####################################### LIFECYCLE #############################################################
###############################################################################################################

function record_func_timing() {
    local fn="$1"
    local dur="$2"
    FUNC_TIMINGS["$fn"]=$dur 2>/dev/null || true
}

declare -A FUNC_TIMINGS 2>/dev/null || true

function print_timing_summary() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 2 ]] && return 0
    if [[ ${#FUNC_TIMINGS[@]} -eq 0 ]] 2>/dev/null; then
        return 0
    fi

    printf "\n"
    _print_rule
    printf "%b[%s] Performance Timing Summary%b\n\n" "${bblue:-}" "$(date +'%Y-%m-%d %H:%M:%S')" "${reset:-}"

    local total=0
    local fn dur
    local -a sorted_entries=()

    for fn in "${!FUNC_TIMINGS[@]}"; do
        dur=${FUNC_TIMINGS[$fn]}
        if [[ "$dur" =~ ^[0-9]+$ ]]; then
            total=$((total + dur))
            sorted_entries+=("$(printf "%08d %s" "$dur" "$fn")")
        fi
    done

    local entry
    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        dur="${entry%% *}"
        fn="${entry#* }"
        dur=$((10#$dur))
        printf "  %-28s %6s\n" "$fn" "$(format_duration "$dur")"
    done < <(printf '%s\n' "${sorted_entries[@]}" | sort -r)

    printf "  %-28s %6s\n" "TOTAL" "$(format_duration "$total")"
    printf "\n"
}

# Usage: start_func <name> <description>
function start_func() {
    _check_disk_mid_run || _abort_disk_full
    local current_date
    current_date=$(date +'%Y-%m-%d %H:%M:%S')
    echo "[$current_date] Start function: ${1} " >>"${LOGFILE}"
    local _fn_name="${1}"
    printf -v "_start_time_${_fn_name//[^a-zA-Z0-9_]/_}" '%s' "$(date +%s)"
    start=$(date +%s)
    if [[ -n "${called_fn_dir:-}" ]] && [[ "${DRY_RUN:-false}" != "true" ]]; then
        touch "$called_fn_dir/.inprogress_${1}" 2>/dev/null || true
    fi
    log_json "INFO" "${1}" "Function started" "description=${2}"
    if declare -F ui_log_jsonl >/dev/null 2>&1; then
        ui_log_jsonl "INFO" "${1}" "Function started" "description=${2}"
    fi
    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
        _print_msg "INFO" "Running ${1}..."
    fi
}

# Usage: end_func <message> <func> [status]
function end_func() {
    local message="${1:-}"
    local fn="${2:-${FUNCNAME[1]:-unknown}}"
    local status="${3:-}"

    if [[ -n "$status" ]]; then
        case "$status" in
            info|warn|error|good|OK|WARN|FAIL|SKIP|SKIP_CONFIG|SKIP_NOINPUT|CACHE_HIT)
                ;;
            *)
                status="OK"
                ;;
        esac
    else
        case "$fn" in
            info|warn|error|good|OK|WARN|FAIL|SKIP|SKIP_CONFIG|SKIP_NOINPUT|CACHE_HIT)
                status="$fn"
                fn="${FUNCNAME[1]:-unknown}"
                ;;
            *)
                status="OK"
                ;;
        esac
    fi

    if [[ -n "${called_fn_dir:-}" ]] && [[ "${DRY_RUN:-false}" != "true" ]]; then
        rm -f "$called_fn_dir/.inprogress_${fn}" 2>/dev/null || true
        touch "$called_fn_dir/.${fn}" 2>/dev/null || true
    fi
    local end
    end=$(date +%s)
    local _start_var="_start_time_${fn//[^a-zA-Z0-9_]/_}"
    local _fn_start="${!_start_var:-$start}"
    local runtime=""
    getElapsedTime "$_fn_start" "$end"
    record_func_timing "${fn}" "$((end - _fn_start))"
    local duration=$((end - _fn_start))
    local end_date
    end_date=$(date +'%Y-%m-%d %H:%M:%S')
    echo "[$end_date] End function: ${fn} " >>"${LOGFILE}"
    local badge="OK"
    local reason_code=""
    case "$status" in
        info|INFO) badge="INFO" ;;
        warn|WARN) badge="WARN" ;;
        error|ERROR) badge="FAIL" ;;
        good|SUCCESS) badge="OK" ;;
        OK|FAIL|SKIP|CACHE) badge="$status" ;;
        SKIP_CONFIG) badge="SKIP"; reason_code="config" ;;
        SKIP_NOINPUT) badge="SKIP"; reason_code="noinput" ;;
        CACHE_HIT) badge="CACHE"; reason_code="cache" ;;
    esac

    if [[ "$badge" == "OK" ]] && [[ -n "$message" ]]; then
        local msg_lc
        msg_lc=$(printf "%s" "$message" | tr '[:upper:]' '[:lower:]')
        if [[ "$msg_lc" == no\ * ]] && [[ "$msg_lc" == *"skip"* ]]; then
            badge="SKIP"
            reason_code="noinput"
        fi
    fi

    if [[ -n "${called_fn_dir:-}" ]]; then
        printf "%s\n" "$badge" >"${called_fn_dir}/.status_${fn}" 2>/dev/null || true
        if [[ -n "$reason_code" ]]; then
            printf "%s\n" "$reason_code" >"${called_fn_dir}/.status_reason_${fn}" 2>/dev/null || true
        fi
    fi

    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 1 ]]; then
        _print_status "$badge" "${fn}" "${duration}s"
        if [[ -n "$reason_code" ]] && { [[ "$badge" != "CACHE" ]] || [[ "${SHOW_CACHE:-false}" == "true" ]]; }; then
            printf "         reason: %s\n" "$reason_code"
        fi
        if [[ -n "$message" ]] && [[ "$badge" != "OK" && "$badge" != "INFO" ]]; then
            printf "         %s\n" "$message"
            if [[ "$badge" == "FAIL" || "$badge" == "WARN" ]]; then
                record_incident "$badge" "$fn" "$message"
            fi
        fi
    fi
    log_json "SUCCESS" "${fn}" "Function completed" "runtime=${runtime}" "duration_sec=${duration}"
    if declare -F ui_log_jsonl >/dev/null 2>&1; then
        ui_log_jsonl "SUCCESS" "${fn}" "Function completed" "runtime=${runtime}" "duration_sec=${duration}"
    fi

    _check_disk_mid_run || _abort_disk_full

    :
}

function start_subfunc() {
    current_date=$(date +'%Y-%m-%d %H:%M:%S')
    echo "[$current_date] Start subfunction: ${1} " >>"${LOGFILE}"
    start_sub=$(date +%s)
    log_json "INFO" "${1}" "Subfunction started" "description=${2}"
    if declare -F ui_log_jsonl >/dev/null 2>&1; then
        ui_log_jsonl "INFO" "${1}" "Subfunction started" "description=${2}"
    fi
    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
        _print_msg "INFO" "Running ${1}..."
    fi
}

function end_subfunc() {
    if [[ -n "${called_fn_dir:-}" ]] && [[ "${DRY_RUN:-false}" != "true" ]]; then
        touch "$called_fn_dir/.${2}" 2>/dev/null || true
    fi
    end_sub=$(date +%s)
    getElapsedTime "$start_sub" "$end_sub"
    local duration=$((end_sub - start_sub))
    local status="${3:-OK}"
    local badge="$status"
    local reason_code=""
    case "$status" in
        SKIP_CONFIG) badge="SKIP"; reason_code="config" ;;
        SKIP_NOINPUT) badge="SKIP"; reason_code="noinput" ;;
        CACHE_HIT) badge="CACHE"; reason_code="cache" ;;
    esac

    if [[ -n "${called_fn_dir:-}" ]]; then
        printf "%s\n" "$badge" >"${called_fn_dir}/.status_${2}" 2>/dev/null || true
        if [[ -n "$reason_code" ]]; then
            printf "%s\n" "$reason_code" >"${called_fn_dir}/.status_reason_${2}" 2>/dev/null || true
        fi
    fi

    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 1 ]]; then
        _print_status "$badge" "${2}" "${duration}s"
        if [[ -n "$reason_code" ]] && { [[ "$badge" != "CACHE" ]] || [[ "${SHOW_CACHE:-false}" == "true" ]]; }; then
            printf "         reason: %s\n" "$reason_code"
        fi
    fi
    local end_sub_date
    end_sub_date=$(date +'%Y-%m-%d %H:%M:%S')
    echo "[$end_sub_date] End subfunction: ${1} " >>"${LOGFILE}"
    log_json "SUCCESS" "${2}" "Subfunction completed" "runtime=${runtime}" "duration_sec=${duration}"
    if declare -F ui_log_jsonl >/dev/null 2>&1; then
        ui_log_jsonl "SUCCESS" "${2}" "Subfunction completed" "runtime=${runtime}" "duration_sec=${duration}"
    fi
    :
}

# Filter file through the `inscope` tool (in-scope list from -i / .scope file).
function check_inscope() {
    cat "$1" | inscope >"${1}_tmp" && cp "${1}_tmp" "$1" && rm -f "${1}_tmp"
}

function remove_big_files() {
    rm -rf .tmp/gotator*.txt 2>>"${LOGFILE}"
    rm -rf .tmp/brute_recursive_wordlist.txt 2>>"$LOGFILE"
    rm -rf .tmp/subs_no_resolved.txt .tmp/subdomains_dns.txt .tmp/scrap_subs.txt .tmp/analytics_subs_clean.txt .tmp/passive_recursive.txt .tmp/gotator1_recursive.txt .tmp/gotator2_recursive.txt 2>>"$LOGFILE"
    find .tmp -type f -size +200M -exec rm -f {} + 2>>"$LOGFILE"
}

# Asset store helpers are no-ops in subenum (output contract is subdomains/ only).
function append_asset() { :; }
function append_assets_from_file() { :; }
function plugins_emit() { :; }
