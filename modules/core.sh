#!/bin/bash
# subenum - Core framework module (trimmed from reconFTW modules/core.sh)
# Contains: banner, tools check, logging, notifications,
#           lifecycle (start_subfunc/end_subfunc), check_inscope
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
        ["tlsx"]="tlsx"
        ["hakip2host"]="hakip2host"
        ["mapcidr"]="mapcidr"
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

    if ! exec {TRACE_FD}>>"$LOGFILE"; then
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
    fi
}

###############################################################################################################
####################################### LIFECYCLE #############################################################
###############################################################################################################

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
