#!/usr/bin/env bash
# lib/common.sh - shared helpers for subenum (dirs, files, output, validation)

[[ -n "${_COMMON_SH_LOADED:-}" ]] && return 0
declare -r _COMMON_SH_LOADED=1

# Create directories with error handling.
ensure_dirs() {
    [[ $# -eq 0 ]] && return 0
    if ! mkdir -p "$@" 2>/dev/null; then
        _print_error "Failed to create directories: $*"
        return 1
    fi
    return 0
}

# Safely backup a file if it exists and has content.
# Usage: safe_backup source [destination]
safe_backup() {
    local src="$1"
    local dst="${2:-.tmp/$(basename "$1").bak}"
    if [[ -s "$src" ]]; then
        cp "$src" "$dst" 2>/dev/null || return 1
    fi
    return 0
}

# Count non-empty lines in a file safely.
count_lines() {
    local file="$1"
    if [[ -s "$file" ]]; then
        sed '/^$/d' "$file" | wc -l | tr -d ' '
    else
        echo 0
    fi
}

# Format seconds as 0s / 1m 23s / 19m 04s.
format_duration() {
    local input="${1:-0}"
    [[ "$input" == "--" ]] && { printf "%s" "--"; return 0; }
    if [[ "$input" =~ [a-zA-Z] ]] && ! [[ "$input" =~ ^[0-9]+$ ]]; then
        printf "%s" "$input"
        return 0
    fi
    [[ "$input" =~ ^[0-9]+s$ ]] && input="${input%s}"
    [[ "$input" =~ ^[0-9]+$ ]] || input=0
    local mins=$((input / 60)) secs=$((input % 60))
    if ((mins > 0)); then
        printf "%dm %02ds" "$mins" "$secs"
    else
        printf "%ds" "$secs"
    fi
}

_ui_live_break_if_needed() {
    if declare -F ui_live_progress_break >/dev/null 2>&1; then
        ui_live_progress_break
    fi
}

_truncate_with_ellipsis() {
    local text="$1" max="${2:-0}"
    if ! [[ "$max" =~ ^[0-9]+$ ]] || (( max < 1 )) || (( ${#text} <= max )); then
        printf "%s" "$text"
        return 0
    fi
    if (( max <= 3 )); then
        printf "%s" "${text:0:max}"
        return 0
    fi
    printf "%s..." "${text:0:max-3}"
}

# Print a normalized status line: STATE module duration reason
print_task() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    _ui_live_break_if_needed
    local state="$1" module="$2" duration="${3:-0}" reason="${4:-}"
    local color
    case "$state" in
        OK) color="${bgreen:-}" ;;
        WARN) color="${yellow:-}" ;;
        FAIL) color="${bred:-}" ;;
        SKIP|CACHE) color="${blue:-}" ;;
        RUN) color="${cyan:-}" ;;
        *) color="${bblue:-}" ;;
    esac
    local duration_fmt
    duration_fmt=$(format_duration "$duration")

    local module_pad=26 term_width=0
    if declare -F ui_term_width >/dev/null 2>&1; then
        term_width=$(ui_term_width)
    fi
    if [[ "$term_width" =~ ^[0-9]+$ ]] && ((term_width > 0)); then
        module_pad=$((term_width - 18))
        ((module_pad < 12)) && module_pad=12
        ((module_pad > 40)) && module_pad=40
    fi
    local mod line
    mod=$(_truncate_with_ellipsis "$module" "$module_pad")
    local pad=$((module_pad - ${#mod}))
    ((pad < 1)) && pad=1

    printf -v line "%b%-5s%b %s%*s %6s" "$color" "$state" "${reset:-}" "$mod" "$pad" "" "$duration_fmt"
    [[ -n "$reason" ]] && line+=" ($reason)"
    printf "%s\n" "$line"
}

# Compact artifacts line.
print_artifacts() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    local items="$*"
    [[ -z "$items" ]] && return 0
    _ui_live_break_if_needed
    printf "%bINFO%b Artifacts: %s\n" "${bblue:-}" "${reset:-}" "$items"
}

# Notice line (no counters).
print_notice() {
    local level="$1" module="${2:-notice}" message="$3"
    if [[ "$level" == "FAIL" ]] && [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]]; then
        (OUTPUT_VERBOSITY=1; print_task "$level" "$module" "--" "$message")
    else
        print_task "$level" "$module" "--" "$message"
    fi
}

print_warnf() {
    local fmt="$1"
    shift
    local msg
    printf -v msg "$fmt" "$@"
    _print_msg WARN "$msg"
}

print_errorf() {
    local fmt="$1"
    shift
    local msg
    printf -v msg "$fmt" "$@"
    _print_error "$msg"
}

# Generic LEVEL-prefixed message (INFO/WARN/FAIL/OK).
_print_msg() {
    local level="$1"
    shift
    local msg="$*" color

    if [[ "$level" == "WARN" ]]; then
        if [[ "$msg" == *"already processed"* ]]; then
            _print_status CACHE "${FUNCNAME[1]:-module}" "0s"
            if [[ -n "${called_fn_dir:-}" ]]; then
                : >"${called_fn_dir}/.cache_${FUNCNAME[1]:-module}" 2>/dev/null || true
            fi
            return 0
        fi
        if [[ "$msg" == *"skipped"* ]]; then
            _print_status SKIP "${FUNCNAME[1]:-module}" "0s"
            if [[ -n "${called_fn_dir:-}" ]]; then
                : >"${called_fn_dir}/.skip_${FUNCNAME[1]:-module}" 2>/dev/null || true
            fi
            return 0
        fi
    fi

    case "$level" in
        OK|SUCCESS) color="${bgreen:-}" ;;
        WARN) color="${yellow:-}" ;;
        FAIL|ERROR) color="${bred:-}" ;;
        *) color="${bblue:-}" ;;
    esac
    if [[ "$level" == "INFO" ]] && [[ "${OUTPUT_VERBOSITY:-1}" -lt 2 ]]; then
        return 0
    fi
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    _ui_live_break_if_needed
    printf "%b%-5s%b %s\n" "$color" "$level" "${reset:-}" "$msg"
}

# Print a warning message only once per key.
warn_once() {
    local key="${1:-}"
    shift || true
    local msg="$*"
    [[ -z "$key" || -z "$msg" ]] && return 1

    if ! declare -p WARN_ONCE_KEYS >/dev/null 2>&1; then
        declare -gA WARN_ONCE_KEYS=()
    fi
    [[ "${WARN_ONCE_KEYS[$key]:-0}" == "1" ]] && return 1

    WARN_ONCE_KEYS["$key"]=1
    _print_msg WARN "$msg"
    return 0
}

# Section header with timestamp.
_print_module_start() {
    local title ts
    title=$(printf "%s" "${1:-}" | tr '[:lower:]' '[:upper:]')
    ts=$(date +'%Y-%m-%d %H:%M:%S')
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    if declare -F ui_live_progress_end >/dev/null 2>&1; then
        ui_live_progress_end
    fi
    printf "\n%b── %s ───────────────────────────────────────────────────────────────%b\n" \
        "${bgreen:-}" "$title" "${reset:-}"
    printf "Started: %s\n" "$ts"
}

_print_section() {
    _print_module_start "$1"
}

# Compact status line.
# Usage: _print_status OK "sub_passive" "12s"
_print_status() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    local badge="$1" text="$2" detail="${3:-}"
    local duration="0" reason=""

    if [[ -n "$detail" ]]; then
        if [[ "$detail" =~ ^[0-9]+$ ]]; then
            duration="$detail"
        elif [[ "$detail" =~ ^[0-9]+s$ ]]; then
            duration="${detail%s}"
        elif [[ "$detail" =~ ^[0-9]+m ]]; then
            duration="$detail"
        else
            reason="$detail"
        fi
    fi
    if [[ "$badge" == "CACHE" ]] && [[ "${SHOW_CACHE:-false}" != "true" ]]; then
        return 0
    fi
    if [[ "$badge" == "INFO" ]] && [[ "${OUTPUT_VERBOSITY:-1}" -lt 2 ]]; then
        return 0
    fi
    print_task "$badge" "$text" "$duration" "$reason"
}

# Error that always shows (even in quiet mode).
_print_error() {
    _ui_live_break_if_needed
    printf "%b[FAIL]%b %s\n" "${bred:-}" "${reset:-}" "$1" >&2
}

# Skip notification for disabled/already-processed functions.
# reason: "disabled" | "mode" | "processed" | "processed-visible" | "noinput"
skip_notification() {
    local func_name="${FUNCNAME[1]:-unknown}"
    local reason="${1:-mode or configuration settings}"
    local badge="SKIP"
    local reason_code="config"
    local mark_cache=false

    case "$reason" in
        disabled)
            reason="mode or configuration settings"
            ;;
        mode)
            reason="mode constraints"
            reason_code="mode"
            ;;
        processed)
            reason="already processed"
            badge="CACHE"
            reason_code="cache"
            mark_cache=true
            ;;
        processed-visible)
            reason="already processed"
            badge="SKIP"
            reason_code="cache"
            mark_cache=true
            ;;
        noinput)
            reason="missing required input data"
            reason_code="noinput"
            ;;
    esac

    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 1 ]]; then
        _print_status "$badge" "$func_name" "0s"
        if [[ "$badge" == "SKIP" ]]; then
            printf "         reason: %s\n" "$reason_code"
        elif [[ "$badge" == "CACHE" ]] && [[ "${SHOW_CACHE:-false}" == "true" ]]; then
            printf "         reason: %s\n" "$reason_code"
        fi
        if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
            if [[ "$badge" == "CACHE" ]]; then
                _print_msg INFO "${func_name} already processed. To force re-run, delete: ${called_fn_dir:-.}/.${func_name}"
            else
                _print_msg INFO "${func_name} skipped: ${reason}"
            fi
        fi
    fi

    if [[ -n "${called_fn_dir:-}" ]]; then
        printf "%s\n" "$reason_code" >"${called_fn_dir}/.status_reason_${func_name}" 2>/dev/null || true
        if [[ "$badge" == "CACHE" ]] || [[ "$mark_cache" == "true" ]]; then
            : >"${called_fn_dir}/.cache_${func_name}" 2>/dev/null || true
        else
            : >"${called_fn_dir}/.skip_${func_name}" 2>/dev/null || true
        fi
    fi
}

# Run a command with periodic progress lines for long-running tasks.
# Usage: run_with_heartbeat "label" [interval_seconds] command [args...]
run_with_heartbeat() {
    local label="${1:-task}"
    shift
    local interval="${HEARTBEAT_INTERVAL_SECONDS:-20}"
    if [[ "${1:-}" =~ ^[0-9]+$ ]]; then
        interval="$1"
        shift
    fi
    [[ $# -eq 0 ]] && return 1

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        run_command "$@"
        return $?
    fi

    local start_ts now_ts elapsed last_hb use_live=false
    start_ts=$(date +%s)
    last_hb="$start_ts"
    local hb_log="/dev/null"
    [[ -n "${LOGFILE:-}" ]] && hb_log="$LOGFILE"

    run_command "$@" >>"$hb_log" 2>&1 &
    local cmd_pid=$!

    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 1 ]]; then
        if declare -F ui_is_tty >/dev/null 2>&1 && ui_is_tty; then
            use_live=true
            ui_live_progress_begin
            ui_live_progress_update "Running: ${label} | elapsed 0s"
        else
            printf "Started: %s\n" "$label"
        fi
    fi

    while kill -0 "$cmd_pid" 2>/dev/null; do
        sleep 1
        now_ts=$(date +%s)
        if ((now_ts - last_hb >= interval)); then
            elapsed=$((now_ts - start_ts))
            if [[ "${OUTPUT_VERBOSITY:-1}" -ge 1 ]] && [[ "$use_live" == true ]]; then
                ui_live_progress_update "Running: ${label} | elapsed $(format_duration "$elapsed")"
            fi
            last_hb="$now_ts"
        fi
    done

    wait "$cmd_pid"
    local rc=$?
    elapsed=$(($(date +%s) - start_ts))
    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 1 ]]; then
        if [[ "$use_live" == true ]]; then
            ui_live_progress_end
        else
            printf "Completed: %s (%s)\n" "$label" "$(format_duration "$elapsed")"
        fi
    fi
    return "$rc"
}

# Escape a domain for use in grep regex patterns.
escape_domain_regex() {
    printf '%s' "$1" | sed 's/[.[\*^$()+?{|]/\\&/g'
}

# ERE pattern matching the exact domain or any subdomain.
domain_match_regex() {
    local escaped
    escaped=$(escape_domain_regex "$1")
    printf '(^|\\.)%s$' "$escaped"
}

# Validate that a file exists / is readable.
validate_file_exists() {
    [[ -n "$1" && -e "$1" ]]
}

validate_file_readable() {
    local file="$1"
    validate_file_exists "$file" && [[ -r "$file" && -f "$file" ]]
}
