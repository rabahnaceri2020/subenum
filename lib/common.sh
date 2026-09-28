#!/usr/bin/env bash
# lib/common.sh - Common utility functions to reduce code duplication
# Part of reconFTW refactoring - Phase 2

# Prevent multiple sourcing
[[ -n "$_COMMON_SH_LOADED" ]] && return 0
declare -r _COMMON_SH_LOADED=1

###############################################################################
# Directory Management
###############################################################################

# Create directories with error handling
# Usage: ensure_dirs dir1 [dir2 ...]
# Returns: 0 on success, 1 on failure
ensure_dirs() {
    if [[ $# -eq 0 ]]; then
        return 0
    fi
    if ! mkdir -p "$@" 2>/dev/null; then
        _print_error "Failed to create directories: $*"
        return 1
    fi
    return 0
}

###############################################################################
# File Operations
###############################################################################

# Safely backup a file if it exists and has content
# Usage: safe_backup source [destination]
# Default destination: .tmp/$(basename source).bak
safe_backup() {
    local src="$1"
    local dst="${2:-.tmp/$(basename "$1").bak}"
    if [[ -s "$src" ]]; then
        cp "$src" "$dst" 2>/dev/null || return 1
    fi
    return 0
}

# Count non-empty lines in a file safely
# Usage: count_lines filename
# Returns: line count (0 if file doesn't exist or is empty)
count_lines() {
    local file="$1"
    if [[ -s "$file" ]]; then
        sed '/^$/d' "$file" | wc -l | tr -d ' '
    else
        echo 0
    fi
}

###############################################################################
# Output Primitives
###############################################################################

# Format duration in seconds to human-friendly form: 0s, 6s, 1m 23s, 19m 04s
# Usage: format_duration 83
format_duration() {
    local input="${1:-0}"
    [[ "$input" == "--" ]] && { printf "%s" "--"; return 0; }
    if [[ "$input" =~ [a-zA-Z] ]] && ! [[ "$input" =~ ^[0-9]+$ ]]; then
        printf "%s" "$input"
        return 0
    fi
    if [[ "$input" =~ ^[0-9]+s$ ]]; then
        input="${input%s}"
    fi
    if ! [[ "$input" =~ ^[0-9]+$ ]]; then
        input=0
    fi
    local total="$input"
    local mins=$((total / 60))
    local secs=$((total % 60))
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

_ui_human_output_enabled() {
    if declare -F ui_human_output_enabled >/dev/null 2>&1; then
        ui_human_output_enabled
        return $?
    fi
    return 0
}

_ui_jsonl_enabled() {
    if declare -F ui_is_jsonl >/dev/null 2>&1; then
        ui_is_jsonl
        return $?
    fi
    return 1
}

_truncate_with_ellipsis() {
    local text="$1"
    local max="${2:-0}"
    if ! [[ "$max" =~ ^[0-9]+$ ]] || (( max < 1 )); then
        printf "%s" "$text"
        return 0
    fi
    if (( ${#text} <= max )); then
        printf "%s" "$text"
        return 0
    fi
    if (( max <= 3 )); then
        printf "%s" "${text:0:max}"
        return 0
    fi
    printf "%s..." "${text:0:max-3}"
}

# Print a normalized task/status line
# Usage: print_task STATE module duration_seconds reason
print_task() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    _ui_human_output_enabled || return 0
    _ui_live_break_if_needed
    local state="$1" module="$2" duration="${3:-0}" reason="${4:-}"
    local color=""
    local dim_color="${blue:-}"
    local duration_fmt
    duration_fmt=$(format_duration "$duration")

    case "$state" in
        OK) color="${bgreen:-}" ;;
        WARN) color="${yellow:-}" ;;
        FAIL) color="${bred:-}" ;;
        SKIP|CACHE) color="${dim_color:-}" ;;
        RUN) color="${cyan:-}" ;;
        INFO) color="${bblue:-}" ;;
        *) color="${bblue:-}" ;;
    esac

    local module_pad=26
    local term_width=0
    if declare -F ui_term_width >/dev/null 2>&1; then
        term_width=$(ui_term_width)
    fi
    if [[ "$term_width" =~ ^[0-9]+$ ]] && ((term_width > 0)); then
        local max_module_pad=$((term_width - 18))
        ((max_module_pad < 12)) && max_module_pad=12
        ((max_module_pad > 40)) && max_module_pad=40
        module_pad="$max_module_pad"
    fi
    local mod="$module"
    mod=$(_truncate_with_ellipsis "$mod" "$module_pad")
    local pad=$((module_pad - ${#mod}))
    ((pad < 1)) && pad=1
    local spaces
    spaces=$(printf '%*s' "$pad" "")

    printf "%b%-5s%b %s%s %6s" "$color" "$state" "${reset:-}" "$mod" "$spaces" "$duration_fmt"
    if [[ -n "$reason" ]]; then
        printf " (%s)" "$reason"
    fi
    printf "\n"
}

# Print a compact artifacts line
# Usage: print_artifacts "file1" ["file2"...]
print_artifacts() {
    if [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && ! _ui_jsonl_enabled; then
        return 0
    fi
    local items="$*"
    [[ -z "$items" ]] && return 0
    if ! _ui_human_output_enabled; then
        if declare -F ui_log_jsonl >/dev/null 2>&1; then
            ui_log_jsonl "INFO" "artifacts" "Artifacts summary" "items=${items}"
        fi
        return 0
    fi
    _ui_live_break_if_needed
    printf "%bINFO%b Artifacts: %s\n" "${bblue:-}" "${reset:-}" "$items"
}

# Print a notice line without affecting counters
# Usage: print_notice LEVEL module message
print_notice() {
    local level="$1" module="$2" message="$3"
    [[ -z "$module" ]] && module="notice"
    if declare -F ui_log_jsonl >/dev/null 2>&1; then
        ui_log_jsonl "$level" "$module" "$message"
    fi
    if ! _ui_human_output_enabled; then
        return 0
    fi
    if [[ "$level" == "FAIL" ]] && [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]]; then
        (OUTPUT_VERBOSITY=1; print_task "$level" "$module" "--" "$message")
    else
        print_task "$level" "$module" "--" "$message"
    fi
}

# Formatted WARN message without color codes
# Usage: print_warnf "message %s" "arg"
print_warnf() {
    local fmt="$1"
    shift
    local msg
    printf -v msg "$fmt" "$@"
    _print_msg WARN "$msg"
}

# Formatted FAIL message (stderr, always visible)
# Usage: print_errorf "message %s" "arg"
print_errorf() {
    local fmt="$1"
    shift
    local msg
    printf -v msg "$fmt" "$@"
    _print_error "$msg"
}

# Generic message with LEVEL prefix (INFO/WARN/FAIL/OK)
# Usage: _print_msg WARN "something happened"
_print_msg() {
    local level="$1"
    shift
    local msg="$*"
    local color

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
        INFO) color="${bblue:-}" ;;
        *) color="${bblue:-}" ;;
    esac
    if declare -F ui_log_jsonl >/dev/null 2>&1; then
        ui_log_jsonl "$level" "${FUNCNAME[1]:-module}" "$msg"
    fi
    _ui_human_output_enabled || return 0
    if [[ "$level" == "INFO" ]] && [[ "${OUTPUT_VERBOSITY:-1}" -lt 2 ]]; then
        return 0
    fi
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    _ui_live_break_if_needed
    printf "%b%-5s%b %s\n" "$color" "$level" "${reset:-}" "$msg"
}

# Print a warning message only once per run key.
# Usage: warn_once "missing-tool-dnstake" "subtakeover: dnstake binary not found in PATH - install dnstake first"
warn_once() {
    local key="${1:-}"
    shift || true
    local msg="$*"
    [[ -z "$key" || -z "$msg" ]] && return 1

    if ! declare -p WARN_ONCE_KEYS >/dev/null 2>&1; then
        declare -gA WARN_ONCE_KEYS=()
    fi

    if [[ "${WARN_ONCE_KEYS[$key]:-0}" == "1" ]]; then
        return 1
    fi

    WARN_ONCE_KEYS["$key"]=1
    _print_msg WARN "$msg"
    return 0
}

# Module start message with timestamp
# Usage: _print_module_start "OSINT"
_print_module_start() {
    local title
    title=$(printf "%s" "${1:-}" | tr '[:lower:]' '[:upper:]')
    local ts
    ts=$(date +'%Y-%m-%d %H:%M:%S')
    if declare -F ui_log_jsonl >/dev/null 2>&1; then
        ui_log_jsonl "INFO" "$title" "Module started" "started=${ts}"
    fi
    if [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && ! _ui_jsonl_enabled; then
        return 0
    fi
    _ui_human_output_enabled || return 0
    if declare -F ui_live_progress_end >/dev/null 2>&1; then
        ui_live_progress_end
    fi

    printf "\n%b── %s ───────────────────────────────────────────────────────────────%b\n" \
        "${bgreen:-}" "$title" "${reset:-}"
    printf "Started: %s\n" "$ts"
}

# Section header for major phases (OSINT, Subdomains, Web, Vulns, etc.)
# Usage: _print_section "OSINT"
_print_section() {
    _print_module_start "$1"
}

# Compact status line with dot-fill and right-aligned detail
# Usage: _print_status OK "sub_passive" "12s"
#        _print_status SKIP "sub_crt" "(disabled)"
_print_status() {
    local jsonl_enabled=false
    if _ui_jsonl_enabled; then
        jsonl_enabled=true
    fi
    if [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && [[ "$jsonl_enabled" != "true" ]]; then
        return 0
    fi
    local badge="$1" text="$2" detail="${3:-}"
    local duration="0"
    local reason=""
    local hide_cache_human=false

    if [[ -n "$detail" ]]; then
        if [[ "$detail" =~ ^[0-9]+$ ]]; then
            duration="$detail"
        elif [[ "$detail" =~ ^[0-9]+s$ ]]; then
            duration="${detail%s}"
        elif [[ "$detail" =~ ^[0-9]+m ]]; then
            duration="$detail"
        else
            reason="${detail}"
        fi
    fi

    if [[ "$badge" == "CACHE" ]] && [[ "${SHOW_CACHE:-false}" != "true" ]]; then
        hide_cache_human=true
    fi
    if [[ "$badge" == "INFO" ]] && [[ "${OUTPUT_VERBOSITY:-1}" -lt 2 ]] && [[ "$jsonl_enabled" != "true" ]]; then
        return 0
    fi

    if declare -F ui_log_jsonl >/dev/null 2>&1; then
        ui_log_jsonl "$badge" "$text" "Status update" "duration=${duration}" "reason=${reason}"
    fi
    if ! _ui_human_output_enabled; then
        return 0
    fi
    if [[ "$hide_cache_human" == "true" ]]; then
        return 0
    fi
    print_task "$badge" "$text" "$duration" "$reason"
}

# Error that always shows (even in quiet mode)
# Usage: _print_error "something failed"
_print_error() {
    local msg="$1"
    if declare -F ui_log_jsonl >/dev/null 2>&1; then
        ui_log_jsonl "ERROR" "${FUNCNAME[1]:-module}" "$msg"
    fi
    _ui_human_output_enabled || return 0
    _ui_live_break_if_needed
    printf "%b[FAIL]%b %s\n" "${bred:-}" "${reset:-}" "$msg" >&2
}

###############################################################################
# Notifications
###############################################################################

# Show skip notification for disabled/already-processed functions
# Usage: skip_notification reason
# reason: "disabled" | "mode" | "processed" | "processed-visible" | "noinput" | custom message
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
        if _ui_human_output_enabled; then
            if [[ "$badge" == "SKIP" ]]; then
                printf "         reason: %s\n" "$reason_code"
            elif [[ "$badge" == "CACHE" ]] && [[ "${SHOW_CACHE:-false}" == "true" ]]; then
                printf "         reason: %s\n" "$reason_code"
            fi
        fi
        if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
            if [[ "$badge" == "CACHE" ]]; then
                _print_msg INFO "${func_name} already processed. To force re-run, delete: ${called_fn_dir:-.}/.${func_name}"
            else
                _print_msg INFO "${func_name} skipped: ${reason}"
            fi
        fi
    fi

    # Emit skip marker for parent process (parallel mode)
    if [[ -n "${called_fn_dir:-}" ]]; then
        printf "%s\n" "$reason_code" >"${called_fn_dir}/.status_reason_${func_name}" 2>/dev/null || true
        if [[ "$badge" == "CACHE" ]] || [[ "$mark_cache" == "true" ]]; then
            : >"${called_fn_dir}/.cache_${func_name}" 2>/dev/null || true
        else
            : >"${called_fn_dir}/.skip_${func_name}" 2>/dev/null || true
        fi
    fi
}

###############################################################################
# Command Execution Helpers
###############################################################################

# Remove ANSI/control sequences from a text stream.
# Usage: some_command | strip_ansi_stream
strip_ansi_stream() {
    # Strip ANSI/OSC control sequences and normalize carriage-return updates.
    # This keeps only the final segment of CR-updated lines and removes backspaces.
    if command -v perl >/dev/null 2>&1; then
        perl -pe '
            s/\x1B\[[0-9;?]*[ -\/]*[@-~]//g;
            s/\x1B\][^\x07]*(?:\x07|\x1B\\)//g;
            s/.*\r//;
            1 while s/[^\x08]\x08//g;
            s/\x08//g;
        '
    else
        sed -E $'s/\x1B\\[[0-9;?]*[ -/]*[@-~]//g; s/\x1B\\][^\a]*(\a|\x1B\\\\)//g; s/.*\r//; :a; s/[^\x08]\x08//g; ta; s/\x08//g'
    fi
}

# Run a command with periodic heartbeat status lines for long-running tasks.
# Usage: run_with_heartbeat "label" [interval_seconds] command [args...]
run_with_heartbeat() {
    local label="${1:-task}"
    shift
    local interval="${HEARTBEAT_INTERVAL_SECONDS:-20}"
    if [[ "${1:-}" =~ ^[0-9]+$ ]]; then
        interval="$1"
        shift
    fi

    if [[ $# -eq 0 ]]; then
        return 1
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        run_command "$@"
        return $?
    fi

    local start_ts now_ts elapsed last_hb
    local use_live=false
    start_ts=$(date +%s)
    last_hb="$start_ts"

    local hb_log="/dev/null"
    if [[ -n "${LOGFILE:-}" ]]; then
        hb_log="$LOGFILE"
    fi

    run_command "$@" >>"$hb_log" 2>&1 &
    local cmd_pid=$!

    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 1 ]] && _ui_human_output_enabled; then
        if declare -F ui_is_tty >/dev/null 2>&1 && ui_is_tty && declare -F ui_live_progress_begin >/dev/null 2>&1; then
            use_live=true
            ui_live_progress_begin
            if declare -F ui_live_progress_update >/dev/null 2>&1; then
                ui_live_progress_update "Running: ${label} | elapsed 0s | ETA: --"
            fi
        else
            printf "Started: %s\n" "$label"
        fi
    fi

    while kill -0 "$cmd_pid" 2>/dev/null; do
        sleep 1
        now_ts=$(date +%s)
        if ((now_ts - last_hb >= interval)); then
            elapsed=$((now_ts - start_ts))
            if [[ "${OUTPUT_VERBOSITY:-1}" -ge 1 ]] && [[ "$use_live" == true ]] && declare -F ui_live_progress_update >/dev/null 2>&1; then
                ui_live_progress_update "Running: ${label} | elapsed $(format_duration "$elapsed") | ETA: --"
            fi
            last_hb="$now_ts"
        fi
    done

    wait "$cmd_pid"
    local rc=$?
    elapsed=$(($(date +%s) - start_ts))

    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 1 ]] && _ui_human_output_enabled; then
        if [[ "$use_live" == true ]] && declare -F ui_live_progress_end >/dev/null 2>&1; then
            ui_live_progress_end
        else
            printf "Completed: %s (%s)\n" "$label" "$(format_duration "$elapsed")"
        fi
    fi

    return "$rc"
}

###############################################################################
# Pipeline Helpers
###############################################################################

###############################################################################
# Domain Matching Helpers
###############################################################################

# Escape a domain name for safe use in grep regex patterns
# Dots are literal in domain names but regex metacharacters
# Usage: escaped=$(escape_domain_regex "example.com")
escape_domain_regex() {
    printf '%s' "$1" | sed 's/[.[\*^$()+?{|]/\\&/g'
}

# Build a robust ERE pattern that matches exact domain or any subdomain.
# Usage: regex=$(domain_match_regex "example.com")
domain_match_regex() {
    local raw_domain="$1"
    local escaped
    escaped=$(escape_domain_regex "$raw_domain")
    printf '(^|\\.)%s$' "$escaped"
}

###############################################################################
# Axiom/Local Execution Helper
###############################################################################

###############################################################################
# Function Gate Helper
###############################################################################

###############################################################################
# Validation Helpers
###############################################################################

