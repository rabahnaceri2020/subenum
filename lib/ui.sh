#!/usr/bin/env bash
# lib/ui.sh - TTY/color handling and status presentation

[[ -n "${_UI_SH_LOADED:-}" ]] && return 0
declare -r _UI_SH_LOADED=1

_UI_IS_TTY=false
_UI_NO_COLOR=false
_UI_LIVE_ACTIVE=false

ui_init() {
    [[ -t 1 ]] && _UI_IS_TTY=true

    # NO_COLOR convention + TERM=dumb + non-TTY default
    if [[ -n "${NO_COLOR:-}" ]] || [[ "${TERM:-}" == "dumb" ]] || [[ "$_UI_IS_TTY" != true ]]; then
        _UI_NO_COLOR=true
    fi
    if [[ "$_UI_NO_COLOR" == true ]]; then
        # shellcheck disable=SC2034  # consumed by sourced modules
        bred="" bgreen="" bblue="" byellow="" yellow="" reset=""
        # shellcheck disable=SC2034
        red="" blue="" green="" cyan=""
    fi
}

ui_is_tty() {
    [[ "$_UI_IS_TTY" == true ]]
}

ui_term_width() {
    if [[ -n "$_UI_CACHED_WIDTH" ]]; then
        printf "%s" "$_UI_CACHED_WIDTH"
        return 0
    fi
    local width="${COLUMNS:-0}"
    if ! [[ "$width" =~ ^[0-9]+$ ]] || ((width < 20)); then
        if command -v tput >/dev/null 2>&1; then
            width=$(timeout 1 tput cols 2>/dev/null || echo 0)
        fi
    fi
    if ! [[ "$width" =~ ^[0-9]+$ ]] || ((width < 20)); then
        width=80
    fi
    _UI_CACHED_WIDTH="$width"
    printf "%s" "$width"
}

ui_truncate_text() {
    local text="$1"
    local max="${2:-80}"
    if ! [[ "$max" =~ ^[0-9]+$ ]] || ((max < 1)) || (( ${#text} <= max )); then
        printf "%s" "$text"
        return 0
    fi
    if (( max <= 3 )); then
        printf "%s" "${text:0:max}"
        return 0
    fi
    printf "%s..." "${text:0:max-3}"
}

ui_live_progress_begin() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    ui_is_tty || return 0
    _UI_LIVE_ACTIVE=true
}

ui_live_progress_update() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    ui_is_tty || return 0
    local line
    line=$(ui_truncate_text "$1" "$(ui_term_width)")
    _UI_LIVE_ACTIVE=true
    printf "\r  %b%s%b\033[K" "${bblue:-}" "$line" "${reset:-}"
}

ui_live_progress_break() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    ui_is_tty || return 0
    [[ "$_UI_LIVE_ACTIVE" == true ]] || return 0
    printf "\r\033[K"
}

ui_live_progress_end() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    ui_is_tty || return 0
    if [[ "$_UI_LIVE_ACTIVE" == true ]]; then
        printf "\r\033[K"
    fi
    _UI_LIVE_ACTIVE=false
}

ui_header() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    local target="${domain:-unknown}" outdir="${dir:-unknown}"
    local started
    started=$(date +'%Y-%m-%d %H:%M:%S')
    local width rule="" i
    width=$(ui_term_width)
    for ((i = 0; i < width; i++)); do
        rule+="─"
    done
    printf "%b%s%b\n" "${bgreen:-}" "$rule" "${reset:-}"
    printf "%b%s%b\n" "${bgreen:-}" "$(ui_truncate_text "subenum ${subenum_version:-} | Authorized testing only" "$width")" "${reset:-}"
    printf "%b%s%b\n" "${bgreen:-}" "$rule" "${reset:-}"
    printf "%s\n" "$(ui_truncate_text "Mode: SUBDOMAINS | Target: ${target} | Parallel: ${PARALLEL_MODE:-true} | Jobs: ${PARALLEL_MAX_JOBS:-4}" "$width")"
    printf "%s\n" "$(ui_truncate_text "Output: ${outdir}" "$width")"
    if [[ -n "${RECON_BEHIND_NAT:-}" ]] || [[ -n "${DNS_RESOLVER_SELECTED:-}" ]]; then
        printf "%s\n" "$(ui_truncate_text "Network: behind_nat=${RECON_BEHIND_NAT:-unknown} | DNS: ${DNS_RESOLVER_SELECTED:-unknown}" "$width")"
    fi
    printf "%s\n\n" "$(ui_truncate_text "Started: ${started}" "$width")"
}

# Print the command a dry run would execute (verbose only)
# Usage: ui_dryrun_track "tool_name" "full command string"
ui_dryrun_track() {
    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
        printf "%b[DRY-RUN]%b %s\n" "${yellow:-}" "${reset:-}" \
            "$(echo "$2" | tr '\n' ' ' | tr -s ' ')"
    fi
}
