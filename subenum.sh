#!/bin/bash
# shellcheck disable=SC2034,SC2154
#
# subenum - standalone subdomain enumeration tool
# Extracted from reconFTW: runs ONLY the subdomain enumeration methods and
# writes results into a single subdomains/ folder per target.
#
# Authorized testing only.

# Defaults aimed at unattended execution (fail-soft)
set -o pipefail
set -E
set +e
IFS=$'\n\t'

# Standard exit/return codes (guard for re-source in test harnesses)
if [[ -z "${E_SUCCESS+x}" ]]; then
    readonly E_SUCCESS=0
    readonly E_GENERAL=1
    readonly E_MISSING_DEP=2
    readonly E_INVALID_INPUT=3
    readonly E_NETWORK=4
    readonly E_DISK_SPACE=5
    readonly E_PERMISSION=6
    readonly E_TIMEOUT=7
    readonly E_CONFIG=8
fi

# Detect if the script is being run (not sourced) in macOS and re-exec with modern Bash.
if [[ "${BASH_SOURCE[0]}" == "${0}" && $OSTYPE == "darwin"* ]]; then
    _mac_bash=""
    for _candidate in /opt/homebrew/bin/bash /usr/local/bin/bash /bin/bash; do
        if [[ -x "$_candidate" ]]; then
            _major="$("$_candidate" -lc 'echo "${BASH_VERSINFO[0]}"' 2>/dev/null || echo 0)"
            if [[ "$_major" =~ ^[0-9]+$ ]] && [[ "$_major" -ge 4 ]]; then
                _mac_bash="$_candidate"
                break
            fi
        fi
    done
    if [[ -n "$_mac_bash" ]] && [[ "$BASH" != "$_mac_bash" ]]; then
        exec "$_mac_bash" "$0" "$@"
    fi
    unset _mac_bash _candidate _major
fi

# timeout/gtimeout compatibility
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_CMD="gtimeout"
else
    TIMEOUT_CMD=""
fi

# Ensure a safe default for early log redirections
: "${LOGFILE:=/dev/null}"

###############################################################################################################
############################################## MODULE LOADING #################################################
###############################################################################################################

_INIT_SCRIPTPATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
SCRIPTPATH="${_INIT_SCRIPTPATH}"

# Source libraries first (pure utilities)
source "${_INIT_SCRIPTPATH}/lib/validation.sh"
source "${_INIT_SCRIPTPATH}/lib/common.sh"
source "${_INIT_SCRIPTPATH}/lib/ui.sh"
source "${_INIT_SCRIPTPATH}/lib/parallel.sh"

# Source modules in dependency order
source "${_INIT_SCRIPTPATH}/modules/utils.sh"
source "${_INIT_SCRIPTPATH}/modules/core.sh"
source "${_INIT_SCRIPTPATH}/modules/resolvers.sh"
source "${_INIT_SCRIPTPATH}/modules/subdomains.sh"

# Allow sourcing functions without execution (for testing)
if [[ "${1:-}" == "--source-only" ]]; then
    return 0 2>/dev/null || exit 0
fi

function help() {
    pt_header "Usage"
    printf "\n %bsubenum%b - subdomain enumeration only (reconFTW methods)\n" "${bgreen:-}" "${reset:-}"
    printf "\n Usage: %s -d domain.tld [options]" "$0"
    printf "\n        %s -l targets.txt [options]\n\n" "$0"
    printf " %bTARGET OPTIONS%b\n" "${bblue:-}" "${reset:-}"
    printf "   -d, --domain <domain>       Target domain or IP/CIDR\n"
    printf "   -l, --list <file>           Targets list (one per line)\n"
    printf "   -x, --out-of-scope <file>   Excludes subdomains list (Out Of Scope)\n"
    printf "   -i, --in-scope <file>       Includes subdomains list\n"
    printf "   -o, --output <path>         Output root (default: ./Recon)\n"
    printf " \n"
    printf " %bENUMERATION OPTIONS%b\n" "${bblue:-}" "${reset:-}"
    printf "   --deep                      Deep scan (bigger wordlist, more permutations)\n"
    printf "   --only <m1,m2,...>          Run only the given methods (see METHODS below)\n"
    printf "   --no-parallel               Force sequential execution\n"
    printf "   --parallel                  Run independent phases in parallel (default)\n"
    printf "   --force                     Re-run all methods (ignore cached markers)\n"
    printf "   --gen-resolvers             Generate custom resolvers with dnsvalidator\n"
    printf "   --refresh-cache             Force refresh of cached resolvers\n"
    printf "   -q <rate>                   Rate limit in requests per second\n"
    printf " \n"
    printf " %bGENERAL OPTIONS%b\n" "${bblue:-}" "${reset:-}"
    printf "   -f, --config <file>         Alternate config file\n"
    printf "   --dry-run                   Show what would be executed without running commands\n"
    printf "   --quiet                     Minimal output (errors and final summary only)\n"
    printf "   --verbose                   Extra output\n"
    printf "   --no-color                  Disable colors\n"
    printf "   --check-tools               Exit if one of the tools is missing\n"
    printf "   --show-cache                Show cached/skipped method lines\n"
    printf "   --no-banner                 Disable banner\n"
    printf "   --legal                     Show legal note\n"
    printf "   -h, --help                  Show this help\n"
    printf " \n"
    printf " %bMETHODS (for --only)%b\n" "${bblue:-}" "${reset:-}"
    printf "   sub_asn, sub_passive, sub_crt, sub_active, sub_tls, sub_noerror, sub_srv,\n"
    printf "   sub_dns, sub_ptr_cidrs, sub_brute, sub_permut, sub_regex_permut,\n"
    printf "   sub_ia_permut, sub_recursive_passive, sub_recursive_brute, sub_scraping,\n"
    printf "   sub_analytics, sub_ns_delegation, zonetransfer\n"
    printf " \n"
    printf " %bOUTPUT%b\n" "${bblue:-}" "${reset:-}"
    printf "   <output-root>/<domain>/subdomains/subdomains.txt      All discovered subdomains\n"
    printf "   <output-root>/<domain>/subdomains/subdomains_new.txt  New since previous run\n"
    printf "   <output-root>/<domain>/subdomains/*.txt               Per-method artifacts\n"
    printf " \n"
    printf " %bEXAMPLES%b\n" "${bblue:-}" "${reset:-}"
    printf "   %s -d example.com\n" "$0"
    printf "   %s -d example.com --deep\n" "$0"
    printf "   %s -l targets.txt -o /tmp/recon\n" "$0"
    printf "   %s -d example.com --only sub_passive,sub_crt,sub_brute\n\n" "$0"
}

###############################################################################################################
########################################### START SCRIPT  #####################################################
###############################################################################################################

# macOS PATH initialization
if [[ $OSTYPE == "darwin"* ]]; then
    if ! command -v brew &>/dev/null; then
        _print_error "Brew is not installed or not in the PATH"
        exit 1
    fi
    _brew_prefix="$(brew --prefix)"
    if [[ ! -x "${_brew_prefix}/opt/gnu-getopt/bin/getopt" ]]; then
        _print_error "Brew formula gnu-getopt is not installed"
        exit 1
    fi
    if [[ ! -d "${_brew_prefix}/opt/coreutils/libexec/gnubin" ]]; then
        _print_error "Brew formula coreutils is not installed"
        exit 1
    fi
    if [[ ! -d "${_brew_prefix}/opt/gnu-sed/libexec/gnubin" ]]; then
        _print_error "Brew formula gnu-sed is not installed"
        exit 1
    fi
    PATH="${_brew_prefix}/opt/gnu-getopt/bin:$PATH"
    PATH="${_brew_prefix}/opt/coreutils/libexec/gnubin:$PATH"
    PATH="${_brew_prefix}/opt/gnu-sed/libexec/gnubin:$PATH"
    unset _brew_prefix
fi

# Defaults for CLI-overridable values
opt_mode='s'
ONLY_METHODS=""
OUTPUT_ROOT=""
SHOW_BANNER=true
SHOW_LEGAL=false
HELP_REQUESTED=false
CLI_OUTPUT_VERBOSITY=""
CLI_NO_COLOR=""
CLI_PARALLEL_MODE=""
CLI_FORCE_RESCAN=false
CLI_DRY_RUN=false
CLI_GENERATE_RESOLVERS=false
CLI_CACHE_REFRESH=false
CHECK_TOOLS_OR_EXIT=false
CUSTOM_CONFIG=""
outOfScope_file=""
inScope_file=""
list=""
domain=""
rate_limit=""

PROGARGS=$(getopt -o 'd:l:o:x:i:f:q:h' --long 'domain:,list:,output:,out-of-scope:,in-scope:,config:,only:,deep,help,gen-resolvers,refresh-cache,force,dry-run,parallel,no-parallel,quiet,verbose,no-color,check-tools,show-cache,banner,no-banner,legal,source-only' -n 'subenum' -- "$@")
exit_status=$?
if [[ $exit_status -ne 0 ]]; then
    UNKNOWN_ARGUMENT=true
fi

# shellcheck disable=SC2086
eval set -- "$PROGARGS"
unset PROGARGS

while true; do
    case "$1" in
        '-d' | '--domain')
            target_input="$2"
            if [[ "$target_input" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
                if ! domain=$(sanitize_ip "$target_input"); then
                    print_errorf "Invalid IP/CIDR provided: '%s'" "$target_input"
                    exit 1
                fi
            else
                if ! domain=$(sanitize_domain "$target_input"); then
                    print_errorf "Invalid domain provided: '%s'" "$target_input"
                    exit 1
                fi
            fi
            shift 2
            continue
            ;;
        '-l' | '--list')
            list="$2"
            if ! validate_file_readable "$list"; then
                print_errorf "List file not found or not readable: '%s'" "$list"
                _print_msg WARN "Usage: -l <file> where file contains one target per line"
                exit 1
            fi
            shift 2
            continue
            ;;
        '-o' | '--output')
            if [[ "$2" != /* ]]; then
                OUTPUT_ROOT="$PWD/$2"
            else
                OUTPUT_ROOT="$2"
            fi
            shift 2
            continue
            ;;
        '-x' | '--out-of-scope')
            outOfScope_file="$2"
            if [[ -n "$outOfScope_file" ]] && ! validate_file_readable "$outOfScope_file"; then
                print_errorf "Out-of-scope file not found or not readable: '%s'" "$outOfScope_file"
                exit 1
            fi
            shift 2
            continue
            ;;
        '-i' | '--in-scope')
            inScope_file="$2"
            if [[ -n "$inScope_file" ]] && ! validate_file_readable "$inScope_file"; then
                print_errorf "In-scope file not found or not readable: '%s'" "$inScope_file"
                exit 1
            fi
            shift 2
            continue
            ;;
        '-f' | '--config')
            CUSTOM_CONFIG="$2"
            shift 2
            continue
            ;;
        '-q')
            rate_limit="$2"
            shift 2
            continue
            ;;
        '--only')
            ONLY_METHODS="$2"
            shift 2
            continue
            ;;
        '--deep')
            opt_deep=true
            shift
            continue
            ;;
        '--gen-resolvers')
            CLI_GENERATE_RESOLVERS=true
            shift
            continue
            ;;
        '--refresh-cache')
            CLI_CACHE_REFRESH=true
            shift
            continue
            ;;
        '--force')
            CLI_FORCE_RESCAN=true
            shift
            continue
            ;;
        '--dry-run')
            CLI_DRY_RUN=true
            shift
            continue
            ;;
        '--parallel')
            PARALLEL_MODE=true
            CLI_PARALLEL_MODE=true
            shift
            continue
            ;;
        '--no-parallel')
            PARALLEL_MODE=false
            CLI_PARALLEL_MODE=false
            shift
            continue
            ;;
        '--quiet')
            CLI_OUTPUT_VERBOSITY=0
            shift
            continue
            ;;
        '--verbose')
            CLI_OUTPUT_VERBOSITY=2
            shift
            continue
            ;;
        '--no-color')
            CLI_NO_COLOR=1
            shift
            continue
            ;;
        '--check-tools')
            CHECK_TOOLS_OR_EXIT=true
            shift
            continue
            ;;
        '--show-cache')
            SHOW_CACHE=true
            shift
            continue
            ;;
        '--banner')
            SHOW_BANNER=true
            shift
            continue
            ;;
        '--no-banner')
            SHOW_BANNER=false
            shift
            continue
            ;;
        '--legal')
            SHOW_LEGAL=true
            shift
            continue
            ;;
        '--source-only')
            shift
            continue
            ;;
        '--help' | '-h')
            HELP_REQUESTED=true
            break
            ;;
        '--')
            shift
            break
            ;;
        *)
            UNKNOWN_ARGUMENT=true
            break
            ;;
    esac
done

# Load configuration
SCRIPTPATH="$(
    cd "$(dirname "$0")" >/dev/null 2>&1 || exit
    pwd -P
)"
. "${SCRIPTPATH}"/subenum.cfg || {
    _print_error "Error importing subenum.cfg"
    exit 1
}

# Source optional secrets file (gitignored, for API keys and tokens)
[[ -f "${SCRIPTPATH}/secrets.cfg" ]] && . "${SCRIPTPATH}/secrets.cfg"

if [[ -n "$CUSTOM_CONFIG" ]] && [[ -s $CUSTOM_CONFIG ]]; then
    . "${CUSTOM_CONFIG}" || {
        _print_error "Error importing custom config"
        exit 1
    }
fi

# Re-apply CLI overrides after config load (config defaults should not clobber CLI flags)
if [[ -n "${CLI_PARALLEL_MODE:-}" ]]; then
    PARALLEL_MODE="${CLI_PARALLEL_MODE}"
fi
if [[ -n "${CLI_OUTPUT_VERBOSITY:-}" ]]; then
    OUTPUT_VERBOSITY="${CLI_OUTPUT_VERBOSITY}"
fi
if [[ -n "${CLI_NO_COLOR:-}" ]]; then
    NO_COLOR=1
fi
if [[ "${CLI_FORCE_RESCAN:-false}" == "true" ]]; then
    FORCE_RESCAN=true
fi
if [[ "${CLI_DRY_RUN:-false}" == "true" ]]; then
    DRY_RUN=true
fi
if [[ "${CLI_GENERATE_RESOLVERS:-false}" == "true" ]]; then
    generate_resolvers=true
fi
if [[ "${CLI_CACHE_REFRESH:-false}" == "true" ]]; then
    CACHE_REFRESH=true
fi
SHOW_CACHE="${SHOW_CACHE:-false}"

if [[ "${HELP_REQUESTED:-false}" == "true" ]]; then
    help
    exit 0
fi

if [[ "${OUTPUT_VERBOSITY:-1}" -eq 0 ]]; then
    SHOW_BANNER=false
    SHOW_LEGAL=false
fi

if [[ $opt_deep ]]; then
    DEEP=true
fi

if [[ -n $rate_limit ]]; then
    DNSX_RATE_LIMIT=$rate_limit
    HTTPX_RATELIMIT=$rate_limit
fi

# Root/sudo detection (used by the installer; kept for parity)
if [[ $(id -u | grep -o '^0$') == "0" ]]; then
    SUDO=""
else
    SUDO="sudo"
fi

# Resolve output root
if [[ -z "$OUTPUT_ROOT" ]]; then
    OUTPUT_ROOT="${SCRIPTPATH}/Recon"
fi
OUTPUT_ROOT="${OUTPUT_ROOT%/}"

startdir=${PWD}

# Initialize UI layer after config and CLI overrides (before any output)
ui_init

# Apply --only method selection (map function names -> config flags)
apply_only_selection() {
    [[ -z "$ONLY_METHODS" ]] && return 0
    declare -A only_map=(
        [sub_asn]=ASN_ENUM
        [sub_passive]=SUBPASSIVE
        [sub_crt]=SUBCRT
        [sub_noerror]=SUBNOERROR
        [sub_srv]=SRV_ENUM
        [sub_brute]=SUBBRUTE
        [sub_permut]=SUBPERMUTE
        [sub_regex_permut]=SUBREGEXPERMUTE
        [sub_ia_permut]=SUBIAPERMUTE
        [sub_recursive_passive]=SUB_RECURSIVE_PASSIVE
        [sub_recursive_brute]=SUB_RECURSIVE_BRUTE
        [sub_scraping]=SUBSCRAPING
        [sub_analytics]=SUBANALYTICS
        [sub_ns_delegation]=NS_DELEGATION
        [sub_ptr_cidrs]=PTR_SWEEP
        [zonetransfer]=ZONETRANSFER
    )
    local flag m
    for flag in "${!only_map[@]}"; do
        printf -v "${only_map[$flag]}" '%s' false
    done
    IFS=',' read -ra _only_selected <<<"$ONLY_METHODS"
    for m in "${_only_selected[@]}"; do
        m="${m// /}"
        [[ -z "$m" ]] && continue
        if [[ -n "${only_map[$m]:-}" ]]; then
            printf -v "${only_map[$m]}" '%s' true
        else
            _print_msg WARN "Unknown method for --only: ${m}"
        fi
    done
    unset _only_selected
}
apply_only_selection

# Returns 0 when a method is allowed to run under --only selection.
_method_selected() {
    [[ -z "$ONLY_METHODS" ]] && return 0
    [[ ",${ONLY_METHODS}," == *",$1,"* ]]
}

if [[ "${SHOW_BANNER:-false}" == "true" ]]; then
    banner
fi
if [[ "${SHOW_LEGAL:-false}" == "true" ]]; then
    printf "  %b[LEGAL]%b Authorized testing only. You confirm explicit permission\n" "$yellow" "$reset"
    printf "          for specified targets and compliance with applicable laws.\n\n"
fi

# Check critical dependencies before proceeding
check_critical_dependencies

if [[ "${DRY_RUN:-false}" == "true" ]]; then
    _print_status WARN "DRY-RUN MODE ENABLED" "0s"
fi

# Expand an IP/CIDR target into one or more concrete targets.
expand_target() {
    local t="$1"
    if [[ "$t" == */* ]] && [[ "$t" =~ ^[0-9./]+$ ]]; then
        if command -v mapcidr >/dev/null 2>&1; then
            mapcidr -silent <<<"$t" 2>>"${LOGFILE:-/dev/null}" | sed '/^$/d'
            return 0
        fi
        print_warnf "mapcidr not installed; treating '%s' as a single target" "$t"
    fi
    printf '%s\n' "$t"
}

# Per-target workflow: prepare dirs, run enumeration, summarize.
subenum_target() {
    local target="$1"

    domain="$target"
    dir="${OUTPUT_ROOT}/${domain}"
    called_fn_dir="$dir/.called_fn"

    if [[ -z $domain ]]; then
        notification "${bred} No domain or list provided ${reset}\n\n" error
        exit 1
    fi

    mkdir -p "$called_fn_dir" "$dir" || {
        print_errorf "Failed to create target directory: %s" "$dir"
        return 1
    }
    if [[ "${FORCE_RESCAN:-false}" == "true" ]]; then
        rm -f "$called_fn_dir"/.* 2>>"${LOGFILE:-/dev/null}" || true
        rm -f "$called_fn_dir"/.inprogress_* 2>>"${LOGFILE:-/dev/null}" || true
    fi

    cd "$dir" || {
        print_errorf "Failed to cd directory in %s @ line %s" "${FUNCNAME[0]}" "${LINENO}"
        return 1
    }

    # Only the subdomains/ tree is a public output; .log/.tmp/.called_fn are internal state.
    mkdir -p .log .tmp subdomains
    chmod 700 .tmp 2>/dev/null || true
    touch subdomains/subdomains.txt 2>/dev/null || true

    NOW=$(date +"%F")
    NOWT=$(date +"%T")
    LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
    touch "$LOGFILE"
    DEBUG_LOG="${dir}/.log/debug.log"
    touch "$DEBUG_LOG"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Start ${NOW} ${NOWT}" >"${LOGFILE}"
    enable_command_trace

    # Cache resolver selection once per run
    init_dns_resolver

    # Rotate old log files
    rotate_logs "${dir}/.log" "${MAX_LOG_FILES:-10}" "${MAX_LOG_AGE_DAYS:-30}"

    # Traps for cleanup / resume sentinel sweep
    trap 'cleanup_on_exit' INT TERM
    trap '_cleanup_inprogress' EXIT

    log_init
    cache_init
    cache_clean "${CACHE_MAX_AGE_DAYS:-30}" 2>>"${LOGFILE:-/dev/null}" || true

    # Non-fatal error trap: log and continue
    trap 'rc=$?; ts=$(date +"%Y-%m-%d %H:%M:%S"); cmd=${BASH_COMMAND}; loc_fn=${FUNCNAME[0]:-main}; loc_ln=${BASH_LINENO[0]:-0}; msg="[$ts] ERR($rc) @ ${loc_fn}:${loc_ln} :: ${cmd}"; if [[ -n "${LOGFILE:-}" ]]; then echo "$msg" >>"$LOGFILE"; else echo "$msg" >&2; fi; explain_err "$rc" "$cmd" "$loc_fn" "$loc_ln"' ERR

    ui_header

    if [[ "${FORCE_RESCAN:-false}" == "true" ]]; then
        _print_msg WARN "Force rescan enabled: ignoring cached module markers"
    fi

    tools_installed

    global_start=$(date +%s)
    _RECON_CLEAN_EXIT=false

    _print_section "Subdomains"
    subdomains_full

    # Zone transfer is an additional enumeration source; run it before final summary.
    zonetransfer

    # Recompute the "new since previous run" delta so zone-transfer hits are included.
    if [[ -s ".tmp/subdomains_old.txt" ]]; then
        comm -13 <(sort -u ".tmp/subdomains_old.txt") <(sort -u "subdomains/subdomains.txt" 2>/dev/null) \
            | sed '/^$/d' >"subdomains/subdomains_new.txt" 2>/dev/null || true
    else
        cp "subdomains/subdomains.txt" "subdomains/subdomains_new.txt" 2>/dev/null || true
    fi

    # Final summary
    local TOTAL_SUBS NEW_SUBS
    TOTAL_SUBS=$(count_lines "subdomains/subdomains.txt")
    NEW_SUBS=$(count_lines "subdomains/subdomains_new.txt")

    global_end=$(date +%s)
    getElapsedTime "$global_start" "$global_end"
    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 1 ]]; then
        printf "\n"
        printf "RESULTS  %s\n" "$domain"
        printf "Mode: SUBDOMAINS\n"
        printf "Subdomains: %s\n" "${TOTAL_SUBS:-0}"
        printf "New since previous run: %s\n" "${NEW_SUBS:-0}"
        printf "Duration: %s\n" "$runtime"
        printf "Output: %s\n" "$dir"
        printf "\n"
    fi
    notification "Finished subdomain enumeration on: ${domain} (${TOTAL_SUBS:-0} subdomains, ${NEW_SUBS:-0} new) in: ${runtime}" good "$(date +'%Y-%m-%d %H:%M:%S')"

    print_timing_summary

    _RECON_CLEAN_EXIT=true
    cd "${startdir}" 2>/dev/null || cd "$SCRIPTPATH" || true
    return 0
}

run_all_targets() {
    if [[ -n $list ]]; then
        local flist
        if [[ $list == ./* ]]; then
            flist="${startdir}/${list:2}"
        elif [[ $list == ~* ]]; then
            flist="${HOME}/${list:2}"
        elif [[ $list == /* ]]; then
            flist=$list
        else
            flist="$startdir/$list"
        fi
        # Never mutate the user's input file: strip CRs into a private temp copy.
        local tmp_list
        tmp_list=$(mktemp -t subenum_targets.XXXXXX) || {
            print_errorf "Failed to create temporary target list"
            exit 1
        }
        tr -d '\r' <"$flist" >"$tmp_list"
        while IFS= read -r raw_domain <&3 || [[ -n "$raw_domain" ]]; do
            [[ -z "$raw_domain" ]] && continue
            raw_domain=$(_sanitize_list_entry "$raw_domain") || continue
            local expanded
            while IFS= read -r expanded; do
                [[ -z "$expanded" ]] && continue
                subenum_target "$expanded"
            done < <(expand_target "$raw_domain")
        done 3<"$tmp_list"
        rm -f "$tmp_list" 2>/dev/null || true
    elif [[ -n $domain ]]; then
        local expanded
        while IFS= read -r expanded; do
            [[ -z "$expanded" ]] && continue
            subenum_target "$expanded"
        done < <(expand_target "$domain")
    else
        help
        if [[ $UNKNOWN_ARGUMENT == true ]]; then
            exit 1
        fi
        exit 0
    fi
}

run_all_targets
