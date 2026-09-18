#!/bin/bash
# subenum - Resolver management module (trimmed from reconFTW modules/axiom.sh)
# Contains: resolvers_update, resolvers_update_quick_local, resolvers_optimize_local
# This file is sourced by subenum.sh - do not execute directly

# shellcheck disable=SC2154  # Variables defined in subenum.cfg
# shellcheck disable=SC2034

[[ -z "${SCRIPTPATH:-}" ]] && {
    echo "Error: This module must be sourced by subenum.sh" >&2
    exit 1
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
            cached_download_typed "${resolvers_url}" "$resolvers" "resolvers.txt" "resolvers" || return 1
            cached_download_typed "${resolvers_trusted_url}" "$resolvers_trusted" "resolvers_trusted.txt" "resolvers" || return 1
            if [[ ! -s "$resolvers" ]] || [[ ! -s "$resolvers_trusted" ]]; then
                _print_msg WARN "Resolver files are missing or empty after update"
                return 1
            fi
            _print_msg OK "Resolvers updated"
        fi
    fi
}

function resolvers_update_quick_local() {
    if [[ $update_resolvers == true ]]; then
        cached_download_typed "${resolvers_url}" "$resolvers" "resolvers.txt" "resolvers"
        cached_download_typed "${resolvers_trusted_url}" "$resolvers_trusted" "resolvers_trusted.txt" "resolvers"
    fi
}

function resolvers_optimize_local() {
    # Experimental: dedupe resolvers
    sort -u "$resolvers" -o "$resolvers" 2>/dev/null || true
    sort -u "$resolvers_trusted" -o "$resolvers_trusted" 2>/dev/null || true
}
