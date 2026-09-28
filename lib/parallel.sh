#!/usr/bin/env bash
# lib/parallel.sh - minimal parallel runner for subenum phases

[[ -n "${_PARALLEL_SH_LOADED:-}" ]] && return 0
declare -r _PARALLEL_SH_LOADED=1

PARALLEL_MAX_JOBS="${PARALLEL_MAX_JOBS:-4}"

# Run functions in parallel, capped at max_jobs.
# Usage: parallel_funcs <max_jobs> func1 func2 ...
# Returns the number of failed jobs.
parallel_funcs() {
    local max_jobs="${1:-$PARALLEL_MAX_JOBS}"
    shift
    [[ "$max_jobs" =~ ^[0-9]+$ ]] || max_jobs="$PARALLEL_MAX_JOBS"
    ((max_jobs < 1)) && max_jobs=1

    local -a pids=() funcs=()
    local func failed=0
    for func in "$@"; do
        if ! declare -f "$func" >/dev/null 2>&1; then
            print_warnf "Function %s not found, skipping" "$func"
            continue
        fi
        "$func" &
        pids+=("$!")
        funcs+=("$func")
        while (( $(jobs -rp | wc -l) >= max_jobs )); do
            wait -n 2>/dev/null || true
        done
    done

    local i rc
    for i in "${!pids[@]}"; do
        wait "${pids[$i]}" 2>/dev/null
        rc=$?
        if ((rc != 0)); then
            failed=$((failed + 1))
        fi
    done
    return "$failed"
}
