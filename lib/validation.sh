#!/bin/bash
# subenum Validation Library
# Provides input validation functions

set -o pipefail

# NOTE: sanitize_domain() is defined in modules/utils.sh
# This avoids duplication and ensures consistent behavior

# validate_file_exists()
# Description: Validates that a file exists
# Arguments: $1 - File path
# Returns: 0 if file exists, E_INVALID_PATH if not
function validate_file_exists() {
	local file="$1"

	if [[ -z "$file" ]]; then
		return $E_INVALID_PATH
	fi

	if [[ ! -e "$file" ]]; then
		return $E_INVALID_PATH
	fi

	return 0
}

# validate_file_readable()
# Description: Validates that a file exists and is readable
# Arguments: $1 - File path
# Returns: 0 if readable, E_INVALID_PATH if not
function validate_file_readable() {
	local file="$1"

	if ! validate_file_exists "$file"; then
		return $E_INVALID_PATH
	fi

	if [[ ! -r "$file" ]]; then
		return $E_INVALID_PATH
	fi

	if [[ ! -f "$file" ]]; then
		return $E_INVALID_PATH
	fi

	return 0
}

