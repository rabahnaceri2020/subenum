#!/bin/bash
# shellcheck disable=SC2154,SC2034
#
# subenum installer - installs ONLY the tools required for subdomain enumeration.
# No OSINT, no web scanning, no screenshots, no vulnerability tooling.
#
# Usage: ./install.sh [--tools] [--verbose] [--log <file>] [--dry-run] [-h]

# Safer bash defaults
set -o pipefail
set -E
set +e
IFS=$'\n\t'

# Detect if the script is being run in macOS and re-exec with modern Bash.
if [[ $OSTYPE == "darwin"* ]]; then
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

# Load main configuration
CONFIG_FILE="./subenum.cfg"
if [[ ! -f $CONFIG_FILE ]]; then
    printf "[!] Config file subenum.cfg not found.\n"
    exit 1
fi

# shellcheck source=./subenum.cfg
if ! source "$CONFIG_FILE"; then
    printf "[!] Failed to parse config file %s. Check for syntax errors.\n" "$CONFIG_FILE" >&2
    exit 1
fi

# Initialize variables
dir="${tools}"
double_check=false
ARCH=$(uname -m)
IS_MAC=$([[ $OSTYPE == "darwin"* ]] && echo "True" || echo "False")

# timeout/gtimeout compatibility
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_CMD="gtimeout"
else
    TIMEOUT_CMD=""
fi

# Globals for CLI overrides
FORCE_UPDATE=${FORCE_UPDATE:-false}
VERBOSE=${VERBOSE:-false}
LOGFILE=${LOGFILE:-"./install.log"}
DRY_RUN=${DRY_RUN:-false}
TOOLS_ONLY=${TOOLS_ONLY:-false}

# Log all output (default: install.log in repo root)
if [[ -n ${LOGFILE} ]]; then
    : >"${LOGFILE}"
    exec > >(tee -a "${LOGFILE}") 2>&1
fi

run_to() {
    local secs=$1
    shift || true
    if [[ -n $TIMEOUT_CMD ]]; then "$TIMEOUT_CMD" "$secs" "$@"; else "$@"; fi
}

run_cmd() {
    if [[ $DRY_RUN == "true" ]]; then
        printf "%s" "[DRY-RUN] "
        printf "%q " "$@"
        printf "\n"
        return 0
    fi
    "$@"
}

q() {
    if [[ $DRY_RUN == "true" ]]; then
        printf "%s" "[DRY-RUN] "
        printf "%q " "$@"
        printf "\n"
        return 0
    fi
    if [[ $VERBOSE == "true" ]]; then "$@"; else { "$@"; } &>/dev/null; fi
}

q_to() {
    local secs=$1
    shift || true
    if [[ $DRY_RUN == "true" ]]; then
        printf "%s" "[DRY-RUN] (to ${secs}) "
        printf "%q " "$@"
        printf "\n"
        return 0
    fi
    if [[ -n $TIMEOUT_CMD ]]; then
        if [[ $VERBOSE == "true" ]]; then "$TIMEOUT_CMD" "$secs" "$@"; else { "$TIMEOUT_CMD" "$secs" "$@"; } &>/dev/null; fi
    else
        if [[ $VERBOSE == "true" ]]; then "$@"; else { "$@"; } &>/dev/null; fi
    fi
}

retry() {
    local attempts=$1
    local delay=$2
    shift 2
    local n=0
    until "$@"; do
        n=$((n + 1))
        if ((n >= attempts)); then return 1; fi
        sleep $((delay * n))
    done
}

ensure_git_dir() {
    local _path="$1"
    if [[ -d "$_path" && ! -d "$_path/.git" ]]; then
        rm -rf "$_path" 2>/dev/null || true
    fi
}

# Non-fatal error trap: log and continue
trap 'rc=$?; ts=$(date +"%Y-%m-%d %H:%M:%S"); cmd=${BASH_COMMAND}; loc_ln=${BASH_LINENO[0]:-0}; msg="[$ts] install.sh ERR($rc) @ line ${loc_ln} :: ${cmd}"; if [[ -n "${LOGFILE:-}" ]]; then echo "$msg" >>"$LOGFILE"; else echo "$msg" >&2; fi' ERR

# -------------------------------
# Minimal UI helpers
# -------------------------------

header() { printf "%bRunning: %s%b\n" "$bblue" "$1" "$reset"; }
msg_run() { printf "%b%s%b\n" "$yellow" "$1" "$reset"; }
msg_ok() { printf "%b%s%b\n" "$bgreen" "$1" "$reset"; }
msg_warn() { printf "%b%s%b\n" "$yellow" "$1" "$reset"; }
msg_err() { printf "%b%s%b\n" "$red" "$1" "$reset"; }

with_spinner() {
    local _msg="$1"
    shift
    if [[ $DRY_RUN == "true" ]]; then
        printf "%s\n" "[DRY-RUN] ${_msg}"
        printf "%s" "[DRY-RUN] "
        printf "%q " "$@"
        printf "\n"
        return 0
    fi
    if [[ $VERBOSE == "true" ]]; then
        [[ -n $_msg ]] && printf "%s\n" "$_msg"
        "$@"
        return $?
    fi
    if [[ ! -t 1 ]]; then
        [[ -n $_msg ]] && printf "%s ... " "$_msg"
        "$@" >/dev/null 2>&1
        local exit_code=$?
        if [[ $exit_code -eq 0 ]]; then
            printf "done\n"
        else
            printf "failed\n"
        fi
        return $exit_code
    fi
    local spinner="|/-\\"
    local spinner_len=4
    local i=0
    [[ -n $_msg ]] && printf "%s " "$_msg"
    "$@" &
    local cmd_pid=$!
    while kill -0 "$cmd_pid" 2>/dev/null; do
        printf "\r%s %s" "$_msg" "${spinner:i:1}"
        i=$(((i + 1) % spinner_len))
        sleep 0.1
    done
    wait "$cmd_pid"
    local exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        printf "\r%s done\n" "$_msg"
    else
        printf "\r%s failed\n" "$_msg"
    fi
    return $exit_code
}

check_network() {
    printf "%bRunning: Network precheck%b\n" "$bblue" "$reset"
    local _net_ok=true
    if ! q_to 5 bash -lc 'getent hosts github.com >/dev/null 2>&1 || dig +short github.com >/dev/null 2>&1 || nslookup github.com >/dev/null 2>&1'; then
        printf "%b[!] DNS resolution for github.com failed. Check your network.%b\n" "$bred" "$reset"
        _net_ok=false
    fi
    if ! q_to 10 curl -I -s https://github.com >/dev/null 2>&1; then
        printf "%b[!] HTTPS connectivity to github.com failed. Installer may fail.%b\n" "$yellow" "$reset"
        _net_ok=false
    fi
    if [[ $_net_ok == true ]]; then
        printf "%bNetwork OK%b\n" "$bgreen" "$reset"
    fi

    local _avail_mb
    _avail_mb=$(df -m "${HOME}" 2>/dev/null | awk 'NR==2{print $4}')
    if [[ -n ${_avail_mb:-} ]] && (( _avail_mb < 3072 )); then
        printf "%b[!] Low disk space: only %s MB free on %s. Installation needs ~3GB.%b\n" "$bred" "$_avail_mb" "$HOME" "$reset"
    fi

    if [[ -f /proc/meminfo ]]; then
        local _mem_total_kb
        _mem_total_kb=$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null || true)
        if [[ -n ${_mem_total_kb:-} ]] && (( _mem_total_kb < 1048576 )); then
            printf "%b[!] Low memory: %s MB total. Go compilation may fail. Consider adding swap.%b\n" "$yellow" "$((_mem_total_kb / 1024))" "$reset"
        fi
    fi
}

# Check Bash version
BASH_VERSION_NUM=$(bash --version | awk 'NR==1{print $4}' | cut -d'.' -f1)
if [[ $BASH_VERSION_NUM -lt 4 ]]; then
    printf "%bYour Bash version is lower than 4, please update.%b\n" "$bred" "$reset"
    if [[ $IS_MAC == "True" ]]; then
        printf "%bFor macOS, run 'brew install bash' and rerun the installer in a new terminal.%b\n" "$yellow" "$reset"
    fi
    exit 1
fi

# ------------------------------------------------------------------------------
# Tools used by subenum and its pipeline script (script.sh)
# ------------------------------------------------------------------------------
declare -A gotools=(
    ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    ["github-subdomains"]="github.com/gwen001/github-subdomains"
    ["gitlab-subdomains"]="github.com/gwen001/gitlab-subdomains"
    ["asnmap"]="github.com/projectdiscovery/asnmap/cmd/asnmap"
    ["puredns"]="github.com/d3mondev/puredns/v2"
    ["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx"
    ["dsieve"]="github.com/trickest/dsieve"
    ["gotator"]="github.com/Josue87/gotator"
    ["analyticsrelationships"]="github.com/Josue87/analyticsrelationships"
    ["csprecon"]="github.com/edoardottt/csprecon/cmd/csprecon"
    ["tlsx"]="github.com/projectdiscovery/tlsx/cmd/tlsx"
    ["hakip2host"]="github.com/hakluke/hakip2host"
    ["mapcidr"]="github.com/projectdiscovery/mapcidr/cmd/mapcidr"
    ["urlfinder"]="github.com/projectdiscovery/urlfinder/cmd/urlfinder"
    ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx"
    ["anew"]="github.com/tomnomnom/anew"
    ["unfurl"]="github.com/tomnomnom/unfurl"
    ["inscope"]="github.com/tomnomnom/hacks/inscope"
    ["notify"]="github.com/projectdiscovery/notify/cmd/notify"
    ["katana"]="github.com/projectdiscovery/katana/cmd/katana"
    ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
)

# uv-managed Python tools used by subdomain enumeration
declare -A pipxtools=(
    ["waymore"]="xnl-h4ck3r/waymore"
    ["subwiz"]="hadriansecurity/subwiz"
    ["dnsvalidator"]="vortexau/dnsvalidator"
)

# Repositories needed for subdomain enumeration
declare -A repos=(
    ["massdns"]="blechschmidt/massdns"
    ["regulator"]="cramppet/regulator"
)

function banner() {
    printf "\n"
    printf "%b" "$bgreen"
    cat <<'EOF'

  subenum installer - subdomain enumeration tooling only
  (methods extracted from reconFTW)

EOF
    printf "%b" "$reset"
}

# Clone a GitHub repo with retry + cleanup between attempts.
clone_repo() {
    local gh_path="$1" dest="$2"
    [[ -z "$dest" || "$dest" == "/" ]] && return 1
    local url="https://github.com/${gh_path}"
    local n=0 max=3 delay=3
    while true; do
        rm -rf "$dest" 2>/dev/null
        if q_to 180 git clone --filter="blob:none" "$url" "$dest"; then
            return 0
        fi
        rm -rf "$dest" 2>/dev/null
        if q_to 180 git clone "$url" "$dest"; then
            return 0
        fi
        n=$((n + 1))
        if ((n >= max)); then return 1; fi
        sleep $((delay * n))
    done
}

# Install Go tools
function install_tools() {
    header "Installing Golang tools (${#gotools[@]})"

    export GOFLAGS="-mod=mod"
    export GO111MODULE="on"

    local go_step=0
    local failed_tools=()
    local total_go=${#gotools[@]}
    local go_ok=0 go_skip=0 go_fail=0
    for gotool in "${!gotools[@]}"; do
        ((++go_step))
        if q go install -v "${gotools[$gotool]}@latest"; then
            ((++go_ok))
            msg_ok "[$go_step/$total_go] ${gotool} installed"
        else
            if command -v "$gotool" >/dev/null 2>&1; then
                ((++go_skip))
                msg_warn "[$go_step/$total_go] ${gotool} upgrade failed (existing binary kept)"
            else
                failed_tools+=("$gotool")
                ((++go_fail))
                double_check=true
                msg_err "[$go_step/$total_go] ${gotool} failed"
            fi
        fi
    done

    header "Installing uv tools (${#pipxtools[@]})"

    local pipx_step=0
    local failed_pipx_tools=()
    local total_px=${#pipxtools[@]}
    local px_ok=0 px_fail=0

    for pipxtool in "${!pipxtools[@]}"; do
        ((++pipx_step))
        local tool_url="git+https://github.com/${pipxtools[$pipxtool]}"
        if q uv tool install "$tool_url" --force; then
            ((++px_ok))
            msg_ok "[$pipx_step/$total_px] ${pipxtool} ready"
        else
            failed_pipx_tools+=("$pipxtool")
            ((++px_fail))
            double_check=true
            msg_err "[$pipx_step/$total_px] ${pipxtool} failed"
        fi
    done

    header "Installing repositories (${#repos[@]})"

    local repos_step=0
    local failed_repos=()
    local total_repo=${#repos[@]}
    local repo_ok=0 repo_skip=0 repo_fail=0

    for repo in "${!repos[@]}"; do
        ((++repos_step))
        if [[ $DRY_RUN == "true" ]]; then
            printf "%s\n" "[DRY-RUN] clone/pull ${repo} from https://github.com/${repos[$repo]}"
            continue
        fi
        if [[ $upgrade_tools == "false" ]]; then
            if [[ -d "${dir}/${repo}" ]]; then
                ((++repo_skip))
                msg_warn "[$repos_step/$total_repo] $repo already present at ${dir}/${repo}"
                continue
            fi
        fi
        if [[ ! -d "${dir}/${repo}/.git" ]]; then
            [[ -d "${dir}/${repo}" ]] && rm -rf "${dir}/${repo}"
            msg_run "[$repos_step/${#repos[@]}] $repo (clone)"
            clone_repo "${repos[$repo]}" "${dir}/${repo}"
            exit_status=$?
            if [[ $exit_status -ne 0 ]]; then
                msg_err "[$repos_step/$total_repo] $repo clone failed"
                failed_repos+=("$repo")
                ((++repo_fail))
                double_check=true
                continue
            fi
            ((++repo_ok))
        fi

        cd "${dir}/${repo}" || {
            msg_err "[$repos_step/$total_repo] $repo: cannot enter ${dir}/${repo}"
            failed_repos+=("$repo")
            ((++repo_fail))
            double_check=true
            continue
        }

        msg_run "[$repos_step/${#repos[@]}] $repo (pull)"
        retry 3 3 q_to 60 git pull
        exit_status=$?
        if [[ $exit_status -ne 0 ]]; then
            msg_err "[$repos_step/$total_repo] $repo pull failed"
            failed_repos+=("$repo")
            ((++repo_fail))
            double_check=true
            continue
        fi

        case "$repo" in
            "massdns")
                if ! q make; then
                    msg_warn "[$repos_step/$total_repo] $repo: make failed"
                else
                    strip -s bin/massdns 2>/dev/null || true
                    $SUDO cp bin/massdns /usr/local/bin/ &>/dev/null
                fi
                ;;
            "regulator")
                if [[ ! -d "venv" ]]; then
                    uv venv venv &>/dev/null || true
                fi
                if [[ -s "requirements.txt" ]]; then
                    uv pip install --upgrade -r requirements.txt --python venv/bin/python3 &>/dev/null || msg_warn "[$repos_step/$total_repo] $repo: pip requirements failed"
                fi
                ;;
        esac

        cd "$dir" || {
            msg_err "Failed to navigate back to directory '$dir'"
            exit 1
        }

        msg_ok "[$repos_step/$total_repo] $repo ready"
    done

    # Initialize tool configs on first run
    q command -v subfinder >/dev/null 2>&1 && q subfinder || true
    mkdir -p "${HOME}/.config/notify"
    q command -v notify >/dev/null 2>&1 && q notify || true

    # Installation summary
    printf "\n%b--- Tool Installation Summary ---%b\n" "$bblue" "$reset"
    printf "  Go tools:  %b%d OK%b, %d skipped, %b%d failed%b (of %d)\n" \
        "$bgreen" "$go_ok" "$reset" "$go_skip" \
        "$([[ $go_fail -gt 0 ]] && echo "$red" || echo "$bgreen")" "$go_fail" "$reset" "$total_go"
    printf "  uv tools:  %b%d OK%b, %b%d failed%b (of %d)\n" \
        "$bgreen" "$px_ok" "$reset" \
        "$([[ $px_fail -gt 0 ]] && echo "$red" || echo "$bgreen")" "$px_fail" "$reset" "$total_px"
    printf "  Repos:     %b%d OK%b, %d skipped, %b%d failed%b (of %d)\n" \
        "$bgreen" "$repo_ok" "$reset" "$repo_skip" \
        "$([[ $repo_fail -gt 0 ]] && echo "$red" || echo "$bgreen")" "$repo_fail" "$reset" "$total_repo"

    local _total_fail=$(( go_fail + px_fail + repo_fail ))
    if [[ $_total_fail -gt 0 ]]; then
        printf "\n%bFailed items:%b\n" "$red" "$reset"
        [[ ${#failed_tools[@]} -gt 0 ]] && printf "  Go:    %s\n" "${failed_tools[*]}"
        [[ ${#failed_pipx_tools[@]} -gt 0 ]] && printf "  uv:    %s\n" "${failed_pipx_tools[*]}"
        [[ ${#failed_repos[@]} -gt 0 ]] && printf "  Repos: %s\n" "${failed_repos[*]}"
        printf "\n%bRe-run install.sh to retry failed items.%b\n" "$yellow" "$reset"
    fi
}

# Install/Update Golang
function install_golang_version() {
    local version="go1.23.6"
    local latest_version
    latest_version=$(curl -s https://go.dev/VERSION?m=text | head -1 || echo "go1.23.6")
    if [[ $latest_version == g* ]]; then
        version="$latest_version"
    fi

    printf "%bRunning: Installing/Updating Golang(%s) %b\n" "$bblue" "$version" "$reset"

    if [[ $install_golang == "true" ]]; then
        local current_version=""
        if command -v go &>/dev/null; then
            current_version="$(go version | awk '{print $3}')"
        fi

        if [[ -n $current_version && $version == "$current_version" ]]; then
            printf "%bGolang is already installed and up to date.%b\n" "$bgreen" "$reset"
        else
            local archive_suffix=""

            case "$ARCH" in
                arm64 | aarch64)
                    if [[ $IS_MAC == "True" ]]; then
                        archive_suffix="darwin-arm64"
                    else
                        archive_suffix="linux-arm64"
                    fi
                    ;;
                armv6l | armv7l)
                    archive_suffix="linux-armv6l"
                    ;;
                amd64 | x86_64)
                    if [[ $IS_MAC == "True" ]]; then
                        archive_suffix="darwin-amd64"
                    else
                        archive_suffix="linux-amd64"
                    fi
                    ;;
                *)
                    msg_err "[!] Unsupported architecture. Please install go manually."
                    return 1
                    ;;
            esac

            local archive_url="https://dl.google.com/go/${version}.${archive_suffix}.tar.gz"
            local archive_path="/tmp/${version}.${archive_suffix}.tar.gz"

            if ! wget "$archive_url" -O "$archive_path" &>/dev/null; then
                msg_err "[!] Failed to download Golang archive from ${archive_url}"
                return 1
            fi

            local expected_sha256
            expected_sha256=$(curl -sL "${archive_url}.sha256" 2>/dev/null || true)
            if [[ -n $expected_sha256 ]]; then
                local actual_sha256
                if command -v sha256sum &>/dev/null; then
                    actual_sha256=$(sha256sum "$archive_path" | awk '{print $1}')
                elif command -v shasum &>/dev/null; then
                    actual_sha256=$(shasum -a 256 "$archive_path" | awk '{print $1}')
                fi
                if [[ -n ${actual_sha256:-} && $actual_sha256 != "$expected_sha256" ]]; then
                    msg_err "[!] SHA256 checksum mismatch for Go archive"
                    rm -f "$archive_path"
                    return 1
                fi
            fi

            local tmp_unpack
            tmp_unpack=$(mktemp -d 2>/dev/null || mktemp -d -t goinstall)
            trap 'rm -rf "$tmp_unpack" "$archive_path"' RETURN
            if ! tar -C "$tmp_unpack" -xzf "$archive_path" &>/dev/null; then
                msg_err "[!] Failed to extract ${archive_path}"
                return 1
            fi

            if [[ ! -d "${tmp_unpack}/go" ]]; then
                msg_err "[!] Extracted archive missing 'go' directory"
                return 1
            fi

            local go_backup=""
            if [[ -d /usr/local/go ]]; then
                go_backup="/usr/local/go.subenum.$(date +%s)"
                if ! $SUDO mv /usr/local/go "$go_backup" &>/dev/null; then
                    go_backup=""
                    $SUDO rm -rf /usr/local/go &>/dev/null || true
                fi
            fi
            if ! $SUDO mv "${tmp_unpack}/go" /usr/local/go; then
                msg_err "[!] Failed to move Golang into /usr/local/go"
                if [[ -n $go_backup && -d $go_backup ]]; then
                    $SUDO mv "$go_backup" /usr/local/go &>/dev/null || true
                fi
                return 1
            fi
            if [[ -n $go_backup ]]; then
                $SUDO rm -rf "$go_backup" &>/dev/null
            fi

            $SUDO ln -sf /usr/local/go/bin/go /usr/local/bin/ 2>/dev/null
        fi

        export GOROOT=/usr/local/go
        export GOPATH="${HOME}/go"
        export PATH="$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$PATH"

        # Write Go env to profile files so it's available in login shells.
        local marker="# Golang environment variables (subenum)"
        local _go_env_block
        _go_env_block=$(printf '%s\nexport GOROOT=/usr/local/go\nexport GOPATH=$HOME/go\nexport PATH=$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$PATH\n' "$marker")

        local _profile_targets=()
        _profile_targets+=("${HOME}/.profile")
        local _detected_shell="${SHELL:-/bin/bash}"
        local _profile_shell
        _profile_shell=".$(basename "${_detected_shell}")rc"
        if [[ -n ${_profile_shell:-} && "${_profile_shell}" != ".profile" ]]; then
            _profile_targets+=("${HOME}/${_profile_shell}")
        fi

        for _ptarget in "${_profile_targets[@]}"; do
            if [[ -f "$_ptarget" ]] && grep -q '^# Golang environment variables' "$_ptarget" 2>/dev/null; then
                local tmp_profile
                tmp_profile=$(mktemp)
                awk '
                    /^# Golang environment variables/ { skip = 3; next }
                    skip > 0 && /^export (GOROOT|GOPATH|PATH)=/ { skip--; next }
                    skip > 0 { skip = 0 }
                    { print }
                ' "$_ptarget" > "$tmp_profile" && mv "$tmp_profile" "$_ptarget"
            fi
            printf '\n%s\n' "$_go_env_block" >>"$_ptarget"
        done
    else
        msg_warn "Golang will not be configured according to the user's preferences (install_golang=false in subenum.cfg)."
    fi

    if ! command -v go &>/dev/null; then
        msg_err "[!] Go binary not found in PATH. Please install Go or enable install_golang in subenum.cfg."
        return 1
    fi
}

# Install uv (needed for the uv-managed Python tools)
function install_uv() {
    if command -v uv &>/dev/null; then
        printf "%buv is already installed.%b\n" "$bgreen" "$reset"
        return 0
    fi
    if [[ $DRY_RUN == "true" ]]; then
        printf "%s\n" "[DRY-RUN] install uv from https://astral.sh/uv/install.sh"
        return 0
    fi
    printf "%bRunning: Installing uv%b\n" "$bblue" "$reset"
    local _tmpfile
    _tmpfile=$(mktemp "${TMPDIR:-/tmp}/uv_install.XXXXXX")
    if curl -LsSf https://astral.sh/uv/install.sh -o "$_tmpfile" 2>/dev/null; then
        sh "$_tmpfile" &>/dev/null
    else
        msg_warn "[!] Failed to download uv installer"
    fi
    rm -f "$_tmpfile"
    # shellcheck source=/dev/null
    source "${HOME}/.local/bin/env" 2>/dev/null || export PATH="${HOME}/.local/bin:$PATH"
    uv tool update-shell &>/dev/null || true
}

# System packages per OS (only what the subdomain toolchain needs)
function install_system_packages() {
    if [[ -f /etc/debian_version ]]; then
        $SUDO apt-get update -y &>/dev/null
        $SUDO apt-get install -y python3 python3-venv build-essential gcc make cmake git curl libpcap-dev wget zip gzip pv dnsutils jq ca-certificates &>/dev/null
        install_uv
    elif [[ -f /etc/redhat-release ]]; then
        $SUDO yum groupinstall "Development Tools" -y &>/dev/null
        $SUDO yum install -y epel-release &>/dev/null || true
        $SUDO yum install -y python3 gcc make cmake git curl libpcap wget zip gzip pv bind-utils jq ca-certificates &>/dev/null
        install_uv
    elif [[ -f /etc/arch-release ]]; then
        $SUDO pacman -Sy --noconfirm python base-devel gcc make cmake git curl libpcap wget zip gzip pv bind jq ca-certificates &>/dev/null
        install_uv
    elif [[ $IS_MAC == "True" ]]; then
        if ! command -v brew &>/dev/null; then
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        brew update &>/dev/null
        brew install --formula bash coreutils gnu-getopt gnu-sed python uv massdns jq gcc cmake git curl wget zip pv bind &>/dev/null
        uv tool update-shell &>/dev/null || true
    elif [[ -f /etc/os-release ]]; then
        $SUDO yum install -y python3 gcc make cmake git curl libpcap wget zip gzip pv bind-utils jq ca-certificates &>/dev/null
        install_uv
    else
        printf "%b[!] Unsupported OS. Please install dependencies manually.%b\n" "$bred" "$reset"
        exit 1
    fi
}

# Download resolvers + wordlists and expand the vendored wordlist
function download_required_files() {
    header "Downloading required files"

    if [[ $DRY_RUN == "true" ]]; then
        printf "%s\n" "[DRY-RUN] would fetch resolvers, default + big subdomain wordlists"
        return 0
    fi

    mkdir -p "$dir"
    mkdir -p "$WORDLISTS_DIR"
    touch "${dir}/.github_tokens"
    touch "${dir}/.gitlab_tokens"

    # Resolvers
    if [[ ! -s "$resolvers" ]] || [[ -n "$(find "$resolvers" -mtime +1 -print 2>/dev/null)" ]]; then
        printf "%bFetching resolvers...%b\n" "$yellow" "$reset"
        retry 3 3 q_to 120 wget -q -O "$resolvers" "$resolvers_url" || msg_err "Failed to download resolvers"
        retry 3 3 q_to 120 wget -q -O "$resolvers_trusted" "$resolvers_trusted_url" || msg_err "Failed to download trusted resolvers"
    fi

    # Default brute-force wordlist: expand the vendored .gz, or download it if absent.
    if [[ ! -s "${WORDLISTS_DIR}/subdomains.txt" ]]; then
        if [[ -s "${WORDLISTS_DIR}/subdomains.txt.gz" ]]; then
            printf "%bExpanding subdomains wordlist...%b\n" "$yellow" "$reset"
            gzip -dc "${WORDLISTS_DIR}/subdomains.txt.gz" >"${WORDLISTS_DIR}/subdomains.txt"
        else
            printf "%bFetching default subdomains wordlist...%b\n" "$yellow" "$reset"
            retry 3 3 q_to 300 wget -q -O "${WORDLISTS_DIR}/subdomains.txt.gz" \
                "https://raw.githubusercontent.com/six2dez/reconftw/main/data/wordlists/subdomains.txt.gz" \
                && gzip -dc "${WORDLISTS_DIR}/subdomains.txt.gz" >"${WORDLISTS_DIR}/subdomains.txt" \
                || msg_err "Failed to download default subdomains wordlist"
        fi
    fi

    # Big wordlist used by --deep
    if [[ ! -s "${WORDLISTS_DIR}/subdomains_big.txt" ]]; then
        printf "%bFetching big subdomains wordlist (DEEP mode)...%b\n" "$yellow" "$reset"
        retry 3 3 q_to 300 wget -q -O "${WORDLISTS_DIR}/subdomains_big.txt" \
            "https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_huge.txt" \
            || msg_err "Failed to download big subdomains wordlist"
    fi

    printf "\n%bReminder:%b for GitHub/GitLab passive sources, set tokens in:\n" "$yellow" "$reset"
    printf "  %s/.github_tokens and %s/.gitlab_tokens\n" "$dir" "$dir"
    printf "%bFinished downloading files.%b\n" "$bgreen" "$reset"
}

function initial_setup() {
    banner

    if [[ $TOOLS_ONLY == "true" ]]; then
        header "Tools-only mode"
        with_spinner "Installing/validating Golang" install_golang_version
        export GOROOT=/usr/local/go
        export GOPATH="${HOME}/go"
        export PATH="$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$PATH"
        mkdir -p "$dir"
        install_uv
        q uv tool update-shell
        export PATH="${HOME}/.local/bin:${PATH}"
        install_tools
        return
    fi

    header "Install/Update"
    with_spinner "Installing system packages" install_system_packages
    if [[ $DRY_RUN != "true" ]]; then
        check_network
    fi
    with_spinner "Installing/validating Golang" install_golang_version
    export GOROOT=/usr/local/go
    export GOPATH="${HOME}/go"
    export PATH="$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$PATH"

    mkdir -p "$dir"
    q uv tool update-shell
    export PATH="${HOME}/.local/bin:${PATH}"

    install_tools
    download_required_files

    # Strip all Go binaries and copy to /usr/local/bin (files only)
    find "${GOPATH}/bin" -type f -perm -u+x -exec strip -s {} \; 2>/dev/null || true
    find "${GOPATH}/bin" -type f -perm -u+x -exec $SUDO cp {} /usr/local/bin/ \; 2>/dev/null || true

    printf "%bFinished!%b\n" "$bgreen" "$reset"
    printf "%b#######################################################################%b\n" "$bgreen" "$reset"
    printf "Run: %b./subenum.sh -d example.com%b\n" "$bgreen" "$reset"
}

function show_additional_help() {
    cat <<USAGE
Usage: $0 [OPTIONS]

Options:
  -h, --help          Show this help and exit
  --tools             Only install/upgrade tools and exit
  --verbose           Show detailed installer output
  --log <file>        Tee all installer output to <file>
  --dry-run           Print actions without executing changes

Installs ONLY subdomain enumeration tools:
  Go:   subfinder, github-subdomains, gitlab-subdomains, asnmap, puredns, dnsx,
        dsieve, gotator, analyticsrelationships, csprecon, tlsx, hakip2host,
        mapcidr, urlfinder, httpx, anew, unfurl, inscope, notify, katana, nuclei
  uv:   waymore, subwiz, dnsvalidator
  Repos: massdns (built), regulator (venv)
  Plus: resolvers, default + big subdomain wordlists
USAGE
    exit 0
}

function handle_install_arguments() {
    printf "\n%bsubenum installer script%b\n" "$bgreen" "$reset"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h | --help)
                show_additional_help
                ;;
            --tools)
                TOOLS_ONLY=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                DEBUG_STD=""
                DEBUG_ERROR=""
                shift
                ;;
            --log)
                LOGFILE="$2"
                shift 2 || true
                ;;
            --force-update)
                FORCE_UPDATE=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            *)
                printf "%bError: Invalid argument '%s'%b\n" "$bred" "$1" "$reset"
                echo "Use -h or --help for usage information."
                exit 1
                ;;
        esac
    done

    printf "%bThis may take some time. Grab a coffee!%b\n" "$yellow" "$reset"

    if [[ "$(id -u)" -eq 0 ]]; then
        SUDO=""
    else
        if ! sudo -n true 2>/dev/null; then
            printf "%bIt is strongly recommended to add your user to sudoers.%b\n" "$bred" "$reset"
            printf "%bThis will avoid prompts for sudo password during installation and scans.%b\n" "$bred" "$reset"
        fi
        SUDO="sudo"
    fi
}

handle_install_arguments "$@"
initial_setup
