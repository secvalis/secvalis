#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Secvalis — Audit Agent (version: see AGENT_VERSION below)
# Usage: ./secvalis.sh <API_KEY> [--dry-run] [--label "custom-name"] [--no-hostname] [--low-priority] [--api-url <url>] [--scan-lxc] [--no-scan-lxc]
#
# --no-hostname:  do NOT transmit the machine's real hostname (data minimisation,
#                 RODO art. 5(1)(c)). Requires --label so the machine still has an
#                 identity in the UI. The real hostname never leaves the host.
# --trivy-mirror=<url>: on-prem instance without internet. Trivy binary and its
#                 databases come from <url> (the instance's /trivy/ path), the binary
#                 is verified against the same pinned checksum, and Trivy never
#                 updates its databases itself. No request goes to GitHub or ghcr.io.
# --cacert=<path>: CA bundle for HTTPS to the instance and the mirror (CURL_CA_BUNDLE).
# secvalis.conf:  optional file next to this script, lines KEY=value with keys
#                 API_URL, TRIVY_MIRROR, CACERT. Parsed line by line, never sourced.
#                 With this file API_URL is mandatory (no fallback to the SaaS API).
#                 Flags override the file.
# --low-priority: run Trivy as a low-impact background scan — nice -n 19 (yields CPU
#                 to real workload), ionice -c 3 (idle I/O) and GOMAXPROCS capped to
#                 ~half the vCPUs, so the scan does not peg the CPU on small VMs.
#                 Recommended for production hosts / scheduled runs. The scan takes
#                 longer but stays out of the way of the client's services.
#
# The script collects information about installed packages and scans them with Trivy.
# In --dry-run mode it prints what would be sent, without actually uploading any data.
#
# Requirements: curl, jq
# Supported distros: Ubuntu 20/22, Debian 11/12, RHEL/CentOS 8/9, Alpine

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
readonly API_URL_DEFAULT="https://api.secvalis.eu"
# Agent version (K06 data provenance) — bump on significant script changes.
# The server compares it with the latest one (separate "agent lifecycle" task → notify/self-update).
readonly AGENT_VERSION="1.5.0"
readonly CURL_TIMEOUT=60           # seconds — timeout for short operations (metadata, info fetch)
readonly CURL_UPLOAD_TIMEOUT=600   # seconds — payload upload timeout (rootfs JSON can be 50MB+)
readonly TRIVY_TIMEOUT=1800        # seconds — Trivy scan timeout (30 min; Ubuntu Noble with apt cache = 10-15 min)
# Trivy installed by this script: a fixed release and the SHA-256 of its
# trivy_<version>_checksums.txt, verified with cosign before pinning.
# Never "latest": a release published with stolen credentials (v0.69.4,
# CVE-2026-33634) ships a matching checksums file. Bump procedure: doc.md.
readonly TRIVY_VERSION="0.76.1"
readonly TRIVY_CHECKSUMS_SHA256="885debc41b570179e81af560e5f393a66be29b9ff8c52915674f3eb2304c535d"

# ---------------------------------------------------------------------------
# Global variables (populated by parse_args)
# ---------------------------------------------------------------------------
API_KEY=""
DRY_RUN=false
MACHINE_LABEL=""
NO_HOSTNAME=false  # true = never transmit the real hostname (requires --label)
LOW_PRIORITY=false # true = throttle Trivy (nice/ionice/GOMAXPROCS) — low-impact scan
TRIVY_NICE=""      # command prefix for Trivy when --low-priority (set in main)
API_URL="${API_URL_DEFAULT}"
SCAN_LXC="false"  # false = disabled by default; --scan-lxc enables; auto = detect Proxmox
TRIVY_MIRROR=""   # on-prem: base URL serving the Trivy binary and DBs; empty = upstream (SaaS)
CACERT=""         # on-prem: CA bundle path for curl to the instance and the mirror
TRIVY_DB_CACHE="/var/cache/secvalis/trivy"  # Trivy --cache-dir in mirror mode

# ---------------------------------------------------------------------------
# Utils
# ---------------------------------------------------------------------------
log_info()  { echo "[INFO] $*" >&2; }
log_ok()    { echo "[OK]   $*" >&2; }
log_warn()  { echo "[WARN] $*" >&2; }
log_error() { echo "[ERROR] $*" >&2; }

# Safely create a temporary directory removed on exit
TMPDIR_WORK=""
cleanup() {
  if [ -n "${TMPDIR_WORK}" ] && [ -d "${TMPDIR_WORK}" ]; then
    rm -rf "${TMPDIR_WORK}"
  fi
}
trap cleanup EXIT INT TERM

setup_tmpdir() {
  TMPDIR_WORK=$(mktemp -d)
  # Make sure the directory is accessible only to the current user
  chmod 700 "${TMPDIR_WORK}"
}

# Hostname to transmit. Empty when --no-hostname (data minimisation); the jq
# payloads convert empty -> null so the server's `hostname ?? machineLabel`
# fallbacks keep working. The real hostname never leaves the host.
hostname_to_send() {
  if [ "${NO_HOSTNAME}" = true ]; then
    echo ""
  else
    hostname
  fi
}

# ---------------------------------------------------------------------------
# Config file (on-prem): KEY=value lines, read as data, never sourced
# ---------------------------------------------------------------------------
load_config() {
  local file="$1"
  [ -f "${file}" ] || return 0
  local key value has_api_url=false
  while IFS='=' read -r key value || [ -n "${key}" ]; do
    value="${value%$'\r'}"
    case "${key}" in
      ''|'#'*) ;;
      API_URL)      API_URL="${value}"; has_api_url=true ;;
      TRIVY_MIRROR) TRIVY_MIRROR="${value}" ;;
      CACERT)       CACERT="${value}" ;;
      *)            log_warn "Ignoring unknown key in ${file}" ;;
    esac
  done < "${file}"
  # A config file means a self-hosted instance: never fall back to the SaaS API.
  if [ "${has_api_url}" != true ]; then
    log_error "${file} has no API_URL line — refusing to fall back to ${API_URL_DEFAULT}"
    exit 1
  fi
  log_info "Config loaded: ${file}"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
parse_args() {
  for arg in "$@"; do
    case "${arg}" in
      --dry-run)
        DRY_RUN=true
        ;;
      --label=*)
        MACHINE_LABEL="${arg#*=}"
        ;;
      --no-hostname)
        NO_HOSTNAME=true
        ;;
      --low-priority)
        LOW_PRIORITY=true
        ;;
      --api-url=*)
        API_URL="${arg#*=}"
        ;;
      --trivy-mirror=*)
        TRIVY_MIRROR="${arg#*=}"
        ;;
      --cacert=*)
        CACERT="${arg#*=}"
        ;;
      --scan-lxc)
        SCAN_LXC=true
        ;;
      --no-scan-lxc)
        SCAN_LXC=false
        ;;
      --*)
        # Ignore unknown flags (without revealing their values in the log)
        ;;
      *)
        if [ -z "${API_KEY}" ]; then
          API_KEY="${arg}"
        fi
        ;;
    esac
  done

  # Require HTTPS for the API endpoint (does not apply to localhost for testing).
  # Checked after flags AND secvalis.conf, so a URL from the file is held to the same rule.
  if [[ "${API_URL}" != https://* ]] && [[ "${API_URL}" != http://localhost* ]] && [[ "${API_URL}" != http://127.0.0.1* ]]; then
    log_error "API URL must use HTTPS: ${API_URL}"
    exit 1
  fi
  if [ -n "${TRIVY_MIRROR}" ] && [[ "${TRIVY_MIRROR}" != https://* ]]; then
    log_error "Trivy mirror URL must use HTTPS: ${TRIVY_MIRROR}"
    exit 1
  fi
  if [ -n "${CACERT}" ] && [ ! -r "${CACERT}" ]; then
    log_error "CA bundle not readable: ${CACERT}"
    exit 1
  fi

  # Fallback: API key from the SYSDEVOPS_KEY env var when not passed as a positional argument.
  # For scheduled runs (cron/systemd) the key goes through a sourced file/EnvironmentFile,
  # not as an argument visible in `ps`/`systemctl show` — see: ./secvalis.sh --schedule-help
  if [ -z "${API_KEY}" ]; then
    API_KEY="${SYSDEVOPS_KEY:-}"
  fi

  # API key validation (required unless --dry-run)
  if [ -z "${API_KEY}" ] && [ "${DRY_RUN}" = false ]; then
    log_error "Missing API key"
    echo "Usage: $0 <API_KEY> [--dry-run] [--label=\"my-machine\"] [--api-url=<url>]" >&2
    exit 1
  fi

  # API key format validation — alphanumerics and dashes only (injection protection)
  if [ -n "${API_KEY}" ]; then
    if ! [[ "${API_KEY}" =~ ^[A-Za-z0-9_-]{8,256}$ ]]; then
      log_error "Invalid API key format (allowed: A-Z a-z 0-9 _ -, length 8-256)"
      exit 1
    fi
  fi
}

# ---------------------------------------------------------------------------
# Distro detection
# ---------------------------------------------------------------------------
detect_distro() {
  local id=""
  if [ -f /etc/os-release ]; then
    # shellcheck source=/dev/null
    id=$(. /etc/os-release && echo "${ID:-unknown}")
  elif command -v lsb_release &>/dev/null; then
    id=$(lsb_release -si 2>/dev/null | tr '[:upper:]' '[:lower:]')
  fi
  echo "${id:-unknown}"
}

detect_distro_version() {
  local version=""
  if [ -f /etc/os-release ]; then
    # shellcheck source=/dev/null
    version=$(. /etc/os-release && echo "${VERSION_ID:-unknown}")
  fi
  echo "${version:-unknown}"
}

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
check_dependencies() {
  local missing=()

  command -v curl &>/dev/null || missing+=("curl")
  command -v jq   &>/dev/null || missing+=("jq")

  if [ "${#missing[@]}" -gt 0 ]; then
    log_error "Missing dependencies: ${missing[*]}"
    log_error "Install: apt install curl jq  OR  yum install curl jq  OR  apk add curl jq"
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Root privilege check (needed for rootfs scan)
# ---------------------------------------------------------------------------
check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    log_warn "Script is not running as root."
    log_warn "The rootfs scan may be incomplete (no access to some files)."
    log_warn "Recommended: sudo $0 $*"
  fi
}

# ---------------------------------------------------------------------------
# Proxmox / LXC
# ---------------------------------------------------------------------------
is_proxmox() {
  command -v pct &>/dev/null && [ -d /etc/pve ]
}

should_scan_lxc() {
  case "${SCAN_LXC}" in
    true)  return 0 ;;
    false) return 1 ;;
    auto)  is_proxmox ;;
  esac
}

# Returns the list of LXC container rootfs directories to skip in the host scan.
# Handles dir storage (/var/lib/lxc) and ZFS (subvol-<ctid>-disk mounted in /proc/mounts).
build_lxc_skip_dirs() {
  local paths=""
  [ -d /var/lib/lxc ] && paths="/var/lib/lxc"
  if [ -f /proc/mounts ]; then
    while IFS= read -r mp; do
      [ -n "${mp}" ] || continue
      paths="${paths:+${paths},}${mp}"
    done < <(awk '/subvol-[0-9]+-disk/ {print $2}' /proc/mounts 2>/dev/null | head -100)
  fi
  echo "${paths}"
}

# ---------------------------------------------------------------------------
# Trivy download verification (supply-chain integrity)
# ---------------------------------------------------------------------------
# Verifies the downloaded Trivy artifact against the release checksums file,
# and that file against TRIVY_CHECKSUMS_SHA256 pinned in this script. The
# release's own checksums file alone proves nothing: whoever can publish a
# malicious release publishes its checksums too.
# Fail-closed: any missing file, missing entry or mismatch ABORTS the install,
# with no fallback to another release — an unverified scanner binary must never
# run as root on a client host (NIS2 art. 21(2)(e) supply chain, ISO 27001 A.8.19).

# Prints the SHA-256 of a file, or nothing when no hashing tool is available.
sha256_of() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum &>/dev/null; then
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

trivy_install_failed() {
  log_error "Refusing to install an unverified Trivy ${TRIVY_VERSION}."
  log_error "Install Trivy yourself (https://trivy.dev) and run this script again;"
  log_error "an existing trivy in PATH is used as is."
  exit 1
}

verify_trivy_checksum() {
  local artifact_file="$1"   # local path of the downloaded artifact
  local artifact_name="$2"   # file name as listed in the checksums file

  local sums_file="${TMPDIR_WORK}/trivy_checksums.txt"
  # $3: checksums URL on the on-prem mirror; the pin below is the same either way.
  local sums_url="${3:-https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt}"

  if ! curl --proto '=https' --tlsv1.2 -fsSL --max-time "${CURL_TIMEOUT}" \
      "${sums_url}" -o "${sums_file}"; then
    log_error "Could not download the Trivy checksums file (${sums_url})"
    trivy_install_failed
  fi

  local sums_actual
  sums_actual=$(sha256_of "${sums_file}") || trivy_install_failed
  if [ -z "${sums_actual}" ]; then
    log_error "sha256sum/shasum not found — cannot verify the Trivy download"
    trivy_install_failed
  fi
  if [ "${sums_actual}" != "${TRIVY_CHECKSUMS_SHA256}" ]; then
    log_error "Trivy checksums file does not match the sum pinned in this script"
    log_error "  pinned: ${TRIVY_CHECKSUMS_SHA256}"
    log_error "  actual: ${sums_actual}"
    trivy_install_failed
  fi

  local expected actual
  expected=$(awk -v f="${artifact_name}" '$2 == f {print $1}' "${sums_file}") || trivy_install_failed
  if [ -z "${expected}" ]; then
    log_error "No checksum entry for ${artifact_name} in the release checksums file"
    trivy_install_failed
  fi

  actual=$(sha256_of "${artifact_file}") || trivy_install_failed
  if [ "${actual}" != "${expected}" ]; then
    log_error "Trivy checksum MISMATCH for ${artifact_name}"
    log_error "  expected: ${expected}"
    log_error "  actual:   ${actual}"
    log_error "The download may be corrupted or tampered with."
    trivy_install_failed
  fi

  log_info "Trivy download verified (sha256 OK: ${artifact_name})"
}

# ---------------------------------------------------------------------------
# Trivy installation (if missing)
# ---------------------------------------------------------------------------
install_trivy() {
  if command -v trivy &>/dev/null; then
    log_info "Trivy $(trivy --version 2>/dev/null | head -1 | awk '{print $2}') already installed"
    return 0
  fi

  log_info "Trivy not found — installing..."

  local arch
  arch=$(uname -m)
  local trivy_arch
  case "${arch}" in
    x86_64)           trivy_arch="64bit" ;;
    aarch64|arm64)    trivy_arch="ARM64" ;;
    armv7l)           trivy_arch="ARM" ;;
    *)
      log_error "Unsupported architecture: ${arch}"
      exit 1
      ;;
  esac

  log_info "Installing Trivy ${TRIVY_VERSION} (arch: ${trivy_arch})..."

  if [ -n "${TRIVY_MIRROR}" ]; then
    install_trivy_from_mirror "${trivy_arch}"
    log_info "Trivy ${TRIVY_VERSION} installed"
    return 0
  fi

  local distro
  distro=$(detect_distro)

  case "${distro}" in
    ubuntu|debian)
      local deb_name="trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.deb"
      local deb_url="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${deb_name}"
      local deb_file="${TMPDIR_WORK}/trivy.deb"
      if ! curl --proto '=https' --tlsv1.2 -fsSL --max-time "${CURL_TIMEOUT}" \
          "${deb_url}" -o "${deb_file}"; then
        log_error "Could not download ${deb_url}"
        trivy_install_failed
      fi
      verify_trivy_checksum "${deb_file}" "${deb_name}"
      dpkg -i "${deb_file}"
      ;;
    centos|rhel|rocky|almalinux|fedora)
      local rpm_name="trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.rpm"
      local rpm_url="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${rpm_name}"
      local rpm_file="${TMPDIR_WORK}/trivy.rpm"
      if ! curl --proto '=https' --tlsv1.2 -fsSL --max-time "${CURL_TIMEOUT}" \
          "${rpm_url}" -o "${rpm_file}"; then
        log_error "Could not download ${rpm_url}"
        trivy_install_failed
      fi
      verify_trivy_checksum "${rpm_file}" "${rpm_name}"
      rpm -ivh "${rpm_file}"
      ;;
    alpine|*)
      # For Alpine and unidentified systems — extract the binary.
      # Download to a file first (no curl|tar streaming) so the archive can be
      # checksum-verified BEFORE anything from it is extracted.
      local tar_name="trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz"
      local tar_url="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${tar_name}"
      local tar_file="${TMPDIR_WORK}/trivy.tar.gz"
      if ! curl --proto '=https' --tlsv1.2 -fsSL --max-time "${CURL_TIMEOUT}" \
          "${tar_url}" -o "${tar_file}"; then
        log_error "Could not download ${tar_url}"
        trivy_install_failed
      fi
      verify_trivy_checksum "${tar_file}" "${tar_name}"
      tar xz -f "${tar_file}" -C "${TMPDIR_WORK}" trivy
      install -m 755 "${TMPDIR_WORK}/trivy" /usr/local/bin/trivy
      ;;
  esac

  log_info "Trivy ${TRIVY_VERSION} installed"
}

# ---------------------------------------------------------------------------
# On-prem Trivy mirror (no GitHub, no ghcr.io)
# ---------------------------------------------------------------------------
# Mirror layout (onprem/trivy-mirror/refresh.sh): trivy_<ver>_checksums.txt,
# trivy_<ver>_Linux-<arch>.tar.gz, db.tar.gz, javadb.tar.gz.
install_trivy_from_mirror() {
  local trivy_arch="$1"
  local base="${TRIVY_MIRROR%/}"
  local tar_name="trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz"
  local tar_file="${TMPDIR_WORK}/trivy.tar.gz"
  if ! curl --proto '=https' --tlsv1.2 -fsSL --max-time "${CURL_TIMEOUT}" \
      "${base}/${tar_name}" -o "${tar_file}"; then
    log_error "Could not download ${base}/${tar_name}"
    trivy_install_failed
  fi
  verify_trivy_checksum "${tar_file}" "${tar_name}" "${base}/trivy_${TRIVY_VERSION}_checksums.txt"
  tar xz -f "${tar_file}" -C "${TMPDIR_WORK}" trivy
  install -m 755 "${TMPDIR_WORK}/trivy" /usr/local/bin/trivy
}

# Downloads the vulnerability DBs into TRIVY_DB_CACHE (Trivy --cache-dir layout:
# db/, java-db/) and makes every trivy call use them without updating:
# TRIVY_CACHE_DIR, TRIVY_SKIP_DB_UPDATE, TRIVY_SKIP_JAVA_DB_UPDATE are the env
# forms of --cache-dir --skip-db-update --skip-java-db-update, so the rootfs,
# image and LXC scans all get them. -z: re-download only when the mirror copy is newer.
fetch_trivy_db_from_mirror() {
  local base="${TRIVY_MIRROR%/}" pair name sub tmp
  mkdir -p "${TRIVY_DB_CACHE}"
  for pair in "db.tar.gz:db" "javadb.tar.gz:java-db"; do
    name="${pair%%:*}"
    sub="${pair#*:}"
    tmp="${TMPDIR_WORK}/${name}"
    if ! curl --proto '=https' --tlsv1.2 -fsSL --max-time "${CURL_UPLOAD_TIMEOUT}" \
        -z "${TRIVY_DB_CACHE}/${name}" "${base}/${name}" -o "${tmp}"; then
      log_error "Could not download ${base}/${name} — no scan without a vulnerability DB"
      exit 1
    fi
    if [ -s "${tmp}" ]; then
      # Extract aside first: a broken archive must not wipe the cached DB.
      mkdir -p "${TMPDIR_WORK}/${sub}"
      tar xz -f "${tmp}" -C "${TMPDIR_WORK}/${sub}"
      rm -rf "${TRIVY_DB_CACHE:?}/${sub}"
      mv "${TMPDIR_WORK}/${sub}" "${TRIVY_DB_CACHE}/${sub}"
      mv "${tmp}" "${TRIVY_DB_CACHE}/${name}"
    fi
  done
  export TRIVY_CACHE_DIR="${TRIVY_DB_CACHE}"
  export TRIVY_SKIP_DB_UPDATE=true
  export TRIVY_SKIP_JAVA_DB_UPDATE=true
  # Java artifacts not found in the DB would otherwise be looked up on Maven Central.
  export TRIVY_OFFLINE_SCAN=true
  log_info "Trivy DBs from mirror: ${TRIVY_DB_CACHE}"
}

# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------
run_trivy_scan() {
  log_info "Starting system scan (rootfs)..."

  local skip_dirs="/var/lib/apt/lists,/var/lib/containerd,/var/lib/docker,/proc,/sys,/dev,/run"

  if is_proxmox; then
    local lxc_skip
    lxc_skip=$(build_lxc_skip_dirs)
    if [ -n "${lxc_skip}" ]; then
      skip_dirs="${skip_dirs},${lxc_skip}"
      log_info "Proxmox detected — skipping LXC directories: ${lxc_skip}"
    fi
  fi

  local scan_result
  local trivy_stderr="${TMPDIR_WORK}/trivy_stderr.txt"

  # SLA (K01): scan_status gates resolve on the server. An empty result from a Trivy
  # error/timeout MUST NOT mass-"resolve" the fleet — we mark it as `failed`.
  # run_trivy_scan runs in a subshell `$(...)`, so we write the status to a file
  # (a global variable from the subshell would not propagate to the parent process).
  local scan_status="ok"

  # `if ! cmd` zjada prawdziwy kod wyjscia ($? w ciele to zawsze 0 przez negacje),
  # a to wlasnie ten kod odroznia timeout od bledu trivy. Dlatego zapisujemy go wprost.
  local trivy_rc=0
  scan_result=$(timeout "${TRIVY_TIMEOUT}" ${TRIVY_NICE} trivy rootfs \
        --format json \
        --quiet \
        --no-progress \
        --timeout "${TRIVY_TIMEOUT}s" \
        --scanners vuln \
        --skip-dirs "${skip_dirs}" \
        / 2>"${trivy_stderr}") || trivy_rc=$?

  if [ "${trivy_rc}" -ne 0 ]; then
    if [ "${trivy_rc}" -eq 124 ]; then
      log_warn "The rootfs scan was killed by timeout after ${TRIVY_TIMEOUT}s"
    elif [ "${trivy_rc}" -eq 137 ]; then
      # 137 = 128+9 (SIGKILL). `timeout` sends SIGTERM (143), so the kill came from
      # outside — in practice the kernel OOM killer. Trivy writes nothing then,
      # which is why the log looked empty.
      log_warn "The rootfs scan was killed with SIGKILL (exit 137) — almost certainly the OOM killer"
      log_warn "Confirm with: dmesg -T | grep -i -E 'out of memory|killed process'"
      log_warn "Workaround: run the scan with a lower GOMEMLIMIT, e.g. GOMEMLIMIT=1GiB ${0}"
    else
      log_warn "The rootfs scan failed (trivy exit code ${trivy_rc})"
    fi
    if [ -s "${trivy_stderr}" ]; then
      log_warn "Trivy error details:"
      grep -E "FATAL|ERROR|WARN|timeout|deadline" "${trivy_stderr}" >&2 \
        || tail -5 "${trivy_stderr}" >&2
    else
      log_warn "Trivy wrote nothing to stderr"
    fi
    log_warn "Continuing with empty results — vulnerabilities may be incomplete"
    scan_result='{"Results":[]}'
    scan_status="failed"
  fi

  # Exit code 0 is NOT proof of a complete scan: Trivy can exit cleanly with an
  # empty result (interrupted DB download, OOM-killed worker). We check whether
  # Trivy reported any TARGET, not any vulnerability — a fully patched machine
  # legitimately has zero vulnerabilities, but it always has a scanned target.
  # No targets means "did not look", and the server would read the missing
  # findings as "everything was remediated".
  if [ "${scan_status}" = "ok" ]; then
    local target_count
    target_count=$(echo "${scan_result}" | jq '.Results // [] | length' 2>/dev/null || echo 0)
    if [ "${target_count}" -eq 0 ] 2>/dev/null; then
      log_warn "The rootfs scan reported no scanned targets — treating as failed, not as a clean machine"
      scan_status="failed"
    fi
  fi

  # Scan Docker images (if Docker is available and the daemon is running).
  # An unreachable daemon silently drops EVERY container vulnerability from the
  # payload; without the partial marker the server treats them as remediated.
  if command -v docker &>/dev/null && ! docker info &>/dev/null 2>&1; then
    log_warn "Docker is installed but the daemon is unreachable — container images were not scanned"
    [ "${scan_status}" = "ok" ] && scan_status="partial"
  fi

  if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    log_info "Docker detected — scanning running containers..."

    # Skanujemy po IDENTYFIKATORZE obrazu, nie po nazwie. Nazwa z `docker ps` bywa
    # nierozwiazywalna lokalnie (Swarm przypina digest, tag zostaje przepiety przy
    # kolejnym deployu, czyszczenie usuwa etykiete), a wtedy trivy przechodzi przez
    # dockera, containerd i podmana az do rejestru i konczy na DENIED, bo agent
    # celowo nie ma poswiadczen. Identyfikator demon zna zawsze, skoro kontener
    # z niego chodzi. Nazwa sluzy juz tylko do opisania wyniku.
    local images
    # `docker ps` NIE zna pola {{.ImageID}} (to pole `docker images`) i konczy
    # bledem szablonu, a `2>/dev/null` polykalo go w calosci: lista wychodzila
    # pusta i agent nie skanowal ZADNEGO obrazu, meldujac przy tym sukces.
    # Identyfikator obrazu bierzemy z `docker inspect`: .Image to sha256 obrazu,
    # z ktorego kontener chodzi, .Config.Image to nazwa podana przy uruchomieniu.
    # Blad `docker ps` (uprawnienia, demon) rozpoznajemy po kodzie wyjscia, nie po
    # pustej liscie: zero uruchomionych kontenerow to normalny stan (runner CI ma
    # kontenery tylko w trakcie jobow), a regula "pusta lista = partial" blokowala
    # takiej maszynie zamykanie podatnosci na zawsze (2026-10-29).
    local container_ids ps_rc=0
    container_ids=$(docker ps -q 2>/dev/null) || ps_rc=$?
    if [ "${ps_rc}" -ne 0 ]; then
      log_warn "docker ps failed (exit ${ps_rc}) — container images were not scanned"
      [ "${scan_status}" = "ok" ] && scan_status="partial"
    fi
    images=$(printf '%s\n' "${container_ids}" | grep . \
      | xargs -r docker inspect --format '{{.Image}} {{.Config.Image}}' 2>/dev/null \
      | sort -u || true)

    local image_count
    image_count=$(printf '%s' "${images}" | grep -c . || true)
    log_info "Running containers to scan: ${image_count}"
    if [ -z "${container_ids}" ] && [ "${ps_rc}" -eq 0 ]; then
      log_info "No running containers — nothing to scan in Docker"
    elif [ "${image_count}" -eq 0 ]; then
      # Kontenery sa, a inspect nie zwrocil zadnego obrazu: tego nie udajemy.
      log_warn "docker inspect returned no images for running containers — the payload does not cover any images"
      [ "${scan_status}" = "ok" ] && scan_status="partial"
    fi

    local image_id image image_line
    local images_ok=0
    while IFS= read -r image_line; do
      [ -z "${image_line}" ] && continue
      image_id="${image_line%% *}"
      image="${image_line#* }"
      log_info "  Scanning image: ${image}"

      local image_result
      local image_stderr="${TMPDIR_WORK}/trivy_image_stderr.txt"
      if ! image_result=$(timeout "${TRIVY_TIMEOUT}" ${TRIVY_NICE} trivy image \
            --format json \
            --quiet \
            --no-progress \
            --timeout "${TRIVY_TIMEOUT}s" \
            --scanners vuln \
            --image-src docker \
            "${image_id}" 2>"${image_stderr}"); then
        log_warn "  Error scanning image: ${image} — skipping"
        # The reason MUST be visible. Swallowing stderr here made a real coverage
        # gap undiagnosable: three of our own registry images were silently absent
        # from every payload, and the log said only "skipping".
        if [ -s "${image_stderr}" ]; then
          grep -E "FATAL|ERROR|unauthorized|denied|not found|timeout|deadline|no such" \
            "${image_stderr}" | head -3 >&2 || head -3 "${image_stderr}" >&2
        fi
        # Ostatnia szansa: sprobuj po nazwie, tak jak robily to wersje < 1.3.2.
        # Kosztuje jedno dodatkowe wywolanie tylko na sciezce bledu, a chroni przed
        # sytuacja, w ktorej dana wersja trivy nie przyjmuje identyfikatora obrazu.
        if image_result=$(timeout "${TRIVY_TIMEOUT}" ${TRIVY_NICE} trivy image \
              --format json --quiet --no-progress \
              --timeout "${TRIVY_TIMEOUT}s" --scanners vuln \
              "${image}" 2>/dev/null); then
          log_info "  Scanned by name after the image-id attempt failed: ${image}"
          images_ok=$(( images_ok + 1 ))
        else
          image_result='{"Results":[]}'
          # Part of the scan failed (rootfs OK, image not) → partial (do not degrade failed).
          [ "${scan_status}" = "ok" ] && scan_status="partial"
        fi
      else
        images_ok=$(( images_ok + 1 ))
      fi

      # Safely merge results via jq (no string interpolation)
      # Every Result from a Docker image is tagged with the _sourceImage field,
      # so the TS parser always knows it is Docker, even if Target has no ":".
      # _sourceImageId (sha256 from docker inspect .Image) tells apart two images
      # on the same tag (e.g. two builds of app:latest); the server validates it.
      scan_result=$(printf '%s\n%s' "${scan_result}" "${image_result}" \
        | jq -s --arg img "${image}" --arg imgid "${image_id}" '
            .[0] as $base |
            .[1] as $extra |
            ($extra.Results // [] | map(. + {_sourceImage: $img, _sourceImageId: $imgid})) as $tagged |
            $base | .Results = (($base.Results // []) + $tagged)
          ')
    done <<< "${images}"
    # Rootfs padl, ale obrazy przeskanowaly sie normalnie: payload NIE jest pusty,
    # tylko niepelny. Trzymanie statusu `failed` kazalo serwerowi wyrzucic caly
    # wynik razem z realnymi znaleziskami z dziewieciu kontenerow. `partial` to
    # dokladnie ten przypadek: dane sa prawdziwe, present-set niekompletny,
    # wiec serwer zapisuje snapshot i nie zamyka niczego.
    if [ "${scan_status}" = "failed" ] && [ "${images_ok}" -gt 0 ]; then
      log_warn "The rootfs scan failed, but ${images_ok} container image(s) scanned — reporting the scan as partial, not failed"
      scan_status="partial"
    fi
  fi

  # Pass scan_status to the parent process via a file (subshell `$(...)`).
  printf '%s' "${scan_status}" > "${TMPDIR_WORK}/rootfs_scan_status"
  echo "${scan_result}"
}

# ---------------------------------------------------------------------------
# Print dry-run summary
# ---------------------------------------------------------------------------
do_dry_run() {
  local distro="$1"
  local distro_version="$2"

  echo ""
  echo "=== DRY RUN — data that would be sent ==="
  echo "API URL:       ${API_URL}/api/v1/audit"
  echo "Machine label: ${MACHINE_LABEL}"
  if [ "${NO_HOSTNAME}" = true ]; then
    echo "Hostname:      (not sent — --no-hostname; real hostname: $(hostname))"
  else
    echo "Hostname:      $(hostname)"
  fi
  echo "Distro:        ${distro} ${distro_version}"
  echo ""

  local scan_result
  log_info "Running scan (dry-run)..."
  scan_result=$(run_trivy_scan)

  local findings_count
  findings_count=$(echo "${scan_result}" \
    | jq '[.Results[]?.Vulnerabilities // [] | length] | add // 0' 2>/dev/null \
    || echo "unknown")

  echo "Vulnerabilities found: ${findings_count}"
  echo ""
  echo "Payload JSON (preview — without the API key):"

  # Use --arg for all text values (safe against injection)
  echo "${scan_result}" | jq \
    --arg ml  "${MACHINE_LABEL}" \
    --arg hn  "$(hostname_to_send)" \
    --arg d   "${distro}" \
    --arg dv  "${distro_version}" \
    '{
      machine_label:   $ml,
      hostname:        ($hn | if . == "" then null else . end),
      distro:          $d,
      distro_version:  $dv,
      findings_count:  ([.Results[]?.Vulnerabilities // [] | length] | add // 0)
    }' 2>/dev/null

  echo ""
  echo "=== No data sent (--dry-run) ==="
}

# ---------------------------------------------------------------------------
# Send results to the API
# ---------------------------------------------------------------------------
send_results() {
  local scan_result="$1"
  local distro="$2"
  local distro_version="$3"
  # SLA (K01): scan status — `ok|partial|failed`. Defaults to `ok` for backward
  # compatibility (calls without a 4th argument). The server resolves only on `ok`.
  local scan_status="${4:-ok}"
  # R1: system_state describes THIS host. An LXC container scanned from the
  # Proxmox host passes "none": the host's kernel and reboot flag are not the
  # container's, so the server gets nulls and keeps everything in SLA.
  local system_state_mode="${5:-host}"

  # Write scan results to a file — avoids the ARG_MAX limit for large JSON
  local scan_file="${TMPDIR_WORK}/scan_result.json"
  printf '%s' "${scan_result}" > "${scan_file}"

  # Trim the trivy JSON to vulnerabilities only (removes file metadata, layers, references)
  # Keeps the fields required by trivy-parser.ts: Class, Type, Target, _sourceImage, _sourceImageId
  # Reduces payload size from 10-50MB to a few hundred KB
  local slim_file="${TMPDIR_WORK}/scan_slim.json"
  # K06: keep Metadata.DB.UpdatedAt (Trivy DB version) — the server extracts it as provenance.
  jq '{ Metadata: (if .Metadata.DB then { DB: { UpdatedAt: .Metadata.DB.UpdatedAt } } else null end), Results: [.Results[]? | select(.Vulnerabilities != null and (.Vulnerabilities | length) > 0) | {
    Target:        .Target,
    Class:         .Class,
    Type:          .Type,
    _sourceImage:  ._sourceImage,
    _sourceImageId: ._sourceImageId,
    Vulnerabilities: [.Vulnerabilities[] | {
      VulnerabilityID:  .VulnerabilityID,
      PkgName:          .PkgName,
      InstalledVersion: .InstalledVersion,
      FixedVersion:     .FixedVersion,
      Severity:         .Severity,
      Status:           .Status,
      Title:            .Title,
      Description:      (.Description // "" | .[0:300]),
      PrimaryURL:       (.PrimaryURL // "")
    }]
  }] }' "${scan_file}" > "${slim_file}"


  # K06 provenance: host time zone (IANA, fallback to abbreviation/UTC).
  local scan_tz
  scan_tz="$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || date +%Z 2>/dev/null || echo UTC)"

  # R1/R11: system_state, running kernel and pending-reboot signal. Failures in
  # rpm/uname must never abort the scan: every command substitution below has an
  # explicit `|| fallback`, because under set -euo pipefail a failing
  # assignment ends the script before the payload is sent.
  local running_kernel
  running_kernel="$(uname -r 2>/dev/null || echo "")"

  local reboot_required_json="null"
  local distro_for_reboot
  if [ "${system_state_mode}" = "none" ]; then
    running_kernel=""
    distro_for_reboot=""
  else
    distro_for_reboot="${distro}"
  fi
  case "${distro_for_reboot}" in
    ubuntu|debian)
      if [ -f /var/run/reboot-required ]; then
        reboot_required_json="true"
      else
        reboot_required_json="false"
      fi
      ;;
    centos|rhel|rocky|almalinux|fedora)
      if command -v rpm >/dev/null 2>&1; then
        local latest_installed_kernel
        # `|| latest_installed_kernel=""`: rpm exits non-zero when package
        # `kernel` is absent (containers, kernel-core only images) and pipefail
        # would abort the scan. It then prints "package kernel is not installed"
        # on stdout, so `sed -n .../p` keeps only real `kernel-*` lines: empty
        # result = reboot_required stays null.
        latest_installed_kernel="$(rpm -q --last kernel 2>/dev/null | head -n1 | awk '{print $1}' | sed -n 's/^kernel-//p')" || latest_installed_kernel=""
        if [ -n "${latest_installed_kernel}" ]; then
          if [ "${latest_installed_kernel}" != "${running_kernel}" ]; then
            reboot_required_json="true"
          else
            reboot_required_json="false"
          fi
        fi
      fi
      ;;
  esac

  # Build the payload via jq --slurpfile (not --argjson — safe for large data)
  local payload_file="${TMPDIR_WORK}/payload.json"
  jq -n \
    --arg  machine_label   "${MACHINE_LABEL}" \
    --arg  hostname        "$(hostname_to_send)" \
    --arg  distro          "${distro}" \
    --arg  distro_version  "${distro_version}" \
    --arg  agent_version   "${AGENT_VERSION}" \
    --arg  scan_timezone   "${scan_tz}" \
    --arg  scan_status     "${scan_status}" \
    --arg  running_kernel  "${running_kernel}" \
    --argjson reboot_required "${reboot_required_json}" \
    --slurpfile trivy_results "${slim_file}" \
    '{
      machine_label:  $machine_label,
      hostname:       ($hostname | if . == "" then null else . end),
      distro:         $distro,
      distro_version: $distro_version,
      agent_version:  $agent_version,
      scan_timezone:  $scan_timezone,
      scan_status:    $scan_status,
      system_state: {
        running_kernel:   ($running_kernel | if . == "" then null else . end),
        reboot_required:  $reboot_required
      },
      trivy_results:  $trivy_results[0]
    }' > "${payload_file}"

  local payload_size_kb
  payload_size_kb=$(( $(wc -c < "${payload_file}") / 1024 ))
  log_info "Payload size: ${payload_size_kb} KB"

  # Kompresja payloadu. Skan maszyny z kilkunastoma obrazami to kilkanascie MB
  # czystego JSON-a, w ktorym te same nazwy pol powtarzaja sie kilkanascie tysiecy
  # razy, wiec gzip scina to kilkunastokrotnie. Serwer rozpoznaje naglowek
  # Content-Encoding; brak gzipa na maszynie = wysylka nieskompresowana jak dotad.
  local send_file="${payload_file}"
  local content_encoding=""
  if command -v gzip >/dev/null 2>&1 && gzip -c "${payload_file}" > "${payload_file}.gz" 2>/dev/null; then
    local gz_kb=$(( $(wc -c < "${payload_file}.gz") / 1024 ))
    log_info "Compressed payload: ${gz_kb} KB (from ${payload_size_kb} KB)"
    send_file="${payload_file}.gz"
    content_encoding="Content-Encoding: gzip"
  else
    log_warn "gzip unavailable — sending the payload uncompressed"
  fi

  # Ostrzezenie o rozmiarze idzie PO kompresji i mierzy plik, ktory FAKTYCZNIE
  # leci na serwer. Do 2026-09-17 sprawdzenie stalo przed kompresja i porownywalo
  # surowy JSON z progiem 3,5 MB, wiec zapalalo sie przy kazdym udanym skanie
  # maszyny z kontenerami (zmierzone: 28 MB surowego JSON-a, 4,5 MB po gzipie,
  # HTTP 200). Ostrzezenie, ktore krzyczy przy normalnej pracy, uczy ignorowac
  # jedyny kanal majacy mowic, ze cos jest nie tak.
  #
  # Prog wynika z limitu ciala zadania w Traefiku dla API agenta (32 MB, patrz
  # docker-stack.yml). Ostrzegamy przy 75 procent, czyli 24 MB: jest wtedy jeszcze
  # margines na reakcje, a nie komunikat po fakcie. Gdy limit po stronie serwera
  # sie zmieni, zmien tez te liczbe — inaczej ostrzezenie znow bedzie mierzyc
  # wzgledem nieistniejacej granicy.
  local sent_size_kb
  sent_size_kb=$(( $(wc -c < "${send_file}") / 1024 ))
  if [ "${sent_size_kb}" -gt 24576 ]; then
    log_warn "Upload is ${sent_size_kb} KB, above 75% of the 32 MB server limit — risk of HTTP 413"
  fi

  local response_file="${TMPDIR_WORK}/api_response.json"

  # Note: no -f — curl does not fail on HTTP 4xx, so %{http_code} always contains
  # only the HTTP code (without an appended "000" from || echo "000")
  local http_code
  http_code=$(curl \
    --proto '=https' \
    --tlsv1.2 \
    -sSL \
    --connect-timeout "${CURL_TIMEOUT}" \
    --max-time "${CURL_UPLOAD_TIMEOUT}" \
    -w "%{http_code}" \
    -o "${response_file}" \
    -X POST "${API_URL}/api/v1/audit" \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    ${content_encoding:+-H "${content_encoding}"} \
    --data-binary "@${send_file}" \
    2>/dev/null || echo "000")

  # Interpret HTTP codes
  if [ "${http_code}" -ge 200 ] && [ "${http_code}" -lt 300 ] 2>/dev/null; then
    log_ok "Results uploaded successfully (HTTP ${http_code})"
    local machine_id findings latest_version deduplicated
    machine_id=$(jq -r '.machine_id // "unknown"' "${response_file}" 2>/dev/null || echo "unknown")
    findings=$(jq -r '.findings_count // "unknown"' "${response_file}" 2>/dev/null || echo "unknown")
    # A deduplicated scan is stored as a ping: the server returns findings_count 0
    # because NOTHING CHANGED, not because nothing was found. Printing the plain
    # zero made a healthy scan look like a broken one.
    deduplicated=$(jq -r '.deduplicated // false' "${response_file}" 2>/dev/null || echo "false")
    if [ "${deduplicated}" = "true" ]; then
      log_ok "Machine ID: ${machine_id} | No change since the previous scan (findings identical)"
    else
      log_ok "Machine ID: ${machine_id} | Vulnerabilities found: ${findings}"
    fi

    # R5: new agent version notification (no self-update — updating = re-run the installer)
    latest_version=$(jq -r '.latest_agent_version // empty' "${response_file}" 2>/dev/null || echo "")
    if [ -n "${latest_version}" ] && [ "${latest_version}" != "${AGENT_VERSION}" ]; then
      log_warn "A new agent version v${latest_version} is available (you have ${AGENT_VERSION}) — update by re-running the installer"
    fi
  elif [ "${http_code}" -eq 401 ] 2>/dev/null; then
    log_error "Invalid API key (401 Unauthorized)"
    exit 1
  elif [ "${http_code}" -eq 403 ] 2>/dev/null; then
    log_error "Not authorized to run the scan (403 Forbidden)"
    exit 1
  elif [ "${http_code}" -eq 413 ] 2>/dev/null; then
    log_error "Payload too large (413 Request Entity Too Large) — sent: ${sent_size_kb} KB (raw JSON: ${payload_size_kb} KB)"
    log_error "The server rejected the oversized JSON. Please report this to the platform administrator."
    exit 1
  elif [ "${http_code}" -eq 429 ] 2>/dev/null; then
    log_error "Too fast — wait 5 minutes between scans (429 Rate Limited)"
    exit 1
  elif [ "${http_code}" -eq 000 ] 2>/dev/null; then
    log_error "No connection to the API (${API_URL})"
    exit 1
  else
    log_error "Upload error (HTTP ${http_code})"
    # Print the response body without risking secret leakage
    if [ -f "${response_file}" ]; then
      jq -r '.error // .message // "No details"' "${response_file}" 2>/dev/null || true
    fi
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Scanning LXC containers (Proxmox) as separate machines
# ---------------------------------------------------------------------------
scan_and_send_lxc() {
  local distro="$1"
  local distro_version="$2"

  if ! command -v pct &>/dev/null; then
    log_warn "pct not found — cannot list LXC containers"
    return
  fi

  log_info "Looking for running LXC containers..."

  local found=0
  while IFS= read -r line; do
    [ -z "${line}" ] && continue

    local ctid name rootfs
    ctid=$(echo "${line}" | awk '{print $1}')
    name=$(echo "${line}" | awk '{print $NF}')
    [ -z "${ctid}" ] && continue

    # Dir storage
    rootfs="/var/lib/lxc/${ctid}/rootfs"
    if [ ! -d "${rootfs}" ]; then
      # ZFS: search by ctid in /proc/mounts
      rootfs=$(awk -v ctid="${ctid}" \
        '$1 ~ "subvol-"ctid"-disk" || $1 ~ "subvol-"ctid"_" {print $2; exit}' \
        /proc/mounts 2>/dev/null || true)
    fi

    if [ -z "${rootfs}" ] || [ ! -d "${rootfs}" ]; then
      log_warn "  LXC ${ctid} (${name}): rootfs not found — skipping"
      continue
    fi

    found=$((found + 1))
    log_info "  Scanning LXC ${ctid} (${name}) -> ${rootfs}"

    local lxc_scan
    local lxc_status="ok"
    local lxc_stderr="${TMPDIR_WORK}/trivy_lxc_${ctid}_stderr.txt"
    if ! lxc_scan=$(timeout "${TRIVY_TIMEOUT}" ${TRIVY_NICE} trivy rootfs \
          --format json \
          --quiet \
          --no-progress \
          --timeout "${TRIVY_TIMEOUT}s" \
          --scanners vuln \
          "${rootfs}" 2>"${lxc_stderr}"); then
      log_warn "  Error scanning LXC ${ctid} — skipping"
      lxc_scan='{"Results":[]}'
      # SLA (K01): LXC scan error = failed (an empty result must not resolve).
      lxc_status="failed"
    fi

    # Scan as a separate machine — replace MACHINE_LABEL with the container name
    local orig_label="${MACHINE_LABEL}"
    MACHINE_LABEL="${name:-lxc-${ctid}}"

    if [ "${DRY_RUN}" = true ]; then
      local count
      count=$(echo "${lxc_scan}" | jq '[.Results[]?.Vulnerabilities // [] | length] | add // 0' 2>/dev/null || echo "?")
      echo ""
      echo "=== DRY RUN — LXC ${ctid} (MACHINE_LABEL: ${MACHINE_LABEL}) ==="
      echo "Rootfs:          ${rootfs}"
      echo "Vulnerabilities: ${count}"
    else
      send_results "${lxc_scan}" "${distro}" "${distro_version}" "${lxc_status}" "none"
    fi

    MACHINE_LABEL="${orig_label}"

  done < <(pct list 2>/dev/null | awk 'NR>1 && $2=="running" {print}')

  if [ "${found}" -eq 0 ]; then
    log_info "No accessible LXC container rootfs (dir storage or ZFS) — skipping"
  fi
}

# ---------------------------------------------------------------------------
# Help: schedule snippets (cron / systemd) — prints, does NOT install
# ---------------------------------------------------------------------------
print_schedule_help() {
  local script_path
  script_path="$(realpath "$0" 2>/dev/null || echo "$0")"

  cat <<EOF
=== Recurring scan schedule (Secvalis Audit Agent) ===

The script scans ONCE. You configure recurrence on your side.
Keep the API key in a file — do NOT paste it into the crontab/unit
(leaks via 'ps aux' / 'systemctl show').

--- 1. Store the API key in a file (once) ---
sudo install -d -m700 /etc/secvalis
printf 'SYSDEVOPS_KEY=%s\n' 'YOUR_API_KEY' | sudo tee /etc/secvalis/key >/dev/null
sudo chmod 600 /etc/secvalis/key

--- 2a. cron variant (daily) ---
# Edit the root crontab:  sudo crontab -e
# Pick YOUR OWN hour/minute (spread the fleet over time — avoid 'everyone at 02:00'):
0 2 * * * set -a; . /etc/secvalis/key; ${script_path} 2>&1 | logger -t secvalis

--- 2b. systemd timer variant (daily, with random delay) ---
# /etc/systemd/system/secvalis.service
[Unit]
Description=Secvalis Audit Agent — audit scan
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/secvalis/key
ExecStart=${script_path}

# /etc/systemd/system/secvalis.timer
[Unit]
Description=Secvalis Audit Agent — daily schedule

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target

# Activation:
sudo systemctl daemon-reload
sudo systemctl enable --now secvalis.timer
EOF

  case "${script_path}" in
    /tmp/*|/var/tmp/*|/dev/shm/*)
      cat <<EOF

[WARNING] The script is in a temporary directory (${script_path}).
          Temporary directories are periodically cleaned — the schedule will stop working.
          Move the script to a permanent location and fix the path above:
            sudo install -m755 "${script_path}" /opt/secvalis.sh
EOF
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  # --schedule-help: print schedule snippets and exit.
  # BEFORE parse_args/setup — help needs no API key, root, or Trivy.
  for arg in "$@"; do
    if [ "${arg}" = "--schedule-help" ]; then
      print_schedule_help
      exit 0
    fi
  done

  # PATH normalization: cron runs jobs with a stripped PATH (/usr/bin:/bin),
  # and Trivy for Alpine/unknown distros lands in /usr/local/bin — without this
  # a scheduled run silently fails 'trivy not found' despite a working interactive test.
  export PATH="/usr/local/bin:${PATH}"

  load_config "$(cd "$(dirname "$0")" && pwd)/secvalis.conf"
  parse_args "$@"
  setup_tmpdir
  # curl honours CURL_CA_BUNDLE for every request: instance, mirror, upload.
  [ -n "${CACERT}" ] && export CURL_CA_BUNDLE="${CACERT}"

  # Mitigation: remove the API-key invocation from bash history (when passed as $1).
  # Incomplete (a subshell does not modify the parent history) — kept as good practice.
  history -d "$(history 1)" 2>/dev/null || true

  check_dependencies
  check_root "$@"

  # Trivy to program w Go i bez limitu potrafi rosnac az zabije go kernel
  # (kod wyjscia 137, zaobserwowane na hoscie dockerowym). GOMEMLIMIT jest
  # miekkim progiem: po jego przekroczeniu runtime zbiera smieci agresywnie
  # zamiast alokowac dalej, wiec skan trwa dluzej zamiast ginac. Pokretlo
  # zostaje: jawnie ustawiony GOMEMLIMIT wygrywa z wyliczonym.
  if [ -z "${GOMEMLIMIT:-}" ]; then
    # Podstawa to MemAvailable, nie MemTotal. Na hoscie dockerowym kontenery
    # trzymaja wiekszosc RAM-u, wiec 60% MemTotal to limit wyzszy niz cala wolna
    # pamiec i GC nigdy by go nie dotknal. Realny przypadek: OOM killer ubil
    # trivy przy 834 MB RSS na maszynie, gdzie MemTotal sugerowal kilka GB.
    local mem_kb mem_basis
    mem_kb=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
    mem_basis="MemAvailable"
    if [ "${mem_kb}" -le 0 ] 2>/dev/null; then
      mem_kb=$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
      mem_basis="MemTotal"
    fi
    if [ "${mem_kb}" -gt 0 ] 2>/dev/null; then
      export GOMEMLIMIT="$(( mem_kb * 60 / 100 ))KiB"
      log_info "Memory guard: GOMEMLIMIT=${GOMEMLIMIT} (60% of ${mem_basis}) — override by exporting GOMEMLIMIT"
      # Ponizej tego progu skan rootfs i tak zwykle nie domknie sie w pamieci,
      # a milczace ponawianie OOM-u kosztuje godziny diagnozy. Lepiej powiedziec
      # wprost, ze maszyna potrzebuje pamieci albo okna z mniejszym obciazeniem.
      if [ "$(( mem_kb / 1024 ))" -lt 1024 ] 2>/dev/null; then
        log_warn "Only $(( mem_kb / 1024 )) MB of ${mem_basis} — the rootfs scan may still be OOM-killed"
        log_warn "Free some memory or run the scan when the machine is less loaded"
      fi
    fi
  fi

  local distro distro_version
  distro=$(detect_distro)
  distro_version=$(detect_distro_version)

  # --no-hostname needs an explicit --label: otherwise the label defaults to the
  # hostname below and leaks exactly what --no-hostname is meant to suppress.
  if [ "${NO_HOSTNAME}" = true ] && [ -z "${MACHINE_LABEL}" ]; then
    log_error "--no-hostname requires --label=\"my-machine\" (otherwise the label would leak the hostname)"
    exit 1
  fi

  # Default label = short hostname (without FQDN)
  if [ -z "${MACHINE_LABEL}" ]; then
    MACHINE_LABEL=$(hostname -s 2>/dev/null || hostname)
  fi

  # --low-priority: build a throttle prefix for Trivy so the scan stays out of the
  # way of the client's workload. `nice -n 19` lowers CPU priority (no privilege
  # needed — we only go lower), `ionice -c 3` sets idle I/O, and GOMAXPROCS caps
  # Trivy's Go parallelism so it does not peg all cores even on an idle small VM.
  if [ "${LOW_PRIORITY}" = true ]; then
    TRIVY_NICE="nice -n 19"
    if command -v ionice >/dev/null 2>&1; then
      TRIVY_NICE="${TRIVY_NICE} ionice -c 3"
    fi
    local ncpu gomaxprocs
    ncpu=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
    gomaxprocs=$(( ncpu / 2 ))
    [ "${gomaxprocs}" -lt 1 ] && gomaxprocs=1
    export GOMAXPROCS="${gomaxprocs}"
    log_info "Low-priority scan: ${TRIVY_NICE}, GOMAXPROCS=${gomaxprocs} (of ${ncpu} vCPU)"
  fi

  install_trivy
  [ -n "${TRIVY_MIRROR}" ] && fetch_trivy_db_from_mirror

  if [ "${DRY_RUN}" = true ]; then
    do_dry_run "${distro}" "${distro_version}"
    should_scan_lxc && scan_and_send_lxc "${distro}" "${distro_version}"
    exit 0
  fi

  local scan_result
  scan_result=$(run_trivy_scan)

  # SLA (K01): read the status written by run_trivy_scan (subshell `$(...)`).
  local scan_status="ok"
  [ -f "${TMPDIR_WORK}/rootfs_scan_status" ] && scan_status="$(cat "${TMPDIR_WORK}/rootfs_scan_status")"

  send_results "${scan_result}" "${distro}" "${distro_version}" "${scan_status}"

  # Niepelny skan konczyl sie do tej pory samymi liniami [OK] i kodem 0, wiec
  # zepsuty przebieg wygladal dokladnie jak zdrowy: "Vulnerabilities found: 0".
  # Serwer i tak nie zamyka wtedy podatnosci (scan_status), ale czlowiek i cron
  # musza to zobaczyc.
  if [ "${scan_status}" != "ok" ]; then
    log_warn "Scan status: ${scan_status} — the payload is INCOMPLETE, the zero above does not mean the machine is clean"
    log_warn "The server will not close any vulnerabilities based on this run"
  fi

  should_scan_lxc && scan_and_send_lxc "${distro}" "${distro_version}"

  # Auto-hint about scheduling — only interactively (TTY); cron/IaC does not clutter logs.
  if [ -t 1 ]; then
    log_info "Recurring schedule? cron/systemd snippets: $0 --schedule-help"
  fi

  [ "${scan_status}" = "ok" ] || exit 2
}

main "$@"
