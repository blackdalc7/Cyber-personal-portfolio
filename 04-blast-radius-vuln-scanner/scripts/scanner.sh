#!/usr/bin/env bash
#
# scanner.sh - Nmap front-end for the Blast-Radius Vulnerability Scanner.
#
# Discovers open ports and service/version banners on an authorised target, writes
# Nmap XML, then hands off to `python -m vuln_scanner analyse` for NVD/EPSS/KEV
# enrichment, blast-radius ranking, SARIF and the graph image.
#
# Authorisation is mandatory: scanning hosts you don't own or lack written permission
# to test is illegal in most jurisdictions. This script refuses to run without an
# explicit acknowledgement.
#
# Usage:
#   ./scripts/scanner.sh -t 192.168.56.0/24 -i examples/inventory.yml
#   ./scripts/scanner.sh -t scanme.nmap.org -p 1-1000 --skip-cve
#   SCAN_AUTHORIZED=yes ./scripts/scanner.sh -t 10.0.0.5 -o results/
#
set -Eeuo pipefail

# ----------------------------------------------------------------------------- defaults
TARGET=""
PORTS="1-1024"
OUTDIR="results"
EXTRA_NMAP=""
RUN_CVE=1
TIMING="-T4"
INVENTORY=""
FEEDS_DIR=""
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="$(cd "${SELF}/.." && pwd)"

log()  { printf '\033[0;36m[*]\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[0;32m[+]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[0;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[0;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    cat >&2 <<EOF
Blast-Radius Vulnerability Scanner - Nmap front-end

Usage: $0 -t <target> [options]
  -t, --target   <host|CIDR>   Target to scan (required)
  -p, --ports    <spec>        Port spec (default: ${PORTS}; e.g. 1-65535, 22,80,443)
  -o, --output   <dir>         Output directory (default: ${OUTDIR})
      --timing   <T0-T5>       Nmap timing template (default: ${TIMING})
      --extra    "<args>"      Extra args passed through to nmap
  -i, --inventory <file>       Asset inventory / network policy YAML for blast-radius analysis
      --feeds-dir <dir>         Use NVD/EPSS/KEV snapshots instead of the live APIs (air-gapped)
      --skip-cve                Stop after the Nmap scan; don't run the analysis
  -h, --help                   Show this help

Authorisation: set SCAN_AUTHORIZED=yes (env) or answer the prompt to confirm you are
permitted to scan the target.
EOF
    exit "${1:-0}"
}

# ----------------------------------------------------------------------------- arg parse
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--target)  TARGET="${2:?missing target}"; shift 2 ;;
        -p|--ports)   PORTS="${2:?missing ports}"; shift 2 ;;
        -o|--output)  OUTDIR="${2:?missing dir}"; shift 2 ;;
        --timing)     TIMING="${2:?}"; shift 2 ;;
        --extra)      EXTRA_NMAP="${2:-}"; shift 2 ;;
        -i|--inventory) INVENTORY="${2:?missing inventory}"; shift 2 ;;
        --feeds-dir)  FEEDS_DIR="${2:?missing dir}"; shift 2 ;;
        --skip-cve)   RUN_CVE=0; shift ;;
        -h|--help)    usage 0 ;;
        *) die "Unknown argument: $1 (see --help)" ;;
    esac
done

[[ -n "$TARGET" ]] || { warn "No target specified."; usage 1; }

# Basic sanity: a hostname or IPv4/CIDR, nothing shell-dangerous.
if [[ ! "$TARGET" =~ ^[A-Za-z0-9._:/-]+$ ]]; then
    die "Target '$TARGET' contains unexpected characters; refusing."
fi
[[ "$PORTS" =~ ^[0-9,-]+$ ]] || die "Port spec '$PORTS' must be digits, commas and dashes."
[[ "$TIMING" =~ ^-T[0-5]$ ]] || die "Timing must be -T0 .. -T5."
[[ -z "$INVENTORY" || -f "$INVENTORY" ]] || die "Inventory file not found: $INVENTORY"

# ----------------------------------------------------------------------------- deps
command -v nmap >/dev/null 2>&1 || die "nmap is not installed. Install it: sudo apt install nmap"
NMAP_VER="$(nmap --version | head -1)"
log "Using ${NMAP_VER}"

if [[ "$RUN_CVE" -eq 1 ]]; then
    PYBIN="${PYTHON:-python3}"
    command -v "$PYBIN" >/dev/null 2>&1 || die "python3 not found (needed for CVE mapping; use --skip-cve to skip)"
fi

# ----------------------------------------------------------------------------- authz gate
if [[ "${SCAN_AUTHORIZED:-}" != "yes" ]]; then
    warn "You are about to actively scan: ${TARGET}"
    warn "Only scan systems you own or have WRITTEN authorisation to test."
    if [[ -t 0 ]]; then
        read -r -p "Type 'I AM AUTHORIZED' to continue: " reply
        [[ "$reply" == "I AM AUTHORIZED" ]] || die "Authorisation not confirmed. Aborting."
    else
        die "Non-interactive run without SCAN_AUTHORIZED=yes. Aborting."
    fi
fi

# ----------------------------------------------------------------------------- privileges
# -sS (SYN) needs root; fall back to -sT (connect) otherwise so the tool still works unprivileged.
if [[ "$(id -u)" -eq 0 ]]; then
    SCAN_TYPE="-sS"
else
    SCAN_TYPE="-sT"
    warn "Not running as root: using TCP connect scan (-sT). SYN scan (-sS) needs sudo."
fi

mkdir -p "$OUTDIR"
STAMP="$(date -u +%Y%m%d_%H%M%S)"
SAFE_TARGET="$(echo "$TARGET" | tr '/:' '__')"
BASE="${OUTDIR}/scan_${SAFE_TARGET}_${STAMP}"
XML="${BASE}.xml"

# ----------------------------------------------------------------------------- scan
log "Scanning ${TARGET} ports ${PORTS} (${SCAN_TYPE} ${TIMING}) ..."
# -sV service/version detection is what powers CVE mapping.
# shellcheck disable=SC2086  # EXTRA_NMAP is an intentional word-split passthrough
if ! nmap $SCAN_TYPE -sV --version-intensity 7 -p "$PORTS" $TIMING \
        -oX "$XML" -oN "${BASE}.txt" $EXTRA_NMAP "$TARGET"; then
    die "Nmap exited non-zero. See ${BASE}.txt for partial output."
fi
ok "Nmap complete. XML: ${XML}"

OPEN_COUNT="$(grep -c 'state="open"' "$XML" 2>/dev/null || echo 0)"
log "Open ports with a state recorded: ${OPEN_COUNT}"

# ----------------------------------------------------------------------------- handoff
if [[ "$RUN_CVE" -eq 1 ]]; then
    log "Ranking findings (NVD + EPSS + CISA KEV + blast radius) ..."
    ARGS=(analyse "$XML" --sarif "${BASE}.sarif" --report "${BASE}_report.md" --json "${BASE}_findings.json"
          --graph "${BASE}_blast_radius.png")
    [[ -n "$INVENTORY" ]] && ARGS+=(--inventory "$INVENTORY")
    [[ -n "$FEEDS_DIR" ]] && ARGS+=(--feeds-dir "$FEEDS_DIR")
    if PYTHONPATH="${PROJECT}/src${PYTHONPATH:+:$PYTHONPATH}" "$PYBIN" -m vuln_scanner "${ARGS[@]}"; then
        ok "Report: ${BASE}_report.md  SARIF: ${BASE}.sarif  Graph: ${BASE}_blast_radius.png"
        echo "${BASE}_report.md"   # stdout = report path, for pipelines
    else
        warn "Analysis failed; the Nmap XML is still at ${XML}"
        exit 1
    fi
else
    echo "$XML"
fi
