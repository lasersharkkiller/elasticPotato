#!/usr/bin/env bash
# set-logging-policy.sh
# Apply hardened journald and rsyslog configuration, and fix /var/log permissions.
# Requires root.
#
# Usage:
#   sudo ./set-logging-policy.sh [options]
#
# Options:
#   --journald-only   Only configure journald; skip rsyslog
#   --rsyslog-only    Only configure rsyslog; skip journald
#   --force           Skip confirmation prompt

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; NC='\033[0m'

pass()    { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()    { echo -e "${RED}[FAIL]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
section() { echo -e "\n${MAGENTA}${BOLD}--- $* ---${NC}"; }

# ============================================================
# Arguments
# ============================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIGS_DIR="$SCRIPT_DIR/Configs"
JOURNALD_ONLY=false
RSYSLOG_ONLY=false
FORCE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --journald-only) JOURNALD_ONLY=true ;;
        --rsyslog-only)  RSYSLOG_ONLY=true ;;
        --force)         FORCE=true ;;
        -h|--help)
            echo "Usage: sudo $0 [--journald-only] [--rsyslog-only] [--force]"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

# ============================================================
# Pre-flight
# ============================================================
if [[ "$(id -u)" -ne 0 ]]; then
    fail "Must run as root. Try: sudo $0"
    exit 1
fi

if [[ "$FORCE" == "false" ]]; then
    warn "This will write journald/rsyslog config files and adjust /var/log permissions."
    read -rp "Continue? (y/N): " confirm
    [[ "$confirm" =~ ^[yY]$ ]] || { info "Aborted."; exit 0; }
fi

DO_JOURNALD=true; DO_RSYSLOG=true
[[ "$RSYSLOG_ONLY" == "true" ]] && DO_JOURNALD=false
[[ "$JOURNALD_ONLY" == "true" ]] && DO_RSYSLOG=false

# ============================================================
# journald
# ============================================================
if [[ "$DO_JOURNALD" == "true" ]]; then
    section "Configuring systemd-journald"

    JSRC="$CONFIGS_DIR/journald-hardened.conf"
    if [[ ! -f "$JSRC" ]]; then
        warn "journald-hardened.conf not found at $JSRC — skipping."
    else
        JDEST_DIR="/etc/systemd/journald.conf.d"
        JDEST="$JDEST_DIR/99-hardened.conf"

        mkdir -p "$JDEST_DIR"
        if [[ -f "$JDEST" ]]; then
            cp "$JDEST" "${JDEST}.bak_$(date +%Y%m%d_%H%M%S)"
            info "Backed up existing journald config"
        fi

        cp "$JSRC" "$JDEST"
        chmod 644 "$JDEST"
        pass "journald config written: $JDEST"

        if systemctl restart systemd-journald 2>/dev/null; then
            pass "systemd-journald restarted"
        else
            warn "systemd-journald restart returned non-zero — check: systemctl status systemd-journald"
        fi
    fi
fi

# ============================================================
# rsyslog
# ============================================================
if [[ "$DO_RSYSLOG" == "true" ]]; then
    section "Configuring rsyslog"

    if ! command -v rsyslogd &>/dev/null; then
        warn "rsyslogd not installed — skipping rsyslog configuration."
        info "Install with:  apt install rsyslog  |  dnf install rsyslog"
    else
        RSRC="$CONFIGS_DIR/rsyslog-hardened.conf"
        if [[ ! -f "$RSRC" ]]; then
            warn "rsyslog-hardened.conf not found at $RSRC — skipping."
        else
            RDEST_DIR="/etc/rsyslog.d"
            RDEST="$RDEST_DIR/99-hardened.conf"

            mkdir -p "$RDEST_DIR"
            if [[ -f "$RDEST" ]]; then
                cp "$RDEST" "${RDEST}.bak_$(date +%Y%m%d_%H%M%S)"
                info "Backed up existing rsyslog config"
            fi

            cp "$RSRC" "$RDEST"
            chmod 640 "$RDEST"
            pass "rsyslog config written: $RDEST"

            # Validate config syntax before restarting
            if rsyslogd -N1 &>/dev/null; then
                pass "rsyslog configuration validated"
            else
                warn "rsyslog syntax check reported issues — review $RDEST before restarting manually."
                warn "Skipping rsyslog restart to avoid breaking logging."
                DO_RSYSLOG=false
            fi

            if [[ "$DO_RSYSLOG" == "true" ]]; then
                systemctl restart rsyslog
                systemctl enable rsyslog 2>/dev/null
                pass "rsyslog restarted and enabled"
            fi
        fi
    fi
fi

# ============================================================
# /var/log permission hardening
# ============================================================
section "Hardening /var/log Permissions"

# Remove world-write from files
ww_files=$(find /var/log -type f -perm /o+w 2>/dev/null | wc -l)
if [[ "$ww_files" -gt 0 ]]; then
    find /var/log -type f -perm /o+w -exec chmod o-w {} \;
    pass "Removed world-write from $ww_files file(s) in /var/log"
else
    pass "/var/log — no world-writable files found"
fi

# Remove world-write from directories
ww_dirs=$(find /var/log -type d -perm /o+w 2>/dev/null | wc -l)
if [[ "$ww_dirs" -gt 0 ]]; then
    find /var/log -type d -perm /o+w -exec chmod o-w {} \;
    pass "Removed world-write from $ww_dirs director(y/ies) in /var/log"
fi

# Ensure standard log files exist with correct permissions
declare -A LOGFILE_MODES=(
    ["/var/log/auth.log"]=640
    ["/var/log/btmp"]=640
)
for logfile in "${!LOGFILE_MODES[@]}"; do
    mode="${LOGFILE_MODES[$logfile]}"
    if [[ ! -f "$logfile" ]]; then
        touch "$logfile"
        chmod "$mode" "$logfile"
        pass "Created $logfile with mode $mode"
    fi
done

# ============================================================
# Done
# ============================================================
section "Done"
info "Run ./linux-scan.sh to verify the logging configuration."
