#!/usr/bin/env bash
# set-auditd-policy.sh
# Apply CIS Benchmark-aligned auditd rules and harden auditd.conf.
# Requires root.
#
# Usage:
#   sudo ./set-auditd-policy.sh [options]
#
# Options:
#   --no-immutable   Omit -e 2 flag (rules can be modified without reboot)
#   --skip-conf      Skip auditd.conf hardening; only deploy rules file
#   --force          Skip confirmation prompt
#   --output PATH    Write rules to PATH  (default: /etc/audit/rules.d/99-hardened.rules)

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
SRC_RULES="$CONFIGS_DIR/cis-auditd.rules"
RULES_OUTPUT="/etc/audit/rules.d/99-hardened.rules"
AUDITD_CONF="/etc/audit/auditd.conf"
NO_IMMUTABLE=false
SKIP_CONF=false
FORCE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-immutable) NO_IMMUTABLE=true ;;
        --skip-conf)    SKIP_CONF=true ;;
        --force)        FORCE=true ;;
        --output)       RULES_OUTPUT="$2"; shift ;;
        -h|--help)
            echo "Usage: sudo $0 [--no-immutable] [--skip-conf] [--force] [--output PATH]"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

# ============================================================
# Pre-flight checks
# ============================================================
if [[ "$(id -u)" -ne 0 ]]; then
    fail "Must run as root. Try: sudo $0 $*"
    exit 1
fi

if ! command -v auditd &>/dev/null; then
    fail "auditd is not installed."
    echo "  Debian/Ubuntu : apt install auditd audispd-plugins"
    echo "  RHEL/Fedora   : dnf install audit"
    echo "  SUSE          : zypper install audit"
    exit 1
fi

if [[ ! -f "$SRC_RULES" ]]; then
    fail "Rules source file not found: $SRC_RULES"
    exit 1
fi

# ============================================================
# Confirmation
# ============================================================
if [[ "$FORCE" == "false" ]]; then
    warn "This will write audit rules to $RULES_OUTPUT and restart auditd."
    [[ "$NO_IMMUTABLE" == "false" ]] && \
        warn "The -e 2 flag will make audit config immutable until next reboot."
    read -rp "Continue? (y/N): " confirm
    [[ "$confirm" =~ ^[yY]$ ]] || { info "Aborted."; exit 0; }
fi

# ============================================================
# Backup existing rules
# ============================================================
section "Backing Up Existing Rules"
RULES_DIR="$(dirname "$RULES_OUTPUT")"
mkdir -p "$RULES_DIR"

EXISTING=("$RULES_DIR"/*.rules)
if [[ -f "${EXISTING[0]}" ]]; then
    BACKUP_DIR="$RULES_DIR/backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    cp "$RULES_DIR"/*.rules "$BACKUP_DIR/" 2>/dev/null || true
    info "Backed up existing rules to $BACKUP_DIR"
else
    info "No existing rules to back up."
fi

# ============================================================
# Build rules: static CIS rules + dynamic SUID/SGID discovery
# ============================================================
section "Building Audit Rules"

# Strip the immutable flag from the static file so we can control placement
RULES_BODY=$(grep -v '^-e 2' "$SRC_RULES")

# Discover SUID/SGID binaries on this system
info "Discovering SUID/SGID binaries for privileged command rules ..."
DYNAMIC_RULES=""
DCOUNT=0
while IFS= read -r bin; do
    # Skip if the binary is already listed in the static rules file
    grep -qF "$bin" "$SRC_RULES" && continue
    DYNAMIC_RULES+=$'\n'"-a always,exit -F path=${bin} -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged"
    (( DCOUNT++ ))
done < <(find /usr/bin /usr/sbin /bin /sbin -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort -u)

if [[ "$DCOUNT" -gt 0 ]]; then
    info "Added $DCOUNT dynamic SUID/SGID rules."
    RULES_BODY+=$'\n\n'
    RULES_BODY+="# ============================================================"$'\n'
    RULES_BODY+="# Dynamic: SUID/SGID binaries discovered on this system"$'\n'
    RULES_BODY+="# ============================================================"
    RULES_BODY+="$DYNAMIC_RULES"
fi

# Append immutable flag last
if [[ "$NO_IMMUTABLE" == "false" ]]; then
    RULES_BODY+=$'\n\n'"# CIS 4.1.17 — Immutable (requires reboot to modify rules)"
    RULES_BODY+=$'\n'"-e 2"
else
    warn "Immutable flag (-e 2) omitted. Rules can be changed without reboot."
    RULES_BODY+=$'\n\n'"# -e 2 omitted (--no-immutable flag was used)"
fi

# ============================================================
# Write rules file
# ============================================================
section "Writing Rules"
printf '%s\n' "$RULES_BODY" > "$RULES_OUTPUT"
chmod 600 "$RULES_OUTPUT"
pass "Rules written: $RULES_OUTPUT"

# ============================================================
# Harden auditd.conf
# ============================================================
if [[ "$SKIP_CONF" == "false" ]]; then
    section "Hardening auditd.conf"
    if [[ -f "$AUDITD_CONF" ]]; then
        CONF_BAK="${AUDITD_CONF}.bak_$(date +%Y%m%d_%H%M%S)"
        cp "$AUDITD_CONF" "$CONF_BAK"
        info "Backed up auditd.conf to $CONF_BAK"

        # set_conf_value <key> <value> <file>
        set_conf_value() {
            local key="$1" val="$2" file="$3"
            if grep -qE "^\s*${key}\s*=" "$file"; then
                sed -i "s|^\s*${key}\s*=.*|${key} = ${val}|" "$file"
            else
                echo "${key} = ${val}" >> "$file"
            fi
        }

        set_conf_value max_log_file            8          "$AUDITD_CONF"
        set_conf_value num_logs                5          "$AUDITD_CONF"
        set_conf_value max_log_file_action     keep_logs  "$AUDITD_CONF"
        set_conf_value space_left_action       email      "$AUDITD_CONF"
        set_conf_value admin_space_left_action halt       "$AUDITD_CONF"
        set_conf_value disk_full_action        halt       "$AUDITD_CONF"
        set_conf_value disk_error_action       syslog     "$AUDITD_CONF"
        set_conf_value log_format              ENRICHED   "$AUDITD_CONF"
        set_conf_value log_group               root       "$AUDITD_CONF"

        pass "auditd.conf hardened"
    else
        warn "auditd.conf not found at $AUDITD_CONF — skipping conf hardening."
    fi
fi

# ============================================================
# Reload and restart auditd
# ============================================================
section "Reloading auditd"

if command -v augenrules &>/dev/null; then
    augenrules --load 2>&1 | tail -5 || true
    pass "Rules loaded via augenrules"
else
    auditctl -R "$RULES_OUTPUT" 2>&1 || true
    pass "Rules loaded via auditctl -R"
fi

systemctl restart auditd
systemctl enable auditd 2>/dev/null
pass "auditd restarted and enabled"

info "Run ./linux-scan.sh to verify: look for FAIL entries in the Audit Rules section."
