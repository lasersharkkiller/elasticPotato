#!/usr/bin/env bash
# linux-scan.sh
# Read-only compliance scan: auditd, journald, rsyslog, /var/log, kernel sysctl
# Reference: CIS Distribution Independent Linux Benchmark v2.0 / NIST 800-53 Rev 5
#
# Usage:
#   ./linux-scan.sh [output_dir]
#   ./linux-scan.sh [--skip-audit-rules] [output_dir]
#
# Run as root for full auditctl -l access.
# Output: colored terminal + CSV in output_dir (default: ./LinuxHardening_Output)

# ============================================================
# Colors / helpers
# ============================================================
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; NC='\033[0m'

pass()    { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()    { echo -e "${RED}[FAIL]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
section() { echo -e "\n${MAGENTA}${BOLD}--- $* ---${NC}"; }

PASS_COUNT=0; FAIL_COUNT=0; WARN_COUNT=0
declare -a FINDINGS=()

# add_finding <STATUS> <NIST> <CATEGORY> <SETTING> <CURRENT> <EXPECTED> <CIS_REF>
add_finding() {
    local status="$1" nist="$2" cat="$3" setting="$4"
    local current="$5" expected="$6" cis="${7:-N/A}"
    # Escape pipes inside field values
    FINDINGS+=("${status}|${nist}|${cat}|${setting}|${current}|${expected}|${cis}")
    case "$status" in
        PASS) pass "$nist | $setting"; (( PASS_COUNT++ )) ;;
        FAIL) fail "$nist | $setting = $current  (expected: $expected)"; (( FAIL_COUNT++ )) ;;
        WARN) warn "$nist | $setting = $current  (recommended: $expected)"; (( WARN_COUNT++ )) ;;
    esac
}

# get_conf_value <file> <key>  — parse key = value, skip comments
get_conf_value() {
    local file="$1" key="$2"
    [[ -f "$file" ]] || { echo ""; return; }
    grep -E "^\s*${key}\s*=" "$file" 2>/dev/null \
        | grep -v '^\s*#' \
        | tail -1 \
        | sed 's/[^=]*=\s*//' \
        | tr -d '[:space:]'
}

# get_journald_value <key>  — checks base conf + conf.d overrides
get_journald_value() {
    local key="$1" val=""
    [[ -f /etc/systemd/journald.conf ]] && val=$(get_conf_value /etc/systemd/journald.conf "$key")
    if [[ -d /etc/systemd/journald.conf.d ]]; then
        for f in /etc/systemd/journald.conf.d/*.conf; do
            [[ -f "$f" ]] || continue
            local v; v=$(get_conf_value "$f" "$key")
            [[ -n "$v" ]] && val="$v"
        done
    fi
    echo "$val"
}

# ============================================================
# Parse arguments
# ============================================================
SKIP_AUDIT_RULES=false
OUTPUT_DIR="./LinuxHardening_Output"
for arg in "$@"; do
    case "$arg" in
        --skip-audit-rules) SKIP_AUDIT_RULES=true ;;
        *) OUTPUT_DIR="$arg" ;;
    esac
done

echo -e "${CYAN}${BOLD}Linux Compliance Scan — CIS / NIST 800-53${NC}"
echo "Host: $(hostname)  |  Date: $(date)"
[[ "$(id -u)" -ne 0 ]] && warn "Not running as root — auditctl -l and some checks may be incomplete."

# ============================================================
# SECTION 1: auditd Service
# ============================================================
section "auditd Service"

if command -v auditd &>/dev/null; then
    add_finding PASS "AU-2" "auditd" "auditd installed" "$(command -v auditd)" "Present" "CIS 4.1.1.1"
else
    add_finding FAIL "AU-2" "auditd" "auditd installed" "Not found" "Present" "CIS 4.1.1.1"
fi

svc_enabled=$(systemctl is-enabled auditd 2>/dev/null || echo "unknown")
if [[ "$svc_enabled" == "enabled" ]]; then
    add_finding PASS "AU-2" "auditd" "auditd service enabled" "$svc_enabled" "enabled" "CIS 4.1.1.1"
else
    add_finding FAIL "AU-2" "auditd" "auditd service enabled" "$svc_enabled" "enabled" "CIS 4.1.1.1"
fi

svc_active=$(systemctl is-active auditd 2>/dev/null || echo "unknown")
if [[ "$svc_active" == "active" ]]; then
    add_finding PASS "AU-2" "auditd" "auditd service active" "$svc_active" "active" "CIS 4.1.1.1"
else
    add_finding FAIL "AU-2" "auditd" "auditd service active" "$svc_active" "active" "CIS 4.1.1.1"
fi

# ============================================================
# SECTION 2: auditd.conf Settings
# ============================================================
section "auditd.conf"
AUDITD_CONF="/etc/audit/auditd.conf"

max_log=$(get_conf_value "$AUDITD_CONF" "max_log_file")
if [[ -n "$max_log" && "$max_log" -ge 8 ]]; then
    add_finding PASS "AU-11" "auditd.conf" "max_log_file (MB)" "$max_log" ">= 8" "CIS 4.1.2.1"
else
    add_finding FAIL "AU-11" "auditd.conf" "max_log_file (MB)" "${max_log:-NOT SET}" ">= 8" "CIS 4.1.2.1"
fi

num_logs=$(get_conf_value "$AUDITD_CONF" "num_logs")
if [[ -n "$num_logs" && "$num_logs" -ge 5 ]]; then
    add_finding PASS "AU-11" "auditd.conf" "num_logs" "$num_logs" ">= 5" "CIS 4.1.2.2"
else
    add_finding FAIL "AU-11" "auditd.conf" "num_logs" "${num_logs:-NOT SET}" ">= 5" "CIS 4.1.2.2"
fi

max_log_action=$(get_conf_value "$AUDITD_CONF" "max_log_file_action")
if [[ "$max_log_action" =~ ^(keep_logs|rotate)$ ]]; then
    add_finding PASS "AU-11" "auditd.conf" "max_log_file_action" "$max_log_action" "keep_logs|rotate" "CIS 4.1.2.2"
else
    add_finding FAIL "AU-11" "auditd.conf" "max_log_file_action" "${max_log_action:-NOT SET}" "keep_logs|rotate" "CIS 4.1.2.2"
fi

space_left=$(get_conf_value "$AUDITD_CONF" "space_left_action")
if [[ "$space_left" =~ ^(email|exec|halt|singleuser|rotate|suspend)$ ]]; then
    add_finding PASS "AU-5" "auditd.conf" "space_left_action" "$space_left" "email|exec|halt|singleuser" "CIS 4.1.2.3"
else
    add_finding FAIL "AU-5" "auditd.conf" "space_left_action" "${space_left:-NOT SET}" "email|exec|halt|singleuser" "CIS 4.1.2.3"
fi

admin_space=$(get_conf_value "$AUDITD_CONF" "admin_space_left_action")
if [[ "$admin_space" =~ ^(halt|single|singleuser)$ ]]; then
    add_finding PASS "AU-5" "auditd.conf" "admin_space_left_action" "$admin_space" "halt|single" "CIS 4.1.2.3"
else
    add_finding FAIL "AU-5" "auditd.conf" "admin_space_left_action" "${admin_space:-NOT SET}" "halt|single" "CIS 4.1.2.3"
fi

disk_full=$(get_conf_value "$AUDITD_CONF" "disk_full_action")
if [[ "$disk_full" =~ ^(halt|single|singleuser)$ ]]; then
    add_finding PASS "AU-5" "auditd.conf" "disk_full_action" "$disk_full" "halt|single" "CIS 4.1.2.3"
else
    add_finding WARN "AU-5" "auditd.conf" "disk_full_action" "${disk_full:-NOT SET}" "halt|single" "CIS 4.1.2.3"
fi

disk_error=$(get_conf_value "$AUDITD_CONF" "disk_error_action")
if [[ "$disk_error" =~ ^(halt|syslog|exec)$ ]]; then
    add_finding PASS "AU-5" "auditd.conf" "disk_error_action" "$disk_error" "halt|syslog|exec" "CIS 4.1.2.3"
else
    add_finding WARN "AU-5" "auditd.conf" "disk_error_action" "${disk_error:-NOT SET}" "halt|syslog|exec" "CIS 4.1.2.3"
fi

log_format=$(get_conf_value "$AUDITD_CONF" "log_format" | tr '[:lower:]' '[:upper:]')
if [[ "$log_format" == "ENRICHED" ]]; then
    add_finding PASS "AU-3" "auditd.conf" "log_format" "$log_format" "ENRICHED" "CIS 4.1.1.4"
else
    add_finding WARN "AU-3" "auditd.conf" "log_format" "${log_format:-NOT SET}" "ENRICHED" "CIS 4.1.1.4"
fi

# ============================================================
# SECTION 3: Audit Rules
# ============================================================
if [[ "$SKIP_AUDIT_RULES" == "false" ]]; then
    section "Audit Rules"

    ALL_RULES=""
    [[ -d /etc/audit/rules.d ]] && ALL_RULES+="$(cat /etc/audit/rules.d/*.rules 2>/dev/null)"$'\n'
    [[ -f /etc/audit/audit.rules ]] && ALL_RULES+="$(cat /etc/audit/audit.rules 2>/dev/null)"$'\n'
    command -v auditctl &>/dev/null && ALL_RULES+="$(auditctl -l 2>/dev/null)"$'\n'

    check_key() {
        local key="$1" nist="$2" cis="$3" desc="$4"
        if echo "$ALL_RULES" | grep -qE -- "-k[[:space:]]+${key}([[:space:]]|$)"; then
            add_finding PASS "$nist" "Audit Rules" "Key: $key | $desc" "Present" "Present" "$cis"
        else
            add_finding FAIL "$nist" "Audit Rules" "Key: $key | $desc" "Missing" "Present" "$cis"
        fi
    }

    check_key "time-change"   "AU-12" "CIS 4.1.3"  "Date/time modification events"
    check_key "identity"      "AU-12" "CIS 4.1.4"  "User/group identity changes"
    check_key "system-locale" "AU-12" "CIS 4.1.5"  "Network environment changes"
    check_key "MAC-policy"    "AU-12" "CIS 4.1.6"  "MAC policy (SELinux/AppArmor) changes"
    check_key "logins"        "AU-12" "CIS 4.1.7"  "Login and logout events"
    check_key "session"       "AU-12" "CIS 4.1.8"  "Session initiation events"
    check_key "perm_mod"      "AU-12" "CIS 4.1.9"  "DAC permission modifications"
    check_key "access"        "AU-12" "CIS 4.1.10" "Unsuccessful file access"
    check_key "privileged"    "AU-12" "CIS 4.1.11" "Privileged command execution"
    check_key "mounts"        "AU-12" "CIS 4.1.12" "File system mount events"
    check_key "delete"        "AU-12" "CIS 4.1.13" "File deletion events"
    check_key "scope"         "AU-12" "CIS 4.1.14" "Sudoers changes"
    check_key "actions"       "AU-12" "CIS 4.1.15" "sudo command usage"
    check_key "modules"       "AU-12" "CIS 4.1.16" "Kernel module load/unload"

    # Buffer size
    buf_size=$(echo "$ALL_RULES" | grep -oP '(?<=-b\s)\d+' | tail -1)
    if [[ -n "$buf_size" && "$buf_size" -ge 8192 ]]; then
        add_finding PASS "AU-12" "Audit Rules" "Audit buffer size (-b)" "$buf_size" ">= 8192" "CIS 4.1.2"
    else
        add_finding WARN "AU-12" "Audit Rules" "Audit buffer size (-b)" "${buf_size:-NOT SET}" ">= 8192" "CIS 4.1.2"
    fi

    # Immutable flag
    if echo "$ALL_RULES" | grep -qE '^-e[[:space:]]+2'; then
        add_finding PASS "AU-12" "Audit Rules" "Immutable audit config (-e 2)" "Set" "Set" "CIS 4.1.17"
    else
        add_finding WARN "AU-12" "Audit Rules" "Immutable audit config (-e 2)" "Not set" "Set" "CIS 4.1.17"
    fi

    # Audit log file permissions
    LOG_FILE=$(get_conf_value "$AUDITD_CONF" "log_file")
    [[ -z "$LOG_FILE" ]] && LOG_FILE="/var/log/audit/audit.log"
    if [[ -f "$LOG_FILE" ]]; then
        log_perms=$(stat -c '%a' "$LOG_FILE" 2>/dev/null)
        if [[ -n "$log_perms" && "$log_perms" -le 600 ]]; then
            add_finding PASS "AU-9" "Audit Rules" "Audit log file permissions" "$log_perms" "<= 600" "CIS 4.1.1.2"
        else
            add_finding FAIL "AU-9" "Audit Rules" "Audit log file permissions" "${log_perms:-N/A}" "<= 600" "CIS 4.1.1.2"
        fi
    fi

    LOG_DIR=$(dirname "$LOG_FILE")
    if [[ -d "$LOG_DIR" ]]; then
        dir_perms=$(stat -c '%a' "$LOG_DIR" 2>/dev/null)
        if [[ -n "$dir_perms" && "$dir_perms" -le 750 ]]; then
            add_finding PASS "AU-9" "Audit Rules" "Audit log directory permissions" "$dir_perms" "<= 750" "CIS 4.1.1.3"
        else
            add_finding FAIL "AU-9" "Audit Rules" "Audit log directory permissions" "${dir_perms:-N/A}" "<= 750" "CIS 4.1.1.3"
        fi
    fi
fi

# ============================================================
# SECTION 4: systemd-journald
# ============================================================
section "systemd-journald"

jd_storage=$(get_journald_value "Storage")
if [[ "$jd_storage" == "persistent" ]]; then
    add_finding PASS "AU-11" "journald" "Storage" "$jd_storage" "persistent" "CIS 4.2.1.1"
else
    add_finding FAIL "AU-11" "journald" "Storage" "${jd_storage:-NOT SET}" "persistent" "CIS 4.2.1.1"
fi

jd_compress=$(get_journald_value "Compress")
if [[ "$jd_compress" == "yes" ]]; then
    add_finding PASS "AU-11" "journald" "Compress" "$jd_compress" "yes" "CIS 4.2.1.2"
else
    add_finding WARN "AU-11" "journald" "Compress" "${jd_compress:-NOT SET}" "yes" "CIS 4.2.1.2"
fi

jd_fwd=$(get_journald_value "ForwardToSyslog")
if [[ "$jd_fwd" == "yes" ]]; then
    add_finding PASS "AU-3" "journald" "ForwardToSyslog" "$jd_fwd" "yes" "CIS 4.2.1.3"
else
    add_finding WARN "AU-3" "journald" "ForwardToSyslog" "${jd_fwd:-NOT SET}" "yes" "CIS 4.2.1.3"
fi

jd_maxuse=$(get_journald_value "SystemMaxUse")
if [[ -n "$jd_maxuse" ]]; then
    add_finding PASS "AU-11" "journald" "SystemMaxUse" "$jd_maxuse" "Set (e.g. 500M)" "CIS 4.2.1.4"
else
    add_finding WARN "AU-11" "journald" "SystemMaxUse" "NOT SET" "Set (e.g. 500M)" "CIS 4.2.1.4"
fi

jd_maxfile=$(get_journald_value "MaxFileSec")
if [[ -n "$jd_maxfile" ]]; then
    add_finding PASS "AU-11" "journald" "MaxFileSec" "$jd_maxfile" "Set (e.g. 1month)" "CIS 4.2.1.5"
else
    add_finding WARN "AU-11" "journald" "MaxFileSec" "NOT SET" "Set (e.g. 1month)" "CIS 4.2.1.5"
fi

jd_rate_int=$(get_journald_value "RateLimitInterval")
if [[ -n "$jd_rate_int" ]]; then
    add_finding PASS "AU-12" "journald" "RateLimitInterval" "$jd_rate_int" "Set (e.g. 30s)" "CIS 4.2.1"
else
    add_finding WARN "AU-12" "journald" "RateLimitInterval" "NOT SET" "Set (e.g. 30s)" "CIS 4.2.1"
fi

jd_rate_burst=$(get_journald_value "RateLimitBurst")
if [[ -n "$jd_rate_burst" && "$jd_rate_burst" -ge 10000 ]]; then
    add_finding PASS "AU-12" "journald" "RateLimitBurst" "$jd_rate_burst" ">= 10000" "CIS 4.2.1"
else
    add_finding WARN "AU-12" "journald" "RateLimitBurst" "${jd_rate_burst:-NOT SET}" ">= 10000" "CIS 4.2.1"
fi

# ============================================================
# SECTION 5: rsyslog
# ============================================================
section "rsyslog"

if command -v rsyslogd &>/dev/null; then
    add_finding PASS "AU-3" "rsyslog" "rsyslogd installed" "$(command -v rsyslogd)" "Present" "CIS 4.2.2"

    rsyslog_enabled=$(systemctl is-enabled rsyslog 2>/dev/null || echo "unknown")
    if [[ "$rsyslog_enabled" == "enabled" ]]; then
        add_finding PASS "AU-3" "rsyslog" "rsyslog service enabled" "$rsyslog_enabled" "enabled" "CIS 4.2.2.1"
    else
        add_finding WARN "AU-3" "rsyslog" "rsyslog service enabled" "$rsyslog_enabled" "enabled" "CIS 4.2.2.1"
    fi

    rsyslog_active=$(systemctl is-active rsyslog 2>/dev/null || echo "unknown")
    if [[ "$rsyslog_active" == "active" ]]; then
        add_finding PASS "AU-3" "rsyslog" "rsyslog service active" "$rsyslog_active" "active" "CIS 4.2.2.1"
    else
        add_finding WARN "AU-3" "rsyslog" "rsyslog service active" "$rsyslog_active" "active" "CIS 4.2.2.1"
    fi

    # Collect non-comment lines from all rsyslog configs
    rsyslog_content=$(grep -hEv '^\s*#|^\s*$' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null)

    if echo "$rsyslog_content" | grep -qE 'auth[^,]*\s+/var/log/'; then
        add_finding PASS "AU-12" "rsyslog" "auth/authpriv logging configured" "Found" "auth.* /var/log/auth.log" "CIS 4.2.2.2"
    else
        add_finding FAIL "AU-12" "rsyslog" "auth/authpriv logging configured" "Not found" "auth.* /var/log/auth.log" "CIS 4.2.2.2"
    fi

    if echo "$rsyslog_content" | grep -q '\$FileCreateMode'; then
        add_finding PASS "AU-9" "rsyslog" "\$FileCreateMode set" "Found" "0640" "CIS 4.2.2.3"
    else
        add_finding WARN "AU-9" "rsyslog" "\$FileCreateMode set" "Not set" "0640" "CIS 4.2.2.3"
    fi

    # Warn if unencrypted remote syslog (@@) is configured
    if echo "$rsyslog_content" | grep -qE '^\s*\*\.\*[[:space:]]+@@'; then
        add_finding WARN "AU-3" "rsyslog" "Remote syslog forwarding (@@TCP)" \
            "Unencrypted TCP (@@) found" "Use TLS/omrelp instead" "CIS 4.2.2.4"
    fi
else
    add_finding WARN "AU-3" "rsyslog" "rsyslogd installed" "Not found" "Present" "CIS 4.2.2"
fi

# ============================================================
# SECTION 6: /var/log Permissions
# ============================================================
section "/var/log Permissions"

declare -A LOG_CHECKS=(
    ["/var/log"]=755
    ["/var/log/auth.log"]=640
    ["/var/log/syslog"]=640
    ["/var/log/kern.log"]=640
    ["/var/log/wtmp"]=664
    ["/var/log/btmp"]=640
    ["/var/log/lastlog"]=644
)
for path in "${!LOG_CHECKS[@]}"; do
    max_perm="${LOG_CHECKS[$path]}"
    if [[ -e "$path" ]]; then
        perms=$(stat -c '%a' "$path" 2>/dev/null)
        if [[ -n "$perms" && "$perms" -le "$max_perm" ]]; then
            add_finding PASS "AU-9" "Log Permissions" "$path permissions" "$perms" "<= $max_perm" "CIS 4.2.3"
        else
            add_finding FAIL "AU-9" "Log Permissions" "$path permissions" "${perms:-N/A}" "<= $max_perm" "CIS 4.2.3"
        fi
    else
        add_finding WARN "AU-9" "Log Permissions" "$path exists" "Not found" "Present" "CIS 4.2.3"
    fi
done

ww_count=$(find /var/log -type f -perm /o+w 2>/dev/null | wc -l)
if [[ "$ww_count" -eq 0 ]]; then
    add_finding PASS "AU-9" "Log Permissions" "World-writable files in /var/log" "0" "0" "CIS 4.2.3"
else
    add_finding FAIL "AU-9" "Log Permissions" "World-writable files in /var/log" "$ww_count found" "0" "CIS 4.2.3"
fi

# ============================================================
# SECTION 7: Kernel Sysctl
# ============================================================
section "Kernel Audit Settings"

dmesg_restrict=$(sysctl -n kernel.dmesg_restrict 2>/dev/null || echo "NOT SET")
if [[ "$dmesg_restrict" == "1" ]]; then
    add_finding PASS "SI-3" "Kernel" "kernel.dmesg_restrict" "$dmesg_restrict" "1" "CIS 1.6.1"
else
    add_finding FAIL "SI-3" "Kernel" "kernel.dmesg_restrict" "$dmesg_restrict" "1" "CIS 1.6.1"
fi

kptr_restrict=$(sysctl -n kernel.kptr_restrict 2>/dev/null || echo "NOT SET")
if [[ "$kptr_restrict" =~ ^[0-9]+$ && "$kptr_restrict" -ge 1 ]]; then
    add_finding PASS "SI-3" "Kernel" "kernel.kptr_restrict" "$kptr_restrict" ">= 1" "CIS 1.6.2"
else
    add_finding FAIL "SI-3" "Kernel" "kernel.kptr_restrict" "$kptr_restrict" ">= 1" "CIS 1.6.2"
fi

audit_backlog=$(sysctl -n kernel.audit_backlog_limit 2>/dev/null || echo "NOT SET")
if [[ "$audit_backlog" =~ ^[0-9]+$ && "$audit_backlog" -ge 8192 ]]; then
    add_finding PASS "AU-12" "Kernel" "kernel.audit_backlog_limit" "$audit_backlog" ">= 8192" "CIS 4.1.2"
else
    add_finding WARN "AU-12" "Kernel" "kernel.audit_backlog_limit" "${audit_backlog}" ">= 8192" "CIS 4.1.2"
fi

# ============================================================
# SECTION 8: logrotate
# ============================================================
section "Log Rotation"

if command -v logrotate &>/dev/null; then
    add_finding PASS "AU-11" "logrotate" "logrotate installed" "$(command -v logrotate)" "Present" "CIS 4.3"
    if [[ -f /etc/logrotate.conf ]]; then
        add_finding PASS "AU-11" "logrotate" "/etc/logrotate.conf exists" "Present" "Present" "CIS 4.3"
    else
        add_finding FAIL "AU-11" "logrotate" "/etc/logrotate.conf exists" "Missing" "Present" "CIS 4.3"
    fi
    lr_count=$(ls /etc/logrotate.d/ 2>/dev/null | wc -l)
    if [[ "$lr_count" -gt 0 ]]; then
        add_finding PASS "AU-11" "logrotate" "/etc/logrotate.d/ entries" "$lr_count" "> 0" "CIS 4.3"
    else
        add_finding WARN "AU-11" "logrotate" "/etc/logrotate.d/ entries" "0" "> 0" "CIS 4.3"
    fi
else
    add_finding WARN "AU-11" "logrotate" "logrotate installed" "Not found" "Present" "CIS 4.3"
fi

# ============================================================
# Summary
# ============================================================
TOTAL=$(( PASS_COUNT + FAIL_COUNT + WARN_COUNT ))
SCORE=0; [[ "$TOTAL" -gt 0 ]] && SCORE=$(( PASS_COUNT * 100 / TOTAL ))

section "Scan Complete"
echo -e "${GREEN}PASS: $PASS_COUNT${NC}  ${RED}FAIL: $FAIL_COUNT${NC}  ${YELLOW}WARN: $WARN_COUNT${NC}  Total: $TOTAL  Score: ${BOLD}${SCORE}%${NC}"

# ============================================================
# CSV Export
# ============================================================
mkdir -p "$OUTPUT_DIR"
STAMP=$(date +%Y%m%d_%H%M%S)
CSV_PATH="$OUTPUT_DIR/LinuxScan_${STAMP}.csv"

{
    echo "Status,NISTControl,Category,Setting,CurrentValue,RecommendedValue,CISReference"
    for f in "${FINDINGS[@]}"; do
        IFS='|' read -r st nist cat setting current expected cis <<< "$f"
        printf '"%s","%s","%s","%s","%s","%s","%s"\n' \
            "$st" "$nist" "$cat" "$setting" "$current" "$expected" "$cis"
    done
} > "$CSV_PATH"

info "CSV report: $CSV_PATH"
