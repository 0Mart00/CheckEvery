#!/usr/bin/env python3
import subprocess
import sys
import os
import glob
import re
import urllib.request
import json

# ANSI Color Codes for scannability
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"

REPORT_PATH = "/root/forensic_report.txt"
report_file = open(REPORT_PATH, "w")

def log(text, color=RESET, is_bold=False):
    prefix = BOLD if is_bold else ""
    print(f"{color}{prefix}{text}{RESET}")
    clean_text = re.sub(r'\x1b\[[0-9;]*m', '', text)
    report_file.write(clean_text + "\n")

def section_header(text):
    log(f"\n{'='*60}", BLUE, True)
    log(f"[*] {text}", BLUE, True)
    log(f"{'='*60}", BLUE, True)

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=15)
        return result.stdout.strip()
    except Exception:
        return ""

def get_ip_info(ip):
    if ip in ["127.0.0.1", "0.0.0.0", "::1"] or ip.startswith("192.168.") or ip.startswith("10."):
        return {"country": "Local Network", "city": "Local", "org": "Loopback/LAN", "countryCode": "LOCAL"}
    try:
        url = f"http://ip-api.com{ip}"
        with urllib.request.urlopen(url, timeout=5) as response:
            return json.loads(response.read().decode())
    except Exception:
        return None

def get_current_country():
    try:
        with urllib.request.urlopen("http://ip-api.com", timeout=5) as response:
            data = json.loads(response.read().decode())
            return data.get("countryCode", "HU")
    except Exception:
        return "HU"

if os.getuid() != 0:
    print(f"{RED}{BOLD}[!] ERROR: This script must be run with ROOT privileges (sudo)!{RESET}")
    sys.exit(1)

log("============================================================", GREEN, True)
log("===     ARCH LINUX GOD-MODE FORENSICS & OSINT CHECKER    ===", GREEN, True)
log("============================================================", GREEN, True)

my_country = get_current_country()
log(f"[i] Baseline country code set to: {my_country}", BLUE)
log(f"[i] Forensic report will be saved to: {REPORT_PATH}\n", BLUE)

# 1. SYSTEM LOGS & OSINT GEOLOCATION ANOMALIES
section_header("1. SYSTEM LOGS & OSINT IP ANOMALY DETECTION")
last_output = run_command("last -i -n 10")
if last_output:
    ips = list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', last_output)))
    for ip in ips:
        info = get_ip_info(ip)
        if info and info.get("status") == "success":
            country = info.get("country", "Unknown")
            cc = info.get("countryCode", "UNKNOWN")
            city = info.get("city", "Unknown")
            isp = info.get("org", "Unknown")
            if cc != "LOCAL" and cc != my_country:
                log(f"  - IP: \033[91m{ip}\033[0m -> \033[91m\033[1m[ANOMALY DETECTED]\033[0m Location: \033[91m{city}, {country}\033[0m | ISP: \033[93m{isp}\033[0m")
            else:
                log(f"  - IP: \033[92m{ip}\033[0m -> Location: \033[92m{city}, {country}\033[0m | ISP: {isp}")

log(f"\nFailed login attempts (lastb):", RED, True)
lastb_res = run_command("lastb -i -n 5")
if lastb_res:
    failed_ips = list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', lastb_res)))
    for f_ip in failed_ips:
        f_info = get_ip_info(f_ip)
        if f_info and f_info.get("status") == "success":
            log(f"  - Attacker IP: \033[91m{f_ip}\033[0m -> \033[93m{f_info.get('city')}, {f_info.get('country')}\033[0m")
else:
    log("[OK] No failed login attempts found.", GREEN)

# 2. SUSPICIOUS PROCESSES IN MEMORY
section_header("2. HIDDEN OR SUSPICIOUS PROCESSES IN MEMORY")
suspicious_procs = run_command("ps aux | grep -E '(bash|sh|python|perl|php|nc|netcat|ncat).*[0-9]' | grep -v grep")
if suspicious_procs: log(f"[WARNING] Suspicious processes:\n{suspicious_procs}", RED)
deleted_procs = run_command("ls -la /proc/*/exe 2>/dev/null | grep 'deleted'")
if deleted_procs: log(f"[DANGER] Running from DELETED files:\n{deleted_procs}", RED)

# 3. NETWORK CONNECTIONS & PROMISCUOUS MODE
section_header("3. NETWORK CONNECTIONS & PROMISCUOUS MODE CHECK")
promisc = run_command("ip link | grep PROMISC")
if promisc: log(f"[DANGER] Interface in PROMISCUOUS mode!\n{promisc}", RED)
log(run_command("ss -tulpn") or "No network data.")

# 4. SYSTEM FILE INTEGRITY (PACMAN)
section_header("4. SYSTEM FILE INTEGRITY CHECK")
modified_files = run_command("pacman -Qk 2>&1 | grep -v '0 missing files'")
if modified_files: log(f"[WARNING] Modified files:\n{modified_files}", YELLOW)

# 5. PERSISTENCE & PRIVILEGES (BACKDOORS)
section_header("5. PERSISTENCE & PRIVILEGES (BACKDOORS)")
sudo_check = run_command("sudo visudo -c")
if "parsed OK" not in sudo_check: log("[DANGER] Sudoers file compromised!", RED)
log(run_command("ls -la /etc/cron* /var/spool/cron/* 2>/dev/null") or "No cron tasks.")

# 6. AUTHORIZED SSH KEYS FOR REMOTE ACCESS
section_header("6. AUTHORIZED SSH KEYS FOR REMOTE ACCESS")
ssh_keys = run_command("cat /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null")
if ssh_keys: log(f"[WARNING] Active SSH keys found:\n{ssh_keys}", RED)

# 7. FIREFOX EXTENSIONS DIRECTORY SCANNER
section_header("7. FIREFOX PROFILES & RAW EXTENSIONS (.XPI)")
home_dirs = glob.glob('/home/*')
for home in home_dirs:
    extensions = glob.glob(f"{home}/.mozilla/firefox/*.default*/extensions/*.xpi")
    if extensions:
        log(f"Extensions for {os.path.basename(home)}:", YELLOW)
        for ext in extensions: log(f"  - {os.path.basename(ext)}")

# 8. DNS HIJACKING & HOSTS INTEGRITY CHECK
section_header("8. DNS HIJACKING & HOSTS INTEGRITY CHECK")
log(run_command("cat /etc/resolv.conf | grep -E '^nameserver'") or "No nameservers.")
hosts_file = run_command("cat /etc/hosts | grep -v '^#' | grep -E '[0-9]'")
if hosts_file: log(f"Hosts file modifications:\n{hosts_file}", YELLOW)

# 9. SUID/SGID PRIVILEGE ESCALATION HUNTING
section_header("9. SUID/SGID PRIVILEGE ESCALATION HUNTING")
suid_bins = run_command("find /usr/bin /usr/sbin /bin -perm /4000 -type f 2>/dev/null | grep -E -v '(sudo|su|passwd|chfn|chsh|gpasswd|newgrp|mount|umount|pkexec)'")
if suid_bins: log(f"[WARNING] Uncommon SUID binaries:\n{suid_bins}", YELLOW)

# 10. WRITABLE TEMP DIRECTORIES MALWARE SCAN
section_header("10. WRITABLE WORLD TEMP DIRECTORIES SCAN (/tmp & /dev/shm)")
temp_scan = run_command("find /tmp /dev/shm -type f \( -name '.*' -o -perm /111 \) 2>/dev/null")
if temp_scan: log(f"[WARNING] Writable path items:\n{temp_scan}", YELLOW)

# 11. NEW: ACCOUNTS WITH EMPTY PASSWORDS
section_header("11. ACCOUNTS WITH EMPTY PASSWORDS (CRITICAL)")
empty_pass = run_command("sudo awk -F: '($2 == \"\") {print $1}' /etc/shadow")
if empty_pass:
    log(f"[DANGER] Accounts with NO PASSWORD found:\n{empty_pass}", RED, True)
else:
    log("[OK] No passwordless accounts found.", GREEN)

# 12. NEW: GHOST TUNNELS AND PROXIES (Tor/VPN/Proxy checks)
section_header("12. GHOST TUNNELS AND PROXIES (Tor / VPN)")
tunnels = run_command("ip tuntap show || ip link show | grep -E '(tun|tap|wireguard|wg|tor)'")
if tunnels:
    log(f"[WARNING] Active tunnels/VPN interfaces found:\n{tunnels}", YELLOW)
else:
    log("[OK] No suspicious hidden tunnel interfaces active.", GREEN)

# 13. NEW: INTERCEPTED AUTHENTICATION MODULES (PAM Backdoors)
section_header("13. PAM AUTHENTICATION BACKDOOR INSPECTION")
pam_mod = run_command("find /usr/lib/security/ -mtime -3 -type f 2>/dev/null")
if pam_mod:
    log(f"[DANGER] Recently changed auth modules (Potential Keylogger/Backdoor):\n{pam_mod}", RED)
else:
    log("[OK] Authentication libraries are structurally stable.", GREEN)

# 14. NEW: REJTETT FOLYAMATOK ÉS MEMÓRIA INJEKCIÓ (Process Hiding)
section_header("14. UNLINKED PROCESSES AND MEMORY INJECTION HUNTING")
# Compares /proc/ PIDs with ps output to detect hidden rootkits
pids_proc = set([pid for pid in os.listdir('/proc') if pid.isdigit()])
ps_out = run_command("ps -ef | awk '{print $2}'").splitlines()
pids_ps = set([pid for pid in ps_out if pid.isdigit()])
hidden_pids = pids_proc - pids_ps
if hidden_pids:
    log(f"[DANGER] Hidden PIDs found in /proc but invisible to ps (Rootkit Sign!): {hidden_pids}", RED, True)
else:
    log("[OK] No unlinked process anomalies detected in current execution.", GREEN)

# 15. CONFIGURATIONS MODIFIED IN THE LAST 24 HOURS
section_header("15. SYSTEM CONFIGURATIONS MODIFIED IN THE LAST 24 HOURS (/etc)")
changed_etc = run_command("find /etc -mtime -1 -type f 2>/dev/null")
if changed_etc: log(f"[WARNING] Modified files:\n{changed_etc}", YELLOW)

# 16. SUDO HISTORY & CRITICAL ERRORS
section_header("16. RECENT SYSTEM LOG ENTRIES (SUDO & CRITICAL ERRORS)")
log(run_command("journalctl _COMM=sudo -n 5 --no-pager") or "No sudo records.")
log(run_command("journalctl -b 0 -p err..emerg -n 5 --no-pager") or "No critical errors.")

log("\n============================================================", GREEN, True)
log("===       THE GOD-MODE SECURITY SIGN CHECK IS DONE       ===", GREEN, True)
log("============================================================", GREEN, True)

report_file.close()
print(f"\n{GREEN}{BOLD}[+] Finished. Comprehensive analysis written to {REPORT_PATH}{RESET}\n")
