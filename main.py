#!/usr/bin/env python3
import subprocess
import sys
import os
import glob
import re
import urllib.request
import json
from datetime import datetime

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
    """Prints to terminal with color and strips ANSI codes for the text report file."""
    prefix = BOLD if is_bold else ""
    print(f"{color}{prefix}{text}{RESET}")
    # Strip ANSI colors using regex before writing to file
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

# Enforce ROOT privileges
if os.getuid() != 0:
    print(f"{RED}{BOLD}[!] ERROR: This script must be run with ROOT privileges (sudo)!{RESET}")
    sys.exit(1)

log("============================================================", GREEN, True)
log("===     ARCH LINUX ULTIMATE FORENSICS & OSINT CHECKER    ===", GREEN, True)
log("============================================================", GREEN, True)

my_country = get_current_country()
log(f"[i] Baseline country code set to: {my_country}", BLUE)
log(f"[i] Forensic report will be saved to: {REPORT_PATH}\n", BLUE)

# 1. SYSTEM LOGS & OSINT GEOLOCATION ANOMALIES
section_header("1. SYSTEM LOGS & OSINT IP ANOMALY DETECTION")
log("Analyzing last successful logins and hunting for anomalies...")

last_output = run_command("last -i -n 10")
if last_output:
    log("\nRecent Logins & OSINT Location Analysis:", RESET, True)
    ips = list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', last_output)))
    for ip in ips:
        info = get_ip_info(ip)
        if info and info.get("status") == "success":
            country = info.get("country", "Unknown")
            cc = info.get("countryCode", "UNKNOWN")
            city = info.get("city", "Unknown")
            isp = info.get("org", "Unknown")
            
            if cc != "LOCAL" and cc != my_country:
                log(f"  - IP: \033[91m{ip}\033[0m -> \033[91m\033[1m[ANOMALY DETECTED]\033[0m Location: \033[91m{city}, {country}\033[0m | ISP: \033[93m{isp}\033[0m (Unlikely login origin!)")
            else:
                log(f"  - IP: \033[92m{ip}\033[0m -> Location: \033[92m{city}, {country}\033[0m | ISP: {isp}")
        else:
            log(f"  - IP: {ip} -> Location data unavailable or Local LAN.")
else:
    log("No login data available.")

log(f"\nFailed login attempts (lastb - Targets for OSINT Tracing):", RED, True)
lastb_res = run_command("lastb -i -n 10")
if lastb_res:
    log(lastb_res, RED)
    failed_ips = list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', lastb_res)))
    log(f"\n[*] Geolocation of attackers trying to brute-force you:", YELLOW, True)
    for f_ip in failed_ips:
        f_info = get_ip_info(f_ip)
        if f_info and f_info.get("status") == "success":
            log(f"  - Attacker IP: \033[91m{f_ip}\033[0m -> \033[93m{f_info.get('city')}, {f_info.get('country')}\033[0m [ISP: {f_info.get('org')}]")
else:
    log("[OK] No failed login attempts found (lastb is clean).", GREEN)

# 2. SUSPICIOUS PROCESSES IN MEMORY
section_header("2. HIDDEN OR SUSPICIOUS PROCESSES IN MEMORY")
suspicious_procs = run_command("ps aux | grep -E '(bash|sh|python|perl|php|nc|netcat|ncat).*[0-9]' | grep -v grep")
if suspicious_procs:
    log(f"[WARNING] Suspicious network/shell processes running:\n{suspicious_procs}", RED)
else:
    log("[OK] No suspicious active processes found by name.", GREEN)

deleted_procs = run_command("ls -la /proc/*/exe 2>/dev/null | grep 'deleted'")
if deleted_procs:
    log(f"[DANGER] Processes running from DELETED executable files:\n{deleted_procs}", RED)
else:
    log("[OK] No deleted processes running in memory.", GREEN)

# 3. NETWORK CONNECTIONS & PROMISCUOUS MODE
section_header("3. NETWORK CONNECTIONS & PROMISCUOUS MODE CHECK")
promisc = run_command("ip link | grep PROMISC")
if promisc:
    log(f"[DANGER] Network interface is in PROMISCUOUS (sniffing) mode!\n{promisc}", RED)
else:
    log("[OK] Network interfaces are operating in normal mode.", GREEN)

log("\nActive network connections and listening ports (ss):", RESET, True)
log(run_command("ss -tulpn") or "No network connection data available.")

# 4. SYSTEM FILE INTEGRITY (PACMAN)
section_header("4. SYSTEM FILE INTEGRITY CHECK")
log("Verifying pacman database (this might take a few seconds)...")
modified_files = run_command("pacman -Qk 2>&1 | grep -v '0 missing files'")
if modified_files:
    log(f"[WARNING] Modified or missing system files found:\n{modified_files}", YELLOW)
else:
    log("[OK] All default Arch Linux package files are intact.", GREEN)

# 5. PERSISTENCE & PRIVILEGES (BACKDOORS)
section_header("5. PERSISTENCE & PRIVILEGES (BACKDOORS)")
sudo_check = run_command("sudo visudo -c")
if "parsed OK" in sudo_check:
    log("[OK] The /etc/sudoers file structure is intact.", GREEN)
else:
    log("[DANGER] Problem detected with the sudoers file, or it was modified!", RED)

sudoers_dir = run_command("ls -la /etc/sudoers.d/ 2>/dev/null")
log(f"\nContents of /etc/sudoers.d/ directory (Only 'README' is default):\n{sudoers_dir}", RESET, True)

log("\nSystem-wide Cron (scheduled) tasks:", RESET, True)
log(run_command("ls -la /etc/cron* /var/spool/cron/* 2>/dev/null") or "No scheduled cron tasks found.")

rc_changes = run_command("find /home/ -maxdepth 2 -name '.*rc' -mtime -2 2>/dev/null")
if rc_changes:
    log(f"[WARNING] User configuration files (.bashrc/.zshrc) modified in the last 48 hours:\n{rc_changes}", YELLOW)
else:
    log("[OK] Startup shell configurations have not changed recently.", GREEN)

# 6. AUTHORIZED SSH KEYS FOR REMOTE ACCESS
section_header("6. AUTHORIZED SSH KEYS FOR REMOTE ACCESS")
ssh_keys = run_command("cat /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null")
if ssh_keys:
    log(f"[WARNING] Active SSH keys found on the system (Verify if they belong to you!):\n{ssh_keys}", RED)
else:
    log("[OK] No hidden SSH keys found for remote backdoor access.", GREEN)

# 7. FIREFOX EXTENSIONS DIRECTORY SCANNER
section_header("7. FIREFOX PROFILES & RAW EXTENSIONS (.XPI)")
home_dirs = glob.glob('/home/*')
found_extensions = False
for home in home_dirs:
    ext_path = f"{home}/.mozilla/firefox/*.default*/extensions/*.xpi"
    extensions = glob.glob(ext_path)
    if extensions:
        found_extensions = True
        log(f"Installed raw extensions for user ({os.path.basename(home)}):", YELLOW)
        for ext in extensions:
            log(f"  - {os.path.basename(ext)}")
if not found_extensions:
    log("[OK] No raw Firefox extension files found in standard profile directories.", GREEN)

# 8. NEW: DNS HIJACKING & HOSTS INTEGRITY CHECK
section_header("8. DNS HIJACKING & HOSTS INTEGRITY CHECK")
log("Current DNS Nameservers (/etc/resolv.conf):", RESET, True)
resolv_conf = run_command("cat /etc/resolv.conf | grep -E '^nameserver'")
log(resolv_conf or "No active nameservers found.")

log("\nLocal Hosts file overloads (/etc/hosts):", RESET, True)
hosts_file = run_command("cat /etc/hosts | grep -v '^#' | grep -E '[0-9]'")
log(hosts_file or "No overrides found in hosts file.")

# 9. NEW: SUID/SGID PRIVILEGE ESCALATION HUNTING
section_header("9. SUID/SGID PRIVILEGE ESCALATION HUNTING")
log("Scanning for non-standard SUID root binaries in common execution targets...")
suid_bins = run_command("find /usr/bin /usr/sbin /bin -perm /4000 -type f 2>/dev/null | grep -E -v '(sudo|su|passwd|chfn|chsh|gpasswd|newgrp|mount|umount|pkexec)'")
if suid_bins:
    log(f"[WARNING] Uncommon SUID binaries detected (Potential privilege escalation backdoors):\n{suid_bins}", YELLOW)
else:
    log("[OK] No anomalous standard path SUID backdoors found.", GREEN)

# 10. NEW: WRITABLE TEMP DIRECTORIES MALWARE SCAN
section_header("10. WRITABLE WORLD TEMP DIRECTORIES SCAN (/tmp & /dev/shm)")
log("Scanning for hidden or executable files in volatile temporary paths...")
temp_scan = run_command("find /tmp /dev/shm -type f \( -name '.*' -o -perm /111 \) 2>/dev/null")
if temp_scan:
    log(f"[WARNING] Hidden or executable transient files located in shared buffers:\n{temp_scan}", YELLOW)
else:
    log("[OK] Temp folders are clear of obvious staged threats.", GREEN)

# 11. CONFIGURATIONS MODIFIED IN THE LAST 24 HOURS (/etc)
section_header("11. SYSTEM CONFIGURATIONS MODIFIED IN THE LAST 24 HOURS (/etc)")
changed_etc = run_command("find /etc -mtime -1 -type f 2>/dev/null")
if changed_etc:
    log(f"[WARNING] Files modified in /etc within the last 24 hours:\n{changed_etc}", YELLOW)
else:
    log("[OK] No configuration files changed in /etc in the past 24 hours.", GREEN)

# 12. SUDO HISTORY & CRITICAL ERRORS (JOURNALCTL)
section_header("12. RECENT SYSTEM LOG ENTRIES (SUDO & CRITICAL ERRORS)")
log("Last actions executed via sudo:", RESET, True)
