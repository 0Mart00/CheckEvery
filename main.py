#!/usr/bin/env python3
import subprocess
import sys
import os
import glob

# ANSI Color Codes for scannability
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"

def section_header(text):
    print(f"\n{BLUE}{BOLD}{'='*60}{RESET}")
    print(f"{BLUE}{BOLD}[*] {text}{RESET}")
    print(f"{BLUE}{BOLD}{'='*60}{RESET}")

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=15)
        return result.stdout.strip()
    except Exception:
        return ""

# Enforce ROOT privileges
if os.getuid() != 0:
    print(f"{RED}{BOLD}[!] ERROR: This script must be run with ROOT privileges (sudo)!{RESET}")
    sys.exit(1)

print(f"{GREEN}{BOLD}============================================================")
print("===     ARCH LINUX MAXIMUM SECURITY & COMPROMISE CHECK   ===")
print(f"============================================================{RESET}")

# 1. SYSTEM LOGS (SUCCESSFUL / FAILED LOGINS)
section_header("1. SYSTEM LOGS (SUCCESSFUL / FAILED LOGINS)")
print(f"{BOLD}Last successful logins (last):{RESET}")
print(run_command("last -n 10") or "No login data available.")

print(f"\n{RED}{BOLD}Failed login attempts (lastb - SUSPICIOUS!):{RESET}")
lastb_res = run_command("lastb -n 15")
if lastb_res:
    print(f"{RED}{lastb_res}{RESET}")
else:
    print(f"{GREEN}[OK] No failed login attempts found (lastb is clean).{RESET}")

# 2. SUSPICIOUS PROCESSES IN MEMORY
section_header("2. HIDDEN OR SUSPICIOUS PROCESSES IN MEMORY")
suspicious_procs = run_command("ps aux | grep -E '(bash|sh|python|perl|php|nc|netcat|ncat).*[0-9]' | grep -v grep")
if suspicious_procs:
    print(f"{RED}[WARNING] Suspicious network/shell processes running:\n{suspicious_procs}{RESET}")
else:
    print(f"{GREEN}[OK] No suspicious active processes found by name.{RESET}")

# Deleted binaries still running in memory (Common malware trick)
deleted_procs = run_command("ls -la /proc/*/exe 2>/dev/null | grep 'deleted'")
if deleted_procs:
    print(f"{RED}[DANGER] Processes running from DELETED executable files:\n{deleted_procs}{RESET}")
else:
    print(f"{GREEN}[OK] No deleted processes running in memory.{RESET}")

# 3. NETWORK CONNECTIONS & PROMISCUOUS MODE
section_header("3. NETWORK CONNECTIONS & PROMISCUOUS MODE CHECK")
promisc = run_command("ip link | grep PROMISC")
if promisc:
    print(f"{RED}[DANGER] Network interface is in PROMISCUOUS (sniffing) mode!\n{promisc}{RESET}")
else:
    print(f"{GREEN}[OK] Network interfaces are operating in normal mode.{RESET}")

print(f"\n{BOLD}Active network connections and listening ports (ss):{RESET}")
print(run_command("ss -tulpn") or "No network connection data available.")

# 4. SYSTEM FILE INTEGRITY (PACMAN)
section_header("4. SYSTEM FILE INTEGRITY CHECK")
print("Verifying pacman database (this might take a few seconds)...")
modified_files = run_command("pacman -Qk 2>&1 | grep -v '0 missing files'")
if modified_files:
    print(f"{YELLOW}[WARNING] Modified or missing system files found:\n{modified_files}{RESET}")
else:
    print(f"{GREEN}[OK] All default Arch Linux package files are intact.{RESET}")

# 5. PERSISTENCE & PRIVILEGES (BACKDOORS)
section_header("5. PERSISTENCE & PRIVILEGES (BACKDOORS)")
# Sudoers integrity
sudo_check = run_command("sudo visudo -c")
if "parsed OK" in sudo_check:
    print(f"{GREEN}[OK] The /etc/sudoers file structure is intact.{RESET}")
else:
    print(f"{RED}[DANGER] Problem detected with the sudoers file, or it was modified!{RESET}")

sudoers_dir = run_command("ls -la /etc/sudoers.d/ 2>/dev/null")
print(f"\n{BOLD}Contents of /etc/sudoers.d/ directory (Only 'README' is default):{RESET}\n{sudoers_dir}")

# Scheduled tasks (Cron)
print(f"\n{BOLD}System-wide Cron (scheduled) tasks:{RESET}")
print(run_command("ls -la /etc/cron* /var/spool/cron/* 2>/dev/null") or "No scheduled cron tasks found.")

# User startup files modification
rc_changes = run_command("find /home/ -maxdepth 2 -name '.*rc' -mtime -2 2>/dev/null")
if rc_changes:
    print(f"{YELLOW}[WARNING] User configuration files (.bashrc/.zshrc) modified in the last 48 hours:\n{rc_changes}{RESET}")
else:
    print(f"{GREEN}[OK] Startup shell configurations have not changed recently.{RESET}")

# 6. AUTHORIZED SSH KEYS FOR REMOTE ACCESS
section_header("6. AUTHORIZED SSH KEYS FOR REMOTE ACCESS")
ssh_keys = run_command("cat /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null")
if ssh_keys:
    print(f"{RED}[WARNING] Active SSH keys found on the system (Verify if they belong to you!):\n{ssh_keys}{RESET}")
else:
    print(f"{GREEN}[OK] No hidden SSH keys found for remote backdoor access.{RESET}")

# 7. FIREFOX EXTENSIONS DIRECTORY SCANNER
section_header("7. FIREFOX PROFILES & RAW EXTENSIONS (.XPI)")
home_dirs = glob.glob('/home/*')
found_extensions = False
for home in home_dirs:
    ext_path = f"{home}/.mozilla/firefox/*.default*/extensions/*.xpi"
    extensions = glob.glob(ext_path)
    if extensions:
        found_extensions = True
        print(f"{YELLOW}Installed raw extensions for user ({os.path.basename(home)}):{RESET}")
        for ext in extensions:
            print(f"  - {os.path.basename(ext)}")
if not found_extensions:
    print(f"{GREEN}[OK] No raw Firefox extension files found in standard profile directories.{RESET}")

# 8. CONFIGURATIONS MODIFIED IN THE LAST 24 HOURS (/etc)
section_header("8. SYSTEM CONFIGURATIONS MODIFIED IN THE LAST 24 HOURS (/etc)")
changed_etc = run_command("find /etc -mtime -1 -type f 2>/dev/null")
if changed_etc:
    print(f"{YELLOW}[WARNING] Files modified in /etc within the last 24 hours:\n{changed_etc}{RESET}")
else:
    print(f"{GREEN}[OK] No configuration files changed in /etc in the past 24 hours.{RESET}")

# 9. SUDO HISTORY & CRITICAL ERRORS (JOURNALCTL)
section_header("9. RECENT SYSTEM LOG ENTRIES (SUDO & CRITICAL ERRORS)")
print(f"{BOLD}Last actions executed via sudo:{RESET}")
print(run_command("journalctl _COMM=sudo -n 10 --no-pager") or "No records found.")

print(f"\n{YELLOW}{BOLD}Recent critical system errors (err..emerg):{RESET}")
print(run_command("journalctl -b 0 -p err..emerg -n 10 --no-pager") or "No critical errors logged.")

print(f"\n{GREEN}{BOLD}============================================================")
print("===       THE COMPREHENSIVE SECURITY SIGN CHECK IS DONE  ===")
print(f"============================================================{RESET}\n")
