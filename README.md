# Arch Linux Security & Compromise Checker

A comprehensive, all-in-one digital forensics and incident response script designed specifically for Arch Linux. This tool scans system logs, active memory, network configuration, and persistence locations to find reiteterated threat indicators or signs of unauthorized access.

## Features
* **Authentication Auditing:** Checks recent successful and failed login attempts.
* **Memory & Process Analysis:** Scans for hidden, masqueraded, or deleted binaries running in RAM.
* **Network Forensic:** Inspects active ports, active sockets, and checks for unauthorized promiscuous mode.
* **System Integrity:** Verifies core system packages against the official `pacman` database.
* **Persistence & Backdoor Detection:** Scans `cron` jobs, custom `systemd` user units, modifications to startup configurations (`.bashrc` / `.zshrc`), and unauthorized SSH `authorized_keys`.
* **Browser Security:** Scans local Firefox profile directories to list raw extensions (`.xpi`).
* **Configuration Tracking:** Reports any system-wide settings modified in `/etc` within the last 24 hours.

## Prerequisites
* **Operating System:** Arch Linux
* **Python Version:** Python 3.x
* **Privileges:** Must be executed with `sudo` (root privileges) to read restricted log devices and kernel interfaces.

## Usage

1. **Download or create the script:**
   Save the main script code as `super_check.py`.

2. **Make it executable:**
   ```bash
   chmod +x super_check.py
   ```

3. **Run the script:**
   ```bash
   sudo python super_check.py
   ```

## Understanding the Output

The results are color-coded directly inside your terminal session to help you quickly filter benign events from serious issues:

* **[OK] (GREEN):** No abnormalities detected. The system configuration matches baseline assumptions.
* **[WARNING] (YELLOW):** Requires secondary manual review. This highlights altered local files or browser add-ons that might be legitimate but deserve verification.
* **[DANGER] / [WARNING] (RED):** High probability of compromise. This signals malicious parameters like hidden shell connections, network sniffing, unexpected root execution patterns, or untrusted public SSH keys.

## License
This project is licensed under the MIT License - see the `LICENSE` file for details.
