import subprocess
import re
import time
import csv
import os
from collections import defaultdict

# --- CONFIGURATION ---
THRESHOLD = 5               # Max failed attempts allowed
TIME_WINDOW = 60            # Time window in seconds
WHITELIST = {"127.0.0.1"}   # Trusted IPs that won't lock you out during demo
CSV_FILE = "incident_report.csv"

failed_attempts = defaultdict(list)
blocked_ips = set()

def init_csv():
    """Creates the CSV report file with headers if it doesn't exist."""
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Attacker_IP", "Username_Tried", "Severity", "Action_Taken"])

def send_desktop_alert(title, message):
    """Triggers a reliable Kali desktop pop-up notification + audible terminal bell."""
    print("\a", end="", flush=True)
    try:
        subprocess.run(
            ["sudo", "-u", "kali", "DISPLAY=:0", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
             "notify-send", "-u", "critical", title, message],
            check=False, stderr=subprocess.DEVNULL
        )
    except Exception:
        pass

def block_ip(ip):
    """Blocks the attacker IP using iptables firewall (unless whitelisted)."""
    if ip in WHITELIST:
        return "ALERT ONLY (Whitelisted IP)"
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=False)
    return "BLOCKED VIA FIREWALL"

def unblock_ip():
    """Allows the admin to manually unblock an IP from the firewall."""
    ip = input("\nEnter the IP address to unblock: ").strip()
    if ip in blocked_ips:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=False)
        blocked_ips.remove(ip)
        print(f"\033[92m[+] Successfully unblocked IP: {ip}\033[0m\n")
    else:
        print(f"\033[93m[!] IP {ip} is not currently in the active block list.\033[0m\n")

def manage_whitelist():
    """Allows viewing and adding trusted IPs to the Whitelist."""
    print(f"\nCurrent Whitelisted IPs: {', '.join(WHITELIST)}")
    new_ip = input("Enter a new IP to trust (or press Enter to go back): ").strip()
    if new_ip:
        WHITELIST.add(new_ip)
        print(f"\033[92m[+] Added {new_ip} to Whitelist!\033[0m\n")

def log_incident(ip, user, severity, action):
    """Saves attack details to the Excel-ready CSV file."""
    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), ip, user, severity, action])

def start_monitoring():
    init_csv()
    print("\n\033[96m[*] Starting Live SSH Intrusion Detection & Prevention...\033[0m")
    print(f"[*] Rule: {THRESHOLD} failed attempts within {TIME_WINDOW} seconds")
    print(f"[*] Safe Whitelist: {', '.join(WHITELIST)}")
    print("[*] Press Ctrl+C anytime to return to the main menu.\n")

    process = subprocess.Popen(
        ["sudo", "journalctl", "-u", "ssh", "-f", "-n", "0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    try:
        for line in process.stdout:
            if "Failed password" in line:
                ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                user_match = re.search(r"for (?:invalid user )?(\S+) from", line)

                if ip_match:
                    ip = ip_match.group(1)
                    user = user_match.group(1) if user_match else "unknown"
                    now = time.time()

                    failed_attempts[ip].append(now)
                    failed_attempts[ip] = [t for t in failed_attempts[ip] if now - t <= TIME_WINDOW]
                    count = len(failed_attempts[ip])

                    print(f"\033[93m[!] Failed login | IP: {ip} | User: {user} | Attempt: {count}/{THRESHOLD}\033[0m")

                    if count >= THRESHOLD and ip not in blocked_ips:
                        blocked_ips.add(ip)
                        severity = "CRITICAL (Root/Admin Target)" if user in ["root", "admin"] else "HIGH (Brute Force)"
                        action = block_ip(ip)

                        print("\n" + "="*62)
                        print(f"\033[91m[SECURITY ALERT] SSH BRUTE FORCE DETECTED!\033[0m")
                        print(f" -> Attacker IP : {ip}")
                        print(f" -> Target User : {user}")
                        print(f" -> Risk Level  : {severity}")
                        print(f" -> Action      : {action}")
                        print("="*62 + "\n")

                        send_desktop_alert("SSH Brute Force Detected!", f"IP {ip} targeted '{user}' ({count} failures)")
                        log_incident(ip, user, severity, action)

    except KeyboardInterrupt:
        process.terminate()
        print("\n[*] Monitoring stopped. Returning to menu...\n")

def view_reports():
    print("\n--- SAVED INCIDENT REPORTS (incident_report.csv) ---")
    if not os.path.exists(CSV_FILE):
        print("No attacks recorded yet.\n")
        return
    with open(CSV_FILE, "r") as f:
        print(f.read())

def main_menu():
    while True:
        print("\033[92m==================================================")
        print("   SSH BRUTE FORCE DETECTOR & IPS CONSOLE v3.0")
        print("==================================================\033[0m")
        print("1. Start Real-Time SSH Monitoring")
        print("2. View Incident Report (CSV)")
        print("3. Unblock an IP Address")
        print("4. Manage Safe Whitelist")
        print("5. Exit")
        choice = input("\nSelect an option (1-5): ").strip()

        if choice == "1":
            start_monitoring()
        elif choice == "2":
            view_reports()
        elif choice == "3":
            unblock_ip()
        elif choice == "4":
            manage_whitelist()
        elif choice == "5":
            print("Exiting. Stay safe!")
            break
        else:
            print("Invalid option. Please enter a number from 1 to 5.\n")

if __name__ == "__main__":
    main_menu()
