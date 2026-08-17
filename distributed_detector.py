import re
import json
import os
import sys
import ipaddress
from datetime import datetime
from collections import defaultdict

class DistributedAttackDetector:
    def __init__(self, config_file="config.json"):
        if not os.path.exists(config_file):
            print(f"[-] Config file '{config_file}' not found.")
            sys.exit(1)

        with open(config_file, "r") as f:
            self.config = json.load(f)

        self.user_threshold = self.config.get("user_target_threshold", 3)
        self.subnet_threshold = self.config.get("subnet_failure_threshold", 4)
        self.log_file = self.config.get("log_file", "auth_simulation.log")

        # Parsing pattern for OpenSSH failed password events
        self.ssh_pattern = re.compile(
            r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
        )

    def extract_subnet(self, ip_str, prefix=24):
        try:
            net = ipaddress.ip_network(f"{ip_str}/{prefix}", strict=False)
            return str(net)
        except ValueError:
            return "UNKNOWN"

    def analyze(self):
        if not os.path.exists(self.log_file):
            print(f"[-] Log target '{self.log_file}' not found.")
            sys.exit(1)

        print("=" * 65)
        print("🛡️  Distributed SSH Brute-Force & IP Rotation Detector")
        print("=" * 65)
        print(f"[+] Analyzing log source: {self.log_file}\n")

        # Tracking stores
        targeted_users = defaultdict(set)   # user -> set of unique IPs
        subnet_activity = defaultdict(list) # subnet -> list of (IP, user)

        with open(self.log_file, "r") as f:
            for line in f:
                match = self.ssh_pattern.search(line)
                if match:
                    user = match.group("user")
                    ip = match.group("ip")
                    subnet = self.extract_subnet(ip, self.config.get("subnet_mask_prefix", 24))

                    targeted_users[user].add(ip)
                    subnet_activity[subnet].append((ip, user))

        alerts_triggered = False

        # Detection Model 1: Targeted account attacked from multiple distinct IPs (IP rotation)
        for user, ips in targeted_users.items():
            if len(ips) >= self.user_threshold:
                alerts_triggered = True
                print(f"[🚨 CRITICAL ALERT] Coordinated IP-Rotation Attack on User: '{user}'")
                print(f"    • Attacking IP Count: {len(ips)} distinct sources")
                print(f"    • Source IPs Involved: {', '.join(ips)}")
                print(f"    • Remediation: Temporarily disable password auth or enforce hardware key/MFA.\n")

        # Detection Model 2: Subnet-level clustering (attacker using adjacent IP pool)
        for subnet, events in subnet_activity.items():
            if len(events) >= self.subnet_threshold:
                unique_ips = set(ip for ip, _ in events)
                if len(unique_ips) > 1:  # Confirm multiple IPs, not just a single host
                    alerts_triggered = True
                    print(f"[⚠️ HIGH ALERT] Subnet-Level Attack Cluster Detected: {subnet}")
                    print(f"    • Total Attempts: {len(events)} from {len(unique_ips)} hosts")
                    print(f"    • Participating IPs: {', '.join(unique_ips)}")
                    print(f"    • Remediation: Apply temporary CIDR-level block rule for {subnet}.\n")

        if not alerts_triggered:
            print("[✓] Analysis complete: No distributed attack signatures detected.")

if __name__ == "__main__":
    detector = DistributedAttackDetector()
    detector.analyze()
