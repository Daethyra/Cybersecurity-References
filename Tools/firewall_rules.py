"""
Filename: firewall_rules.py
Author: Daethyra Carino <109057945+Daethyra@users.noreply.github.com>
Date: 2025-01-26
Version: v1.0.0
License: MIT (c) 2025 Daethyra Carino
Short Description: Cross-platform firewall rule manager that automatically blocks malicious IPs from FeodoTracker's blocklist, supporting bulk updates for Windows (netsh) and Linux (iptables) with retry logic and rule synchronization.
"""

import csv
import logging
import os
import platform
import re
import subprocess
import time
from typing import Optional, Set

import requests

# Constants and Configurations
URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
MAX_RETRIES = int(os.getenv("MAX_RETRIES", 3))
RETRY_DELAY = int(os.getenv("RETRY_DELAY", 2))
RULE_NAME = "FeodoBadIP"
COMMENT = "FeodoTrackerBlocklist"

# Logging Setup
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

class FirewallCommandGenerator:
    """Base class for firewall command generators with bulk IP support"""
    def get_current_ips(self, direction: str) -> Set[str]:
        raise NotImplementedError()
    
    def update_rule(self, ips: Set[str], direction: str) -> None:
        raise NotImplementedError()

class WindowsFirewallCommandGenerator(FirewallCommandGenerator):
    """Manages Windows firewall rules using netsh with bulk IP support"""
    def get_current_ips(self, direction: str) -> Set[str]:
        try:
            output = subprocess.check_output(
                ["netsh", "advfirewall", "firewall", "show", "rule", 
                 f"name={RULE_NAME}_{direction}"], 
                text=True
            )
            match = re.search(r'RemoteIP:\s*(.+?)\s*LocalIP:', output, re.DOTALL)
            return set(match.group(1).split(',')) if match else set()
        except subprocess.CalledProcessError:
            return set()

    def update_rule(self, ips: Set[str], direction: str) -> None:
        if not ips:
            return

        # Delete existing rule if it exists
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule",
             f"name={RULE_NAME}_{direction}"],
            stderr=subprocess.DEVNULL
        )

        # Create new rule with all IPs
        ip_list = ','.join(ips)
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={RULE_NAME}_{direction}",
            "dir=in" if direction == "In" else "dir=out",
            "action=block",
            f"remoteip={ip_list}"
        ], check=True)

class LinuxFirewallCommandGenerator(FirewallCommandGenerator):
    """Manages Linux iptables rules with bulk IP support"""
    def get_current_ips(self, direction: str) -> Set[str]:
        chain = "INPUT" if direction == "In" else "OUTPUT"
        try:
            output = subprocess.check_output(
                ["iptables-save"], 
                text=True
            )
            pattern = re.compile(
                fr"-A {chain} -s (\d+\.\d+\.\d+\.\d+) -m comment --comment {COMMENT} -j DROP"
            )
            return set(pattern.findall(output))
        except subprocess.CalledProcessError:
            return set()

    def update_rule(self, ips: Set[str], direction: str) -> None:
        chain = "INPUT" if direction == "In" else "OUTPUT"
        
        # Remove existing rules
        subprocess.run([
            "sh", "-c",
            f"iptables-save | grep -v '{COMMENT}' | iptables-restore"
        ], stderr=subprocess.DEVNULL)

        # Add new rules
        for ip in ips:
            subprocess.run([
                "iptables", "-A", chain,
                "-s", ip,
                "-m", "comment", "--comment", COMMENT,
                "-j", "DROP"
            ], check=True)

def get_command_generator() -> FirewallCommandGenerator:
    """Returns the appropriate command generator based on the OS"""
    os_type = platform.system().lower()
    if os_type == 'windows':
        return WindowsFirewallCommandGenerator()
    elif os_type == 'linux':
        return LinuxFirewallCommandGenerator()
    raise NotImplementedError(f"OS {os_type} is not supported")

def fetch_blocklist(url: str) -> Optional[Set[str]]:
    """Fetches and parses blocklist returning a set of IPs"""
    for _ in range(MAX_RETRIES):
        try:
            response = requests.get(url)
            response.raise_for_status()
            reader = csv.reader(response.text.splitlines())
            return {row[1] for row in reader if row and not row[0].startswith('#') and row[1] != 'dst_ip'}
        except Exception as e:
            logger.error(f"Error fetching: {e}")
            time.sleep(RETRY_DELAY)
    return None

def update_firewall_rules(ips: Set[str]) -> None:
    """Updates firewall rules for both directions with the given IP set"""
    cmd_generator = get_command_generator()
    
    for direction in ["In", "Out"]:
        try:
            current_ips = cmd_generator.get_current_ips(direction)
            if current_ips != ips:
                logger.info(f"Updating {direction} rules with {len(ips)} IPs")
                cmd_generator.update_rule(ips, direction)
                logger.info(f"Updated {direction} rules successfully")
            else:
                logger.info(f"{direction} rules already up-to-date")
        except Exception as e:
            logger.error(f"Failed updating {direction} rules: {e}")
            raise

def rule_updater():
    """Main rule update workflow"""
    ips = fetch_blocklist(URL)
    if not ips:
        logger.error("Failed to download blocklist")
        return
    
    logger.info(f"Processing {len(ips)} IP addresses")
    update_firewall_rules(ips)

def main():
    """Entry point for script execution"""
    try:
        rule_updater()
    except Exception as e:
        logger.error(f"Unhandled error: {e}")

if __name__ == "__main__":
    main()