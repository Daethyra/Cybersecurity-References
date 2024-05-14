import csv
import logging
import os
import requests
import subprocess
import time
from typing import List, Optional

# Constants and Configurations
URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
DELETE_RULE_TEMPLATE = "netsh advfirewall firewall delete rule name='BadIP_{direction}_{ip}'"
BLOCK_RULE_TEMPLATE = "netsh advfirewall firewall add rule name='BadIP_{direction}_{ip}' dir={direction} action=block remoteip={ip}"
MAX_RETRIES = int(os.getenv("MAX_RETRIES", 3))
RETRY_DELAY = int(os.getenv("RETRY_DELAY", 2))

# Logging Setup
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def execute_command(command: str) -> None:
    """Execute system command with error handling."""
    try:
        subprocess.run(["Powershell", "-Command", command], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {e}")
        raise


def fetch_blocklist(url: str) -> Optional[str]:
    """Fetch blocklist CSV with retries."""
    for _ in range(MAX_RETRIES):
        try:
            return requests.get(url).text
        except Exception as e:
            logger.error(f"Error fetching: {e}")
            time.sleep(RETRY_DELAY)
    return None


def parse_csv(data: str) -> List[List[str]]:
    """Parse CSV data, filter comments & headers."""
    return [row for row in csv.reader(data.splitlines()) if row]


def update_firewall_rule(ip: str, direction: str) -> None:
    """Update single firewall rule."""
    delete_cmd = DELETE_RULE_TEMPLATE.format(direction=direction, ip=ip)
    add_cmd = BLOCK_RULE_TEMPLATE.format(direction=direction, ip=ip)

    try:
        execute_command(delete_cmd)
        execute_command(add_cmd)
        logger.info(f"Updated {direction} rule for IP: {ip}")
    except Exception as e:
        logger.error(f"Update failed for {ip}: {e}")
        raise


def rule_updater():
    """Orchestrate update process."""
    data = fetch_blocklist(URL)
    if not data:
        logger.error("Failed to download blocklist")
        return

    rules = parse_csv(data)
    for rule in rules:
        ip = rule[1]
        if ip == "dst_ip":
            continue

        try:
            update_firewall_rule(ip, "In")
            update_firewall_rule(ip, "Out")
        except Exception as e:
            logger.error(f"Error updating rule for IP {ip}: {e}")


def main():
    """Entry point for module execution"""
    try:
        rule_updater()
    except Exception as e:
        logger.error(f"Unhandled error: {e}")


if __name__ == "__main__":
    main()
