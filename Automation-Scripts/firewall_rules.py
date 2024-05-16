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
    """
    Executes a system command using PowerShell.

    Parameters:
    command (str): The command to execute.

    Raises:
    subprocess.CalledProcessError: If the command execution fails.
    """
    try:
        subprocess.run(["Powershell", "-Command", command], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {e}")
        raise

def fetch_blocklist(url: str) -> Optional[str]:
    """
    Fetches a blocklist CSV from the specified URL with retries.

    Parameters:
    url (str): The URL of the blocklist CSV.

    Returns:
    Optional[str]: The CSV data as a string, or None if fetching fails after retries.
    """
    for _ in range(MAX_RETRIES):
        try:
            return requests.get(url).text
        except Exception as e:
            logger.error(f"Error fetching: {e}")
            time.sleep(RETRY_DELAY)
    return None

def parse_csv(data: str) -> List[List[str]]:
    """
    Parses CSV data, filtering out comments and headers.

    Parameters:
    data (str): The CSV data as a string.

    Returns:
    List[List[str]]: A list of rows from the CSV data, excluding comments and headers.
    """
    return [row for row in csv.reader(data.splitlines()) if row]

def update_firewall_rule(ip: str, direction: str) -> None:
    """
    Updates a single firewall rule for the specified IP and direction.

    Parameters:
    ip (str): The IP address to update the rule for.
    direction (str): The direction of the rule ('In' or 'Out').

    Raises:
    Exception: If there's an error updating the rule.
    """
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
    """
    Orchestrates the process of updating firewall rules based on a blocklist.

    This function fetches a blocklist, parses it, and updates firewall rules for each IP.
    """
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
    """
    Entry point for the module execution. Orchestrates the rule updating process.
    """
    try:
        rule_updater()
    except Exception as e:
        logger.error(f"Unhandled error: {e}")

if __name__ == "__main__":
    main()