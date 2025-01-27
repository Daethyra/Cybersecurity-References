#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Filename: hashfile_validator.py
Author: Daethyra Carino <109057945+Daethyra@users.noreply.github.com>
Date: 2024-09-29
Version: v0.1.1
License: MIT (c) 2024 Daethyra Carino
Description: A CLI program that uses Certutil to quickly validate whether a cryptographic hash checksum matches the expected string. The program detects the hash algorithm based on the length of the user-provided provided checksum, and calculates the checksum before finally comparing the two strings.
"""

import argparse
import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

# Constants
RED, GREEN, YELLOW = 1, 2, 3
# The following hash algorithms can be automatically detected, \
# MD2 and MD4 must be manually specified with the `-a` argument
HASH_ALGORITHMS = {
    32: ("MD5", ["MD5"]),
    40: ("SHA1", ["SHA1"]),
    64: ("SHA256", ["SHA256"]),
    96: ("SHA384", ["SHA384"]),
    128: ("SHA512", ["SHA512"]),
}

def color_text(text: str, color_code: int) -> str:
    """
    Add color to text if the terminal supports it.

    Args:
        text: The text to colorize.
        color_code: The color code (1 = red, 2 = green, 3 = yellow).

    Returns:
        Colorized text if supported, otherwise plain text.
    """
    return f"\033[3{color_code}m{text}\033[0m" if sys.stdout.isatty() else text

def validate_hash(hash_value: str) -> Tuple[Optional[str], List[str]]:
    """
    Validate the hash format and suggest possible algorithms.

    Args:
        hash_value: The hash to validate.

    Returns:
        A tuple of the default algorithm and list of possible algorithms.

    Raises:
        ValueError: If the hash contains non-hexadecimal characters or has an unsupported length.
    """
    if not set(hash_value).issubset("0123456789abcdefABCDEF"):
        raise ValueError(
            "Invalid hash format. Hash should only contain hexadecimal characters."
        )

    hash_info = HASH_ALGORITHMS.get(len(hash_value))
    if hash_info is None:
        valid_lengths = sorted(HASH_ALGORITHMS.keys())
        raise ValueError(
            f"Unsupported hash length: {len(hash_value)}. "
            f"Valid hash lengths are: {', '.join(map(str, valid_lengths))}."
        )
    
    return hash_info

def run_certutil(
    file_path: str, algorithm: str, expected_hash: str, json_output: bool
) -> Dict[str, Any]:
    """
    Run certutil command and compare the hash.

    Args:
        file_path: Path to the file to hash.
        algorithm: Hash algorithm to use.
        expected_hash: Expected hash value.
        json_output: Whether to return results in JSON format.

    Returns:
        Results of the hash check as a dictionary.
    """
    if algorithm is None:
        error_msg = "Error: Unable to determine hash algorithm"
        print(color_text(error_msg, RED))
        return {"error": error_msg}

    try:
        result = subprocess.run(
            ["certutil", "-hashfile", file_path, algorithm],
            capture_output=True,
            text=True,
            check=True,
        )

        computed_hash = result.stdout.strip().split("\n")[1].strip()
        match = computed_hash.lower() == expected_hash.lower()

        results = {
            "file": file_path,
            "algorithm": algorithm,
            "expected_hash": expected_hash,
            "computed_hash": computed_hash,
            "match": match,
        }

        if not json_output:
            print(
                color_text(
                    f"{'Hash match confirmed' if match else 'Hash mismatch'} for {file_path}",
                    GREEN if match else RED,
                )
            )
            print(f"Algorithm: {algorithm}")
            print(f"Expected hash: {expected_hash}")
            print(f"Computed hash: {computed_hash}")

        return results

    except subprocess.CalledProcessError as e:
        error_msg = f"Error running certutil: {e}"
        print(color_text(error_msg, RED))
        print(f"certutil output: {e.output}")
    except FileNotFoundError:
        error_msg = "Error: certutil not found. Make sure it's installed and in your system PATH."
        print(color_text(error_msg, RED))

    return {"error": error_msg}

def get_file_info(file_path: str) -> Dict[str, Any]:
    """
    Get file information.

    Args:
        file_path: Path to the file.

    Returns:
        File information as a dictionary.
    """
    try:
        file_stats = os.stat(file_path)
        return {
            "size": file_stats.st_size,
            "last_modified": os.path.getmtime(file_path),
            "permissions": oct(file_stats.st_mode)[-3:],
        }
    except OSError as e:
        print(color_text(f"Warning: Unable to retrieve file information. {e}", YELLOW))
        return {}

def process_files(
    files: List[str],
    algorithm: str,
    expected_hash: str,
    include_info: bool,
    json_output: bool,
) -> List[Dict[str, Any]]:
    """
    Process multiple files and return results.

    Args:
        files: List of file paths to process.
        algorithm: Hash algorithm to use.
        expected_hash: Expected hash value.
        include_info: Whether to include additional file info.
        json_output: Whether to format output for JSON.

    Returns:
        List of results for each file.
    """
    results = []
    for file_path in files:
        if not os.path.exists(file_path):
            error_result = {
                "file": file_path,
                "error": f"The file '{file_path}' does not exist."
            }
            results.append(error_result)
            if not json_output:
                print(color_text(error_result["error"], RED))
            continue

        result = run_certutil(file_path, algorithm, expected_hash, json_output)

        if include_info and "error" not in result:
            result["file_info"] = get_file_info(file_path)

        results.append(result)
    return results

def main():
    """
    Main function to run the hash validation program.
    Parses command line arguments and orchestrates the hash checking process.
    """
    parser = argparse.ArgumentParser(description="Check file hash using certutil.")
    parser.add_argument("file", nargs="+", help="Path to the file(s) to check")
    parser.add_argument("hash", help="Expected hash value")
    parser.add_argument(
        "-a", "--algorithm", help="Hash algorithm to use (default: auto-detect)"
    )
    parser.add_argument(
        "-i", "--info", action="store_true", help="Display additional file information"
    )
    parser.add_argument(
        "-j", "--json", action="store_true", help="Output results in JSON format"
    )

    args = parser.parse_args()

    try:
        default_algorithm, possible_algorithms = validate_hash(args.hash)
        
        algorithm = args.algorithm if args.algorithm else default_algorithm
        
        if algorithm is None:
            raise ValueError("Could not determine hash algorithm and none was specified.")
        
        if len(possible_algorithms) > 1 and not args.json:
            print(
                color_text(
                    f"Note: Multiple algorithms possible for this hash length. Using {algorithm}.",
                    YELLOW,
                )
            )
            print(
                f"To use a different algorithm, specify with -a. Possibilities: {', '.join(possible_algorithms)}"
            )

        results = process_files(args.file, algorithm, args.hash, args.info, args.json)

        if args.json:
            print(json.dumps(results, indent=2))

    except ValueError as e:
        error_msg = f"Error: {e}"
        if args.json:
            print(json.dumps({"error": str(e)}))
        else:
            print(color_text(error_msg, RED))
        sys.exit(1)

if __name__ == "__main__":
    main()