#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Filename: hashfile_validator.py
Author: Daethyra Carino <109057945+Daethyra@users.noreply.github.com>
Date: 2025-02-22
Version: v0.2.0
License: MIT (c) 2024 Daethyra Carino
Description: A CLI program that uses hashlib to quickly validate whether a cryptographic hash checksum matches the expected string. The program detects the hash algorithm based on the length of the user-provided checksum, calculates the checksum, and compares the two strings.
"""

import argparse
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

# Constants
RED, GREEN, YELLOW = 1, 2, 3
# Supported hash algorithms for auto-detection (must be lowercase)
HASH_ALGORITHMS = {
    32: ("md5", ["md5"]),
    40: ("sha1", ["sha1"]),
    64: ("sha256", ["sha256"]),
    96: ("sha384", ["sha384"]),
    128: ("sha512", ["sha512"]),
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

def compute_hash(file_path: str, algorithm: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Compute the hash of a file using hashlib.

    Args:
        file_path: Path to the file.
        algorithm: The hash algorithm to use (must be lowercase).

    Returns:
        Tuple (error_message, computed_hash). If error occurs, error_message is a string 
        and computed_hash is None. Otherwise, error is None and computed_hash is the hash string.
    """
    try:
        hash_obj = hashlib.new(algorithm)
    except ValueError as e:
        return (f"Unsupported hash algorithm: {algorithm}. Error: {e}", None)
    
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                hash_obj.update(chunk)
        return (None, hash_obj.hexdigest())
    except IOError as e:
        return (f"Error reading file {file_path}: {e}", None)

def run_hashlib(
    file_path: str, algorithm: str, expected_hash: str, json_output: bool
) -> Dict[str, Any]:
    """
    Compute hash using hashlib and compare with expected hash.

    Args:
        file_path: Path to the file to hash.
        algorithm: Hash algorithm to use.
        expected_hash: Expected hash value.
        json_output: Whether to return results in JSON format.

    Returns:
        Results of the hash check as a dictionary.
    """
    error_msg, computed_hash = compute_hash(file_path, algorithm)
    if error_msg:
        print(color_text(error_msg, RED))
        return {"error": error_msg}
    if computed_hash is None:
        error_msg = "Hash computation failed"
        print(color_text(error_msg, RED))
        return {"error": error_msg}
    
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

        result = run_hashlib(file_path, algorithm, expected_hash, json_output)

        if include_info and "error" not in result:
            result["file_info"] = get_file_info(file_path)

        results.append(result)
    return results

def main():
    """
    Main function to run the hash validation program.
    Parses command line arguments and orchestrates the hash checking process.
    """
    parser = argparse.ArgumentParser(description="Validate file hashes using hashlib.")
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
        print(f"Attempting hash algorithm detection for {args.hash}...")
        default_algorithm, possible_algorithms = validate_hash(args.hash)
        
        # Convert user-provided algorithm to lowercase if specified
        if args.algorithm:
            algorithm = args.algorithm.lower()
            print(
                color_text(
                    f"User-specified algorithm: {algorithm}",
                    YELLOW,
                    )
                )
        else:
            algorithm = default_algorithm
            print(
                color_text(
                    f"Detected {algorithm} based on length. To use a different algorithm, specify with -a.",
                    YELLOW,
                )
            )
        
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

        print(f"---> Attempting hash validation using {algorithm}...")
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