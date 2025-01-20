#!/usr/bin/env python3

import os
import sys
import json
import argparse
import datetime
import requests
import subprocess
import jsbeautifier

from tqdm import tqdm
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# ================
#    CONFIG
# ================
USER_AGENT = "JS-Snitch/0.1 (vavkamil/js-snitch) https://github.com/vavkamil/js-snitch"
OUTPUT_DIR = "output"
FILENAME_FORMAT = "{domain}_{timestamp}"  # domain_%Y-%m-%d_%H_%M_%S
SEMGREP_RULES = [
    "r/generic.secrets",
    "custom-semgrep-templates",
]
# ================


def banner():
    print(
        """
    ▗▖ ▗▄▄▖     ▗▄▄▖▗▖  ▗▖▗▄▄▄▖▗▄▄▄▖▗▄▄▖▗▖ ▗▖
    ▐▌▐▌       ▐▌   ▐▛▚▖▐▌  █    █ ▐▌   ▐▌ ▐▌
    ▐▌ ▝▀▚▖     ▝▀▚▖▐▌ ▝▜▌  █    █ ▐▌   ▐▛▀▜▌
 ▗▄▄▞▘▗▄▄▞▘    ▗▄▄▞▘▐▌  ▐▌▗▄█▄▖  █ ▝▚▄▄▖▐▌ ▐▌v0.1\n"""
    )


def check_dependency(command, name, verbose=False):
    """
    Checks if the given command is available in PATH.
    Returns its --version output as a string if installed.
    Exits the script if not installed.
    If verbose=False, it won't print the version string; it only
    fails if the dependency is missing.
    """
    try:
        result = subprocess.run(
            [command, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        # Try stdout first; if empty, fallback to stderr
        version_str = result.stdout.strip()
        if not version_str:
            version_str = result.stderr.strip()

        if verbose:
            print(f"[i] {name} version: {version_str}")
        return version_str
    except Exception:
        print(f"[-] {name} is not installed or not found in PATH.")
        sys.exit(1)


def extract_js_files(url):
    """
    Fetches the HTML from the given URL, parses out all .js script tags,
    and returns a list of full URLs to those JS files.
    """
    try:
        response = requests.get(
            url,
            timeout=5,
            headers={"User-Agent": USER_AGENT},
        )
        response.raise_for_status()
    except Exception:
        return []

    soup = BeautifulSoup(response.text, "html.parser")
    script_tags = soup.find_all("script")

    js_urls = []
    for tag in script_tags:
        src = tag.get("src")
        if src and src.endswith(".js"):
            full_url = urljoin(url, src)
            js_urls.append(full_url)

    return js_urls


def download_and_beautify(js_url, tmp_dir, beautify_dir):
    """
    Downloads a JS file from js_url, writes the raw file to tmp_dir,
    then beautifies it with jsbeautifier and saves it to beautify_dir.
    """
    try:
        # Remove query parameters from URL
        clean_url = js_url.split("?")[0]

        # Get base filename or use default
        filename = os.path.basename(clean_url)
        if not filename or not filename.endswith(".js"):
            # Generate unique name using timestamp
            timestamp = datetime.datetime.now().strftime("%H%M%S")
            filename = f"script_{timestamp}.js"

        # Ensure unique filenames in both directories
        tmp_file_path = get_unique_path(os.path.join(tmp_dir, filename))
        beautify_file_path = get_unique_path(os.path.join(beautify_dir, filename))

        response = requests.get(
            js_url,
            timeout=5,
            headers={"User-Agent": USER_AGENT},
        )
        response.raise_for_status()

        # Save raw file
        with open(tmp_file_path, "wb") as f:
            f.write(response.content)

        # Beautify and save
        beautifier_options = jsbeautifier.default_options()
        beautifier_options.indent_size = 2

        with open(tmp_file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        beautified_content = jsbeautifier.beautify(content, beautifier_options)

        with open(beautify_file_path, "w", encoding="utf-8") as f:
            f.write(beautified_content)

    except Exception:
        pass


def get_unique_path(file_path):
    """
    Ensures a unique file path by appending a counter if needed.
    """
    if not os.path.exists(file_path):
        return file_path

    base, ext = os.path.splitext(file_path)
    counter = 1
    while os.path.exists(f"{base}_{counter}{ext}"):
        counter += 1
    return f"{base}_{counter}{ext}"


def parse_trufflehog_json(file_path):
    """
    Returns a list of dictionaries, each containing:
    {
      'filename': ...,
      'detector_name': ...,
      'verified': ...,
      'raw': ...
    }
    """
    secrets = []
    if not os.path.isfile(file_path):
        return secrets

    with open(file_path, "r", encoding="utf-8", errors="replace") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                filename = (
                    data.get("SourceMetadata", {})
                    .get("Data", {})
                    .get("Filesystem", {})
                    .get("file", "")
                )
                detector_name = data.get("DetectorName", "")
                verified = data.get("Verified", False)
                raw = data.get("Raw", "")

                secrets.append(
                    {
                        "filename": filename,
                        "detector_name": detector_name,
                        "verified": verified,
                        "raw": raw,
                    }
                )
            except json.JSONDecodeError:
                continue

    return secrets


def parse_semgrep_json(file_path):
    """
    Returns a list of dictionaries, each containing:
    {
      "path": ...,
      "check_id": ...,
      "severity": ...,
      "message": ...,
      "lines": ...
    }
    """
    findings = []
    if not os.path.isfile(file_path):
        return findings

    with open(file_path, "r", encoding="utf-8", errors="replace") as infile:
        try:
            data = json.load(infile)
        except json.JSONDecodeError:
            return findings

    if data.get("results"):
        for result in data["results"]:
            path = result.get("path", "")
            check_id = result.get("check_id", "")
            severity = result.get("extra", {}).get("severity", "")
            message = result.get("extra", {}).get("message", "")
            lines = result.get("extra", {}).get("lines", "")

            findings.append(
                {
                    "path": path,
                    "check_id": check_id,
                    "severity": severity,
                    "message": message,
                    "lines": lines,
                }
            )
    return findings


def save_combined_findings(trufflehog_secrets, semgrep_findings, output_path):
    """
    Writes both Trufflehog and Semgrep results into a single text file
    in a simpler, unified format.
    """
    with open(output_path, "w", encoding="utf-8") as file:
        # -- Trufflehog secrets --
        file.write("Trufflehog secrets:\n\n")
        if not trufflehog_secrets:
            file.write("(None)\n\n")
        else:
            for secret in trufflehog_secrets:
                file.write(f"filename: {secret['filename']}\n")
                file.write(
                    f"DetectorName: {secret['detector_name']} "
                    f"| Verified: {secret['verified']}\n"
                )
                file.write(f"Raw: {secret['raw']}\n\n")

        # -- Semgrep secrets --
        file.write("Semgrep secrets:\n\n")
        if not semgrep_findings:
            file.write("(None)\n")
        else:
            for finding in semgrep_findings:
                file.write(f"filename: {finding['path']}\n")
                file.write(f"rule_id: {finding['check_id']}\n")
                # We'll include the lines as a pseudo "raw" snippet
                file.write(f"raw: {finding['lines']}\n\n")


def scan_host(hostname, minimal_output=False):
    """
    Scans a single host. Returns a dict with:
    {
      "total_findings": <int>,
      "verified_findings": <int>,
      "detector_names": <set of verified trufflehog detector names>,
      "unverified_trufflehog": <set of unverified trufflehog names>,
      "unverified_semgrep": <set of unverified semgrep short rule IDs>,
      "combined_txt_path": <str path to secrets.txt or "" if none>
    }
    """
    # Build the output folder path, e.g. domain_2025-01-20_16_50_01
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H_%M_%S")
    folder_name = FILENAME_FORMAT.format(domain=hostname, timestamp=timestamp)
    output_folder = os.path.join(OUTPUT_DIR, folder_name)

    # Make the subfolders
    tmp_dir = os.path.join(output_folder, "tmp")
    beautify_dir = os.path.join(output_folder, "beautify")

    os.makedirs(tmp_dir, exist_ok=True)
    os.makedirs(beautify_dir, exist_ok=True)

    url = f"https://{hostname}"
    if not minimal_output:
        print(f"[i] Fetching scripts from {url}")

    js_files = extract_js_files(url)
    if not minimal_output:
        print(f"\t[i] Found {len(js_files)} JS files")

    # If no JS found, return right away
    if not js_files:
        if not minimal_output:
            print("No JavaScript files found or page retrieval failed.")
        return {
            "total_findings": 0,
            "verified_findings": 0,
            "detector_names": set(),
            "unverified_trufflehog": set(),
            "unverified_semgrep": set(),
            "combined_txt_path": "",
        }

    # Download each JS file to tmp/, then beautify into beautify/
    if not minimal_output:
        print("\t[i] Downloading and beautifying ...")
    for js_url in js_files:
        download_and_beautify(js_url, tmp_dir, beautify_dir)

    if not minimal_output:
        print(f"\t[i] Files are saved in {output_folder}")

    # TRUFFLEHOG
    secrets_json_path = os.path.join(output_folder, "secrets.json")
    if not minimal_output:
        print(f"\n[i] Running TruffleHog ...")

    # Example: trufflehog filesystem scanning
    subprocess.run(
        ["trufflehog", "filesystem", "--directory", beautify_dir, "--json"],
        stdout=open(secrets_json_path, "w"),
        stderr=subprocess.DEVNULL,
    )

    raw_secrets = parse_trufflehog_json(secrets_json_path)

    # Deduplicate & unify verified status
    unique_secrets_map = {}
    for s in raw_secrets:
        raw = s["raw"]
        if raw not in unique_secrets_map:
            unique_secrets_map[raw] = s
        else:
            # If a later detection is verified, propagate that
            if s["verified"]:
                unique_secrets_map[raw]["verified"] = True

    final_trufflehog_secrets = list(unique_secrets_map.values())

    # Summaries for TruffleHog
    total_unique_th = len(final_trufflehog_secrets)
    verified_unique_th = sum(s["verified"] for s in final_trufflehog_secrets)
    # Verified detector names
    detector_names = {
        s["detector_name"] for s in final_trufflehog_secrets if s["verified"]
    }
    detector_names.discard("")

    # Collect unverified
    unverified_detector_names_th = {
        s["detector_name"]
        for s in final_trufflehog_secrets
        if not s["verified"] and s["detector_name"]
    }

    if not minimal_output:
        print(
            f"\t[!] Found {total_unique_th} unique secrets, {verified_unique_th} verified"
        )
        if verified_unique_th > 0:
            verified_secrets = [
                secret for secret in final_trufflehog_secrets if secret["verified"]
            ]
            print(f"\t[✓] Verified:")
            for vs in verified_secrets:
                print(f"\t\t[!] {vs['detector_name']} - {vs['raw']}")

        if unverified_detector_names_th:
            print(
                f"\t[!] Unverified: {', '.join(sorted(unverified_detector_names_th))}"
            )

    # SEMGREP
    semgrep_output_json = os.path.join(output_folder, "semgrep_output.json")
    if not minimal_output:
        print(f"\n[i] Running Semgrep ...")

    # We'll build the base command, adding each rule via --config
    semgrep_cmd = ["semgrep", "scan", "--no-rewrite-rule-ids"]
    for rule in SEMGREP_RULES:
        semgrep_cmd.extend(["--config", rule])
    semgrep_cmd.extend(
        [
            beautify_dir,
            "--json",
            "--output",
            semgrep_output_json,
        ]
    )
    subprocess.run(semgrep_cmd, stderr=subprocess.DEVNULL)

    semgrep_findings = parse_semgrep_json(semgrep_output_json)

    # Gather unverified short IDs
    unverified_detector_names_semgrep = set()

    if not minimal_output:
        if semgrep_findings:
            print(f"\t[!] Found {len(semgrep_findings)} findings from Semgrep.")
            rule_ids = set()
            for finding in semgrep_findings:
                full_id = finding["check_id"]
                last_part = full_id.split(".")[-1]
                rule_ids.add(last_part)
            unverified_detector_names_semgrep = rule_ids
            print(f"\t[!] Unverified: {', '.join(sorted(rule_ids))}")
        else:
            print(f"\t[!] No Semgrep findings found.")
    else:
        if semgrep_findings:
            for finding in semgrep_findings:
                full_id = finding["check_id"]
                last_part = full_id.split(".")[-1]
                unverified_detector_names_semgrep.add(last_part)

    # Combine results
    total_unique_sg = len(semgrep_findings)
    total_findings = total_unique_th + total_unique_sg

    # If any findings, generate secrets.txt
    if total_findings > 0:
        combined_txt_path = os.path.join(output_folder, "secrets.txt")
        save_combined_findings(
            final_trufflehog_secrets, semgrep_findings, combined_txt_path
        )
    else:
        combined_txt_path = ""

    return {
        "total_findings": total_findings,
        "verified_findings": verified_unique_th,
        "detector_names": detector_names,
        "unverified_trufflehog": unverified_detector_names_th,
        "unverified_semgrep": unverified_detector_names_semgrep,
        "combined_txt_path": combined_txt_path,
    }


def main():
    banner()

    parser = argparse.ArgumentParser(
        description="Scans remote JavaScript files with Trufflehog + Semgrep to detect leaked secrets"
    )
    parser.add_argument("--host", help="Single hostname to scan, e.g. example.com")
    parser.add_argument(
        "--list", help="Path to a file containing multiple hostnames, one per line"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Check dependencies (TruffleHog & Semgrep) versions, then exit.",
    )

    args = parser.parse_args()

    # If --debug, print versions and exit
    if args.debug:
        check_dependency("trufflehog", "TruffleHog", verbose=True)
        check_dependency("semgrep", "Semgrep", verbose=True)
        print("[i] Dependencies OK. Exiting now.")
        sys.exit(0)
    else:
        # Always ensure dependencies are installed (silently)
        check_dependency("trufflehog", "TruffleHog", verbose=False)
        check_dependency("semgrep", "Semgrep", verbose=False)

    # Must specify either --host or --list
    if not args.host and not args.list:
        parser.error("You must specify either --host or --list.")

    # Single-host mode
    if args.host:
        result = scan_host(args.host, minimal_output=False)
        if result["total_findings"] == 0:
            print("\n[i] No findings were discovered.")
        else:
            print(f"\n[i] Done; findings saved to {result['combined_txt_path']}")
        print("\n[i] Have a nice day!\n")
        return

    # Multi-host mode
    if args.list:
        if not os.path.isfile(args.list):
            print(f"[-] The file {args.list} does not exist.")
            sys.exit(1)

        with open(args.list, "r", encoding="utf-8") as f:
            hosts = [line.strip() for line in f if line.strip()]

        total_hosts = len(hosts)
        print("[!] Findings:")

        progress_format = "{desc}: {n}/{total}"
        with tqdm(
            total=total_hosts,
            desc="[?] Scanning Hosts",
            bar_format=progress_format,
        ) as pbar:
            for host in hosts:
                result = scan_host(host, minimal_output=True)
                pbar.update(1)

                total = result["total_findings"]
                verified = result["verified_findings"]
                detectors = result["detector_names"]
                unverified_th = result["unverified_trufflehog"]
                unverified_sg = result["unverified_semgrep"]
                combined_txt = result["combined_txt_path"]

                # If no findings, skip
                if total == 0:
                    continue

                # Decide which icon
                if verified > 0:
                    icon = "[✓]"
                else:
                    icon = "[!]"

                # Build output
                output = f"\t{icon} {host} ({verified}/{total})"
                if verified > 0:
                    detectors_str = ", ".join(sorted(detectors))
                    output += f" [{detectors_str}]"

                # Combine unverified
                unverified_all = unverified_th.union(unverified_sg)
                if unverified_all:
                    output += f", unverified: {', '.join(sorted(unverified_all))}"

                # Show secrets file
                output += f"\n\t\t[+] {combined_txt}\n"

                tqdm.write(output)

        print("\n[i] Have a nice day!\n")


if __name__ == "__main__":  # pragma: no cover
    main()
