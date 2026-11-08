import argparse
import logging
import re
import subprocess
import os
import sys
import requests
import hashlib
import urllib.parse
from packaging import version

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="vat-GitSecretScanner: Scans a git repository for potential secrets and performs basic vulnerability scanning.")

    # Git secret scanning arguments
    parser.add_argument("-r", "--repo_path", help="Path to the local git repository.", required=False)
    parser.add_argument("-a", "--all_commits", action="store_true", help="Scan all commits in the repository history.", required=False)

    # CVE scanning arguments
    parser.add_argument("-s", "--software_version", help="Software name and version (e.g., 'openssl 1.1.1').", required=False)

    # Simple web vulnerability scanning
    parser.add_argument("-u", "--url", help="URL to scan for basic web vulnerabilities (XSS, SQLi).", required=False)

    return parser

def _mask_value(value):
    """Masked preview only: first 4 characters plus a short hash."""
    text = str(value)
    digest = hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()[:8]
    return f"{text[:4]}...[REDACTED sha256:{digest}]"


# The API key pattern requires key context (a keyword such as key,
# token, or secret assigned a value), following the keyword-only model
# of the password pattern. A bare long alphanumeric run is not enough.
SECRET_PATTERNS = {
    "API Key": r"(?i)(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret)\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{16,64})[\"']?",
    "Password": r"(?i)(?:password|pwd|pass)\s*[:=]\s*[\"']?([A-Za-z0-9!@#$%^&*()_+=\-]{4,})[\"']?",
    "Private Key": r"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)",
}


def _report_matches(name, pattern, content, location):
    matches = re.findall(pattern, content, re.MULTILINE | re.IGNORECASE)
    if matches:
        masked = [_mask_value(m if isinstance(m, str) else str(m)) for m in matches]
        logging.warning(f"Potential {name} found in {location}: count={len(matches)} matches={masked}")
    return len(matches)


def find_secrets(repo_path, all_commits=False):
    """
    Scans a git repository for potential secrets using regular expressions.

    Args:
        repo_path (str): Path to the local git repository.
        all_commits (bool): If True, scans all commits in the history. Otherwise, only scans the current state.

    Returns:
        bool: True when the scan was performed, False when the
        repository path is invalid or git could not be read.
    """
    if not repo_path or not os.path.isdir(repo_path):
        logging.error(f"Invalid repository path: {repo_path}")
        return False

    patterns = SECRET_PATTERNS

    if all_commits:
        try:
            result = subprocess.run(['git', 'log', '--all', '--pretty=format:%H'], capture_output=True, text=True, cwd=repo_path, check=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Error retrieving git commit history: {e}")
            return False
        # Distinct commit IDs only, in history order. File name lines
        # are never treated as commits.
        seen = set()
        commit_ids = []
        for line in result.stdout.splitlines():
            cid = line.strip()
            if cid and cid not in seen:
                seen.add(cid)
                commit_ids.append(cid)
        for commit_hash in commit_ids:
            try:
                file_content_result = subprocess.run(['git', 'show', f'{commit_hash}'], capture_output=True, text=True, cwd=repo_path, check=True)
            except subprocess.CalledProcessError as e:
                logging.error(f"Error processing commit {commit_hash}: {e}")
                continue
            file_content = file_content_result.stdout
            if not file_content:
                continue
            for name, pattern in patterns.items():
                _report_matches(name, pattern, file_content, f"commit {commit_hash}")
        return True

    # Scan the current state of the repository, skipping .git
    # internals and binary files.
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d != ".git"]
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'rb') as f:
                    raw = f.read()
            except Exception as e:
                logging.error(f"Error reading file {file_path}: {e}")
                continue
            if b"\x00" in raw[:8192]:
                logging.debug(f"Skipping binary file: {file_path}")
                continue
            try:
                content = raw.decode('utf-8')
            except UnicodeDecodeError:
                logging.debug(f"Skipping non-text file: {file_path}")
                continue
            for name, pattern in patterns.items():
                _report_matches(name, pattern, content, f"file {file_path}")
    return True

def _version_in_range(cpe, software_name, version_str):
    """True when version_str falls in the cpeMatch range, honoring the
    vulnerable flag and every bound with correct strictness."""
    if cpe.get("vulnerable") is False:
        return False
    cpe_uri = cpe.get("cpe23Uri", "") or cpe.get("criteria", "")
    if software_name.lower() not in cpe_uri.lower():
        return False
    try:
        target = version.parse(version_str)
    except Exception:
        return False
    has_bound = False
    for key, fails in (
        ("versionStartIncluding", lambda bound: target < bound),
        ("versionStartExcluding", lambda bound: target <= bound),
        ("versionEndExcluding", lambda bound: target >= bound),
        ("versionEndIncluding", lambda bound: target > bound),
    ):
        raw_bound = cpe.get(key)
        if raw_bound:
            has_bound = True
            try:
                bound = version.parse(raw_bound)
            except Exception:
                continue
            if fails(bound):
                return False
    if has_bound:
        return True
    # No range bounds: only an exact version component in the CPE URI matches.
    parts = cpe_uri.split(":")
    return len(parts) > 5 and parts[5] == version_str


def check_cve(software_version):
    """
    Checks for known CVEs for a given software version using the NIST NVD.

    Args:
        software_version (str): Software name and version (e.g., "openssl 1.1.1").

    Returns:
        bool: True when the NVD check was performed, False otherwise.
    """
    if not software_version:
        logging.error("Software version must be provided.")
        return False
    try:
        software_name, version_str = software_version.split(" ", 1)
    except ValueError:
        logging.error("Invalid software version format. Use 'software_name version'.")
        return False
    if not software_name or not version_str.strip():
        logging.error("Invalid software version format. Use 'software_name version'.")
        return False
    version_str = version_str.strip()

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    vulnerable_cves = []
    start_index = 0
    results_per_page = 200
    try:
        while True:
            params = {
                "keywordSearch": software_name,
                "virtualMatchString": f"cpe:2.3:a:{software_name}:*:{version_str}",
                "resultsPerPage": results_per_page,
                "startIndex": start_index,
            }
            response = requests.get(base_url, params=params, timeout=15)
            if response.status_code != 200:
                logging.error(f"NVD request failed with status {response.status_code}; CVE check not performed.")
                return False
            data = response.json()
            for result in data.get('vulnerabilities', []):
                cve_data = result.get('cve')
                if not cve_data:
                    continue
                description_text = "".join(desc.get('value', '') for desc in cve_data.get('descriptions', []))
                version_match = False
                for configuration in cve_data.get("configurations", []):
                    for node in configuration.get("nodes", []):
                        for cpe in node.get("cpeMatch", []):
                            if _version_in_range(cpe, software_name, version_str):
                                version_match = True
                                break
                        if version_match:
                            break
                    if version_match:
                        break
                if version_match:
                    vulnerable_cves.append({"cve_id": cve_data.get('id'), "description": description_text, "published": cve_data.get('published')})
            total = data.get('totalResults', 0)
            start_index += results_per_page
            if start_index >= total or not data.get('vulnerabilities'):
                break
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during HTTP request: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False

    if vulnerable_cves:
        logging.warning(f"Potential vulnerabilities found for {software_version}:")
        for cve in vulnerable_cves:
            logging.warning(f"  - CVE ID: {cve['cve_id']}")
            logging.warning(f"    Published: {cve['published']}")
            logging.warning(f"    Description: {cve['description']}")
    else:
        logging.info(f"No known vulnerabilities found for {software_version}.")
    return True

def simple_web_scan(url):
    """
    Performs basic web application vulnerability scanning (XSS, SQLi).

    Responses are judged on their body at any status code; an error
    status does not discard the response.

    Args:
        url (str): URL to scan.

    Returns:
        bool: True when at least one check received a response,
        False when no check could be performed.
    """
    if not url:
        logging.error("URL must be provided.")
        return False

    performed = False

    # Basic XSS check (parameter injection). requests percent-encodes
    # the payload, so reflection is judged on the decoded response and
    # on the encoded form that was actually sent.
    xss_payload = "<script>alert('XSS')</script>"
    test_url = f"{url}?xss={xss_payload}"
    try:
        response = requests.get(test_url, timeout=5)
        performed = True
        decoded = urllib.parse.unquote(response.text or "")
        encoded = urllib.parse.quote(xss_payload, safe="")
        if xss_payload in decoded or encoded in (response.text or ""):
            logging.warning(f"Potential XSS vulnerability detected at {url}")
        else:
            logging.info(f"XSS check passed for {url}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during XSS check: {e}")

    # Basic SQL Injection check (single quote)
    sqli_payload = "'"
    test_url = f"{url}?sqli={sqli_payload}"
    try:
        response = requests.get(test_url, timeout=5)
        performed = True
        body = (response.text or "").lower()
        if "error in your sql syntax" in body or "unclosed quotation mark" in body:
            logging.warning(f"Potential SQL Injection vulnerability detected at {url}")
        else:
            logging.info(f"SQL Injection check passed for {url}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during SQL Injection check: {e}")

    return performed


def main():
    """
    Main function to parse arguments and execute the secret scanner and vulnerability checks.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if not args.repo_path and not args.software_version and not args.url:
        parser.print_usage(sys.stderr)
        print("No scan mode selected. Provide -r, -s, or -u.", file=sys.stderr)
        return 2

    exit_code = 0
    if args.repo_path:
        if not find_secrets(args.repo_path, args.all_commits):
            exit_code = 1

    if args.software_version:
        if not check_cve(args.software_version):
            exit_code = 1

    if args.url:
        if not simple_web_scan(args.url):
            exit_code = 1

    return exit_code

if __name__ == "__main__":
    # Example usage:
    # python main.py -r /path/to/repo
    # python main.py -r /path/to/repo -a
    # python main.py -s "openssl 1.1.1"
    # python main.py -u http://example.com
    sys.exit(main())