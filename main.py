import argparse
import logging
import re
import subprocess
import os
import sys
import requests
from bs4 import BeautifulSoup
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

def find_secrets(repo_path, all_commits=False):
    """
    Scans a git repository for potential secrets using regular expressions.

    Args:
        repo_path (str): Path to the local git repository.
        all_commits (bool): If True, scans all commits in the history. Otherwise, only scans the current state.
    """
    try:
        if not os.path.isdir(repo_path):
            raise ValueError(f"Invalid repository path: {repo_path}")

        # Regular expressions for common secrets
        patterns = {
            "API Key": r"[a-zA-Z0-9]{32,45}",  # Simplified API key pattern
            "Password": r"(password|pwd|pass):[\s]*[\"']?[\w\d!@#$%^&*()_+=-]+[\"']?", # Simplified password pattern
            "Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
        }

        if all_commits:
            # Scan all commits in the history
            try:
                result = subprocess.run(['git', 'log', '--all', '--pretty=format:%H', '--name-only', '--diff-filter=ACDMRTUXB'], capture_output=True, text=True, cwd=repo_path, check=True)
                commit_history = result.stdout.split('\n')

                for commit_hash in commit_history:
                    if commit_hash:  # Make sure we have a valid hash
                        commit_hash = commit_hash.strip()
                        try:
                            file_content_result = subprocess.run(['git', 'show', f'{commit_hash}'], capture_output=True, text=True, cwd=repo_path, check=True)
                            file_content = file_content_result.stdout
                            if not file_content:
                                continue  # Skip empty files
                            for name, pattern in patterns.items():
                                matches = re.findall(pattern, file_content, re.MULTILINE | re.IGNORECASE)
                                if matches:
                                    logging.warning(f"Potential {name} found in commit {commit_hash}: {matches}")

                        except subprocess.CalledProcessError as e:
                            logging.error(f"Error processing commit {commit_hash}: {e}")


            except subprocess.CalledProcessError as e:
                logging.error(f"Error retrieving git commit history: {e}")

        else:
            # Scan the current state of the repository
            for root, _, files in os.walk(repo_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            for name, pattern in patterns.items():
                                matches = re.findall(pattern, content, re.MULTILINE | re.IGNORECASE)
                                if matches:
                                    logging.warning(f"Potential {name} found in file {file_path}: {matches}")
                    except Exception as e:
                        logging.error(f"Error reading file {file_path}: {e}")

    except ValueError as e:
        logging.error(e)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

def check_cve(software_version):
    """
    Checks for known CVEs for a given software version using the NIST NVD.

    Args:
        software_version (str): Software name and version (e.g., "openssl 1.1.1").
    """
    try:
        if not software_version:
            raise ValueError("Software version must be provided.")

        software_name, version_str = software_version.split(" ", 1)
        if not software_name or not version_str:
            raise ValueError("Invalid software version format.  Use 'software_name version'.")


        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        query = f"?keyword={software_name}"

        response = requests.get(base_url + query)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        data = response.json()

        vulnerable_cves = []
        for result in data.get('vulnerabilities', []):
            cve_data = result.get('cve')
            if not cve_data:
                continue

            descriptions = cve_data.get('descriptions', [])
            description_text = ""
            for desc in descriptions:
                 description_text += desc.get('value', '')

            cve_id = cve_data.get('id')
            published_date = cve_data.get('published')

            version_match = False
            for configuration in cve_data.get("configurations", []):
                nodes = configuration.get("nodes", [])
                for node in nodes:
                    cpe_match = node.get("cpeMatch", [])
                    for cpe in cpe_match:
                        cpe_uri = cpe.get("cpe23Uri", "")
                        if software_name in cpe_uri and version_str in cpe_uri:
                            version_match = True
                            break

                        if software_name in cpe_uri and cpe.get("versionEndExcluding", None) and version.parse(version_str) <= version.parse(cpe.get("versionEndExcluding")):
                            version_match = True
                            break
                        if software_name in cpe_uri and cpe.get("versionEndIncluding", None) and version.parse(version_str) <= version.parse(cpe.get("versionEndIncluding")):
                            version_match = True
                            break
                    if version_match:
                        break
                if version_match:
                    break


            if version_match:
                vulnerable_cves.append({"cve_id": cve_id, "description": description_text, "published": published_date})

        if vulnerable_cves:
            logging.warning(f"Potential vulnerabilities found for {software_version}:")
            for cve in vulnerable_cves:
                logging.warning(f"  - CVE ID: {cve['cve_id']}")
                logging.warning(f"    Published: {cve['published']}")
                logging.warning(f"    Description: {cve['description']}")
        else:
            logging.info(f"No known vulnerabilities found for {software_version}.")

    except ValueError as e:
        logging.error(e)
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during HTTP request: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

def simple_web_scan(url):
    """
    Performs basic web application vulnerability scanning (XSS, SQLi).

    Args:
        url (str): URL to scan.
    """
    try:
        if not url:
            raise ValueError("URL must be provided.")

        # Basic XSS check (parameter injection)
        xss_payload = "<script>alert('XSS')</script>"
        test_url = f"{url}?xss={xss_payload}"  #append the xss payload as a URL parameter
        try:
            response = requests.get(test_url, timeout=5) # set a timeout
            response.raise_for_status()

            if xss_payload in response.text:
                logging.warning(f"Potential XSS vulnerability detected at {test_url}")
            else:
                logging.info(f"XSS check passed for {url}")

        except requests.exceptions.RequestException as e:
            logging.error(f"Error during XSS check: {e}")


        # Basic SQL Injection check (single quote)
        sqli_payload = "'"  # Single quote for SQLi
        test_url = f"{url}?sqli={sqli_payload}" #append the sqli payload as a URL parameter

        try:
            response = requests.get(test_url, timeout=5)
            response.raise_for_status()

            if "error in your SQL syntax" in response.text.lower() or "unclosed quotation mark" in response.text.lower():
                logging.warning(f"Potential SQL Injection vulnerability detected at {test_url}")
            else:
                logging.info(f"SQL Injection check passed for {url}")


        except requests.exceptions.RequestException as e:
            logging.error(f"Error during SQL Injection check: {e}")



    except ValueError as e:
        logging.error(e)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")


def main():
    """
    Main function to parse arguments and execute the secret scanner and vulnerability checks.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.repo_path:
        find_secrets(args.repo_path, args.all_commits)

    if args.software_version:
        check_cve(args.software_version)

    if args.url:
        simple_web_scan(args.url)

if __name__ == "__main__":
    # Example usage:
    # python main.py -r /path/to/repo
    # python main.py -r /path/to/repo -a
    # python main.py -s "openssl 1.1.1"
    # python main.py -u http://example.com
    main()