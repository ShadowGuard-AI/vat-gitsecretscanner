# vat-GitSecretScanner
A command-line tool that scans a local git repository's commit history and current state for potential secrets (API keys, passwords, private keys) using regular expressions. It does not perform entropy analysis. Matched values are never logged in clear; reports give the pattern name, location, count, and a masked preview. The password pattern accepts both colon and equals assignment (for example `password:` and `password =`) and the masked preview is built from the matched value. The current-state scan skips .git internals and binary files, and the API key pattern requires key context (a keyword such as key, token, or secret assigned a value), so commit hashes and plain long words are not flagged. Performs basic vulnerability scanning based on known CVEs: it can check a software version against the NIST NVD and report potential security risks, honoring version range bounds and the vulnerable flag. Includes simple web application vulnerability scanning (checking for XSS or SQL injection), judging response bodies at any status code.

## Install
`git clone https://github.com/ShadowGuard-AI/vat-gitsecretscanner`

## Usage
`python3 main.py -r <repo path> [-a] [-s '<software> <version>'] [-u <URL>]`

## Parameters
- `-h`: Show help message and exit
- `-r`: Path to the local git repository.
- `-a`: Scan all commits in the repository history.
- `-s`: Software name and version (e.g., 'openssl 1.1.1') to check against the NIST NVD.
- `-u`: URL to scan for basic web vulnerabilities (XSS, SQLi).

A run with no mode selected, an invalid repository path, or a check that could not be performed exits non-zero.

## License
MIT. See LICENSE.
