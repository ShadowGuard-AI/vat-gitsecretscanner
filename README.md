# vat-GitSecretScanner
A command-line tool that scans a local git repository's commit history and current state for potential secrets (API keys, passwords, private keys) using regular expressions and entropy analysis. Reports identified secrets and their location within the repository. - Focused on Performs basic vulnerability scanning based on known CVEs.  Can check installed software versions against known vulnerability databases (e.g., NIST NVD) and report potential security risks.  Includes simple web application vulnerability scanning (e.g., checking for XSS or SQL injection).

## Install
`git clone https://github.com/ShadowGuardAI/vat-gitsecretscanner`

## Usage
`./vat-gitsecretscanner [params]`

## Parameters
- `-h`: Show help message and exit
- `-r`: Path to the local git repository.
- `-a`: Scan all commits in the repository history.
- `-s`: Software name and version (e.g., 
- `-u`: No description provided

## License
Copyright (c) ShadowGuardAI
