# JS Snitch

[![Coverage badge](https://img.shields.io/badge/Coverage-100%25-brightreen)](https://github.com/vavkamil/js-snitch/actions/workflows/tests.yml)
[![Tests badge](https://github.com/vavkamil/js-snitch/actions/workflows/tests.yml/badge.svg)](https://github.com/vavkamil/js-snitch/actions/workflows/tests.yml)
[![Black badge](https://github.com/vavkamil/js-snitch/actions/workflows/black.yml/badge.svg)](https://github.com/vavkamil/js-snitch/actions/workflows/black.yml)
[![License badge](https://badgen.net/github/license/vavkamil/js-snitch)](https://github.com/vavkamil/js-snitch/blob/update-readme/LICENSE)
[![Dependabot badge](https://badgen.net/github/dependabot/vavkamil/js-snitch)](https://github.com/vavkamil/js-snitch/security/dependabot)
[![Last commit badge](https://badgen.net/github/last-commit/vavkamil/js-snitch)](https://github.com/vavkamil/js-snitch/pulls)
<!-- [![Stars badge](https://badgen.net/github/stars/vavkamil/js-snitch)](https://github.com/vavkamil/js-snitch)
[![Forks badge](https://badgen.net/github/forks/vavkamil/js-snitch)](https://github.com/vavkamil/js-snitch/forks)
[![Merged badge](https://badgen.net/github/merged-prs/vavkamil/js-snitch)](https://github.com/vavkamil/js-snitch/pulls)
[![Issues badge](https://badgen.net/github/issues/vavkamil/js-snitch)](https://github.com/vavkamil/js-snitch/issues) -->

## Introduction

**JS Snitch** is a command-line tool designed to scan remote JavaScript files for potential secrets or credentials using [Trufflehog](https://github.com/trufflesecurity/trufflehog) and [Semgrep](https://github.com/semgrep/semgrep). It automates the process of:

- Extracting `.js` files from a target domain.
- Downloading and beautifying the scripts.
- Running Trufflehog and Semgrep for possible secret leaks.

JS Snitch is intended to help penetration testers, bug bounty hunters, and security engineers quickly identify leaked API keys, tokens, or other credentials hidden in external JavaScript files.

## Features

- **Multi-host scanning**: Provide either a single host or a list of hosts to scan.
- **Trufflehog integration**: Leverages Trufflehog's scanning capabilities for secret detection.
- **Semgrep integration**: Configurable Semgrep rulesets for additional scanning and pattern-based detection.
- **Beautification step**: Automatically prettifies downloaded JS files for better readability in local analysis.
- **Aggregated results**: Consolidates Trufflehog and Semgrep findings into a single report.
- **Unverified vs. Verified secrets**: Quickly see which secrets are definitely valid (verified) and which ones need manual inspection.

![JS Snitch Cover](./cover.png)

## Description

Scans remote JavaScript files with Trufflehog + Semgrep to detect leaked secrets

## Installation

```bash
$ git clone https://github.com/vavkamil/js-snitch.git
$ cd js-snitch
$ pip install -r requirements.txt
$ python js_snitch.py
```

### Required

- [github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog?tab=readme-ov-file#floppy_disk-installation)
- [github.com/semgrep/semgrep](https://github.com/semgrep/semgrep?tab=readme-ov-file#option-2-getting-started-from-the-cli)

## Usage

```bash
./js-snitch$ python js_snitch.py --help

    ▗▖ ▗▄▄▖     ▗▄▄▖▗▖  ▗▖▗▄▄▄▖▗▄▄▄▖▗▄▄▖▗▖ ▗▖
    ▐▌▐▌       ▐▌   ▐▛▚▖▐▌  █    █ ▐▌   ▐▌ ▐▌
    ▐▌ ▝▀▚▖     ▝▀▚▖▐▌ ▝▜▌  █    █ ▐▌   ▐▛▀▜▌
 ▗▄▄▞▘▗▄▄▞▘    ▗▄▄▞▘▐▌  ▐▌▗▄█▄▖  █ ▝▚▄▄▖▐▌ ▐▌v0.1

usage: js_snitch.py [-h] [--host HOST] [--list LIST] [--debug]

Scans remote JavaScript files with Trufflehog + Semgrep to detect leaked secrets

options:
  -h, --help   show this help message and exit
  --host HOST  Single hostname to scan, e.g. example.com
  --list LIST  Path to a file containing multiple hostnames, one per line
  --debug      Check dependencies (TruffleHog & Semgrep) versions, then exit.
```

## Examples

### Single host

```bash
$ python js_snitch.py --host foo.example.com

    ▗▖ ▗▄▄▖     ▗▄▄▖▗▖  ▗▖▗▄▄▄▖▗▄▄▄▖▗▄▄▖▗▖ ▗▖
    ▐▌▐▌       ▐▌   ▐▛▚▖▐▌  █    █ ▐▌   ▐▌ ▐▌
    ▐▌ ▝▀▚▖     ▝▀▚▖▐▌ ▝▜▌  █    █ ▐▌   ▐▛▀▜▌
 ▗▄▄▞▘▗▄▄▞▘    ▗▄▄▞▘▐▌  ▐▌▗▄█▄▖  █ ▝▚▄▄▖▐▌ ▐▌v0.1

[i] Fetching scripts from https://foo.example.com
	[i] Found 28 JS files
	[i] Downloading and beautifying ...
	[i] Files are saved in output/foo.example.com_2025-01-20_17_53_27

[i] Running TruffleHog ...
	[!] Found 21 unique secrets, 2 verified
	[✓] Verified:
		[!] Slack - xoxb-1313578942645-REDACTED-WrCPLmuZGZfNGxPZQOjnKEm
		[!] Intercom - dG9rOjAwMDAwMDBfZGNkZl9SRURBQ1RFRF9kYjc1NmYwMDAwMDAwOjE6MA==
	[!] Unverified: HubSpotApiKey, Mailchimp, PosthogApp, Slack, SlackWebhook

[i] Running Semgrep ...
	[!] Found 33 findings from Semgrep.
	[!] Unverified: detected-mailchimp-api-key, detected-slack-webhook, hashicorp-tf-password, slack-bot-token, slack-webhook-url

[i] Done; findings saved to output/foo.example.com_2025-01-20_17_53_27/secrets.txt

[i] Have a nice day!

$ 
```

### List of hosts

```bash
$ python js_snitch.py --list small_list.txt 

    ▗▖ ▗▄▄▖     ▗▄▄▖▗▖  ▗▖▗▄▄▄▖▗▄▄▄▖▗▄▄▖▗▖ ▗▖
    ▐▌▐▌       ▐▌   ▐▛▚▖▐▌  █    █ ▐▌   ▐▌ ▐▌
    ▐▌ ▝▀▚▖     ▝▀▚▖▐▌ ▝▜▌  █    █ ▐▌   ▐▛▀▜▌
 ▗▄▄▞▘▗▄▄▞▘    ▗▄▄▞▘▐▌  ▐▌▗▄█▄▖  █ ▝▚▄▄▖▐▌ ▐▌v0.1

[!] Findings:
        [✓] example.com (1/3) [Github], unverified: detected-jwt-token, github-fine-grained-pat
		[+] output/example.com_2025-01-20_17_48_38/secrets.txt

        [✓] foo.example.com (2/54) [Intercom, Slack], unverified: HubSpotApiKey, Mailchimp, PosthogApp, Slack, SlackWebhook, detected-mailchimp-api-key, detected-slack-webhook, hashicorp-tf-password, slack-bot-token, slack-webhook-url
		[+] output/foo.example.com_2025-01-20_17_48_52/secrets.txt

        [!] example.com (0/5), unverified: YoutubeApiKey, detected-generic-api-key, detected-google-api-key, detected-telegram-bot-api-key, facebook-access-token
		[+] output/example.com_2025-01-20_17_49_19/secrets.txt

        [✓] example.com (1/29) [Github], unverified: detected-facebook-oauth, generic-api-key
		[+] output/example.com_2025-01-20_17_49_49/secrets.txt

[?] Scanning Hosts: 5/5

[i] Have a nice day!

$ 
```
