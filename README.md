# JS Snitch

## Description

Scans remote JavaScript files with Trufflehog + Semgrep to detect leaked secrets

## Installation

```bash
$ git clone https://github.com/vavkamil/js-snitch.git
$ cd js-snitch
$ pip install -r requirements.txt
$ python js-snitch.py
```

### Required

- [github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog?tab=readme-ov-file#floppy_disk-installation)
- [github.com/semgrep/semgrep](https://github.com/semgrep/semgrep?tab=readme-ov-file#option-2-getting-started-from-the-cli)

## Usage

```bash
./js-snitch$ python js-snitch.py --help

    ▗▖ ▗▄▄▖     ▗▄▄▖▗▖  ▗▖▗▄▄▄▖▗▄▄▄▖▗▄▄▖▗▖ ▗▖
    ▐▌▐▌       ▐▌   ▐▛▚▖▐▌  █    █ ▐▌   ▐▌ ▐▌
    ▐▌ ▝▀▚▖     ▝▀▚▖▐▌ ▝▜▌  █    █ ▐▌   ▐▛▀▜▌
 ▗▄▄▞▘▗▄▄▞▘    ▗▄▄▞▘▐▌  ▐▌▗▄█▄▖  █ ▝▚▄▄▖▐▌ ▐▌v0.1

usage: js-snitch.py [-h] [--host HOST] [--list LIST] [--debug]

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
