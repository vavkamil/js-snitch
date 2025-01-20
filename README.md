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

```bash
$ 
```
