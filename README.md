# jsvulnscan

Detects and verifies **outdated / vulnerable JavaScript libraries** in web applications, with evidence you can put straight into a pentest report.

Version-only scanners often report a library based on a file name or URL. `jsvulnscan` tries to confirm the version from the code itself: it reads it from the live JavaScript object in a headless browser, matches the file hash, or reads it from the file content. The result says how the version was confirmed.

> The console output and HTML report are in Turkish (built for the "Güncel Olmayan JavaScript Kütüphanelerinin Kullanılması" finding).

## Features

- Collects `<script src>`, inline scripts, `modulepreload` links and (in browser mode) dynamically loaded scripts.
- Uses the [Retire.js](https://github.com/RetireJS/retire.js) signature database (downloaded and cached for 24 h): SHA1 hashes, file content, file name and URL patterns.
- **Runtime verification** (`--browser`): opens each page in headless Chromium over the Chrome DevTools Protocol and reads the version from the live object (e.g. `jQuery.fn.jquery`, `angular.version.full`). It does not need Node.js or Playwright.
- Resolves conflicts: if the file name says `jquery-3.7.1.min.js` but the content is 1.12.4, the finding is 1.12.4.
- Compares the detected version with the latest version on npm and with known CVE/GHSA ranges.
- Multi-target scans with per-target results and a "library → affected hosts" table.
- Reproduction commands for each finding (`curl | grep`, `sha1sum` or a DevTools console expression).
- HTML, JSON and colored console output; proxy (Burp), cookie, custom header and `-k` support.

## Confidence levels

| Level | Meaning |
|---|---|
| `KESIN` (confirmed) | Version read at runtime, matched by SHA1 hash, or read from the file content (banner/code). |
| `OLASI` (likely) | Version inferred only from the URL or file name; verify manually. |

## Installation

Python 3 with `requests` is enough for static scans. Browser mode also needs Chromium and `websocket-client`. All of these ship with Kali Linux.

```bash
sudo apt install python3-requests python3-websocket python3-regex chromium
git clone https://github.com/ersinerenler/jsvulnscan.git
cd jsvulnscan
```

## Usage

```bash
# Quick static scan
./jsvulnscan.py -u https://target.example

# Confirmed results with runtime verification, HTML + JSON report
./jsvulnscan.py -u https://target.example --browser -o report

# Multiple targets from a file (one URL per line, # for comments)
./jsvulnscan.py -l targets.txt --browser -o report

# Authenticated, through Burp, following links one level deep
./jsvulnscan.py -u https://target.example/app -d 1 -c 'SESSION=...' -H 'Authorization: Bearer ...' \
  -x http://127.0.0.1:8080 -k --browser -o report

# A single JavaScript file
./jsvulnscan.py -j https://target.example/static/vendor.js
```

| Option | Description |
|---|---|
| `-u URL` / `-l FILE` / `-j JS_URL` | Targets (each can be repeated). |
| `-d N`, `--max-pages N` | Same-host link depth and page limit per target. |
| `-b`, `--browser` | Runtime verification in headless Chromium and dynamic script collection. |
| `-c`, `-H`, `-x`, `-k` | Cookie, extra header, proxy, skip TLS verification. |
| `--only-confirmed` | Show only `KESIN` findings. |
| `--show-all` | Also list up-to-date libraries. |
| `--no-latest` | Skip the npm latest-version lookup (offline). |
| `--db FILE` | Use a local Retire.js `jsrepository-v4.json` (offline). |
| `-o PREFIX` | Write `PREFIX.html` and `PREFIX.json`. |

Exit codes: `0` nothing found, `1` outdated library found, `2` library with known vulnerabilities found.

## Interpreting results

A matched version shows that the vulnerable code is **present**. It does not show that a CVE is **exploitable**: many advisories depend on a specific feature or function being used. Treat the finding as a patch-management issue and assess each CVE's preconditions before rating its severity.

## Credits

Vulnerability and signature data comes from the [Retire.js](https://github.com/RetireJS/retire.js) repository (Apache-2.0). It is downloaded at runtime, not bundled.

## Disclaimer

Use only against systems you are authorized to test.

## License

[MIT](LICENSE)
