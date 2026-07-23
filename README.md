
# 🔍 subtakeover

**Passive subdomain enumeration + dangling-CNAME / subdomain-takeover scanner**

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#-contributing)
[![Fingerprints](https://img.shields.io/badge/fingerprints-75%2B%20services-orange.svg)](fingerprints.json)

*Find abandoned CNAMEs before someone else does.*

[Quick Start](#-quick-start) •
[How It Works](#-how-it-works) •
[Usage](#-usage) •
[Sample Output](#-sample-output) •
[Contributing](#-contributing)

</div>

---

```
███████╗██╗   ██╗██████╗ ███████╗████████╗ █████╗ ████████╗██╗   ██╗███████╗
██╔════╝██║   ██║██╔══██╗██╔════╝╚══██╔══╝██╔══██╗╚══██╔══╝██║   ██║██╔════╝
███████╗██║   ██║██████╔╝███████╗   ██║   ███████║   ██║   ██║   ██║███████╗
╚════██║██║   ██║██╔══██╗╚════██║   ██║   ██╔══██║   ██║   ██║   ██║╚════██║
███████║╚██████╔╝██████╔╝███████║   ██║   ██║  ██║   ██║   ╚██████╔╝███████║
╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚══════╝
```

## Overview

`subtakeover` is a single-file, dependency-light CLI that chains together three
steps security teams commonly run separately:

1. **Enumerate** — discover live and historical subdomains via public
   Certificate Transparency logs (crt.sh).
2. **Resolve & probe** — walk each host's CNAME chain, check for `NXDOMAIN`,
   and grab the HTTP response.
3. **Fingerprint** — compare the CNAME target and response body against a
   database of 75+ known "claimable service" signatures, sourced from the
   community-maintained
   [`can-i-take-over-xyz`](https://github.com/EdOverflow/can-i-take-over-xyz)
   project, to flag likely subdomain-takeover candidates.

It's built for authorized recon and attack-surface monitoring — point it at
domains you own or have explicit permission to test.

## ✨ Features

- 🔎 **CT-log enumeration** — no brute-forcing or wordlists required
- 🧵 **Concurrent scanning** — configurable thread pool for fast checks across large subdomain lists
- 🧬 **75+ service fingerprints** — AWS S3, Azure, GitHub Pages, Heroku, Shopify, Zendesk, and more
- 📄 **Structured JSON reports** — pipe results into other tooling or dashboards
- 🧯 **Read-only by design** — never registers, claims, or modifies anything; pure detection
- 🪶 **Minimal dependencies** — just `requests` and `dnspython`

## 📦 Installation

```bash
git clone https://github.com/Yahyaibr/subtakeover.git
cd subtakeover
pip install -r requirements.txt
```

Requires Python 3.9+.

## 🚀 Quick Start

Scan a domain end-to-end (enumerate + check) in one command:

```bash
python3 subtakeover.py scan -d example.com -o report.json
```

Or run the two stages separately:

```bash
# 1. Enumerate subdomains
python3 subtakeover.py enum -d example.com -o subs.txt

# 2. Check them for takeover risk
python3 subtakeover.py check -i subs.txt -o report.json
```

## 🧠 How It Works

```
┌─────────────┐     ┌──────────────────┐     ┌───────────────────┐
│   crt.sh    │ --> │  DNS + HTTP probe │ --> │ Fingerprint match  │
│ (CT logs)   │     │ (CNAME, NXDOMAIN, │     │ (can-i-take-over-  │
│             │     │  status, body)    │     │  xyz signatures)   │
└─────────────┘     └──────────────────┘     └───────────────────┘
      │                       │                        │
      ▼                       ▼                        ▼
  subdomain list      per-host DNS/HTTP data     verdict + report
```

Each host is assigned one of four verdicts:

| Verdict | Meaning |
|---|---|
| 🔴 `LIKELY_VULNERABLE` | CNAME points to a third-party service and the response matches a known "unclaimed resource" signature |
| 🟡 `edge_case_review` | Matches a fingerprint the community flags as inconsistent/provider-dependent — confirm manually |
| 🟡 `review_dangling_cname` | CNAME resolves to `NXDOMAIN` but doesn't match a known signature — still worth a look |
| 🟢 `not_vulnerable` | No third-party CNAME, or the target is alive and claimed |

## 🛠 Usage

```
usage: subtakeover.py [-h] {enum,check,scan} ...

commands:
  enum    Enumerate subdomains via crt.sh
  check   Check a list of hosts for takeover risk
  scan    Enumerate + check in one step

enum:
  -d, --domain        target domain (required)
  -o, --output        write subdomain list to file

check:
  -i, --input         file with one hostname per line (required)
  -o, --output        write JSON report to file
  -t, --threads       concurrent workers (default: 20)
  --http-timeout      per-request timeout in seconds (default: 8)

scan:
  -d, --domain        target domain (required)
  -o, --output        write JSON report to file
  -t, --threads       concurrent workers (default: 20)
  --http-timeout      per-request timeout in seconds (default: 8)
```

## 📊 Sample Output

**Console summary:**

```
======================================================================
SUBDOMAIN TAKEOVER SCAN SUMMARY
======================================================================
Total hosts checked: 214
Likely vulnerable:   2
Needs manual review: 3
======================================================================

[LIKELY VULNERABLE]
  - old-docs.example.com  ->  ['example.readthedocs.io']  (Readthedocs)
  - assets.example.com    ->  ['example.s3.amazonaws.com']  (AWS/S3)

[NEEDS MANUAL REVIEW]
  - status.example.com    ->  ['status.pingdom.com']  (verdict: edge_case_review)
```

**JSON report (`report.json`):**

```json
{
  "hostname": "assets.example.com",
  "cname_chain": ["example.s3.amazonaws.com"],
  "nxdomain": false,
  "http_status": 404,
  "matched_service": "AWS/S3",
  "verdict": "LIKELY_VULNERABLE"
}
```

## 🔄 Updating Fingerprints

`fingerprints.json` is a local snapshot of
[`EdOverflow/can-i-take-over-xyz`](https://github.com/EdOverflow/can-i-take-over-xyz),
which is updated frequently by the community. Periodically re-sync it to pick
up new services and revised signatures.

## ⚠️ Scope & Responsible Use

- **Passive and read-only.** This tool only queries public CT logs, resolves
  DNS, and sends standard HTTP GET requests. It never registers, claims, or
  provisions any resource — actually reclaiming a dangling record is a
  separate, deliberate action that requires you to follow the specific
  provider's official verification process.
- **Only scan assets you own or are explicitly authorized to test.**
  Unauthorized scanning of third-party infrastructure may violate
  computer-fraud laws and target terms of service.
- **Fingerprint matches are candidates, not confirmed vulnerabilities.**
  Always manually verify a `LIKELY_VULNERABLE` result before acting on it or
  reporting it through a bug bounty program.
- DNS/HTTP checks can produce false negatives behind CDNs, WAFs, or rate
  limiting.

## 🙏 Acknowledgements

This project builds on ideas and data from:
- [EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) — the fingerprint database
- Certificate Transparency tooling patterns popularized by projects like `subfinder`, `amass`, and `crt.sh`-based enumerators

## 🤝 Contributing

Issues and PRs are welcome — especially new/updated fingerprints, bug fixes,
and additional enumeration sources (e.g. passive DNS APIs). Please open an
issue first for larger changes.

## 📄 License

[MIT](LICENSE) — see the LICENSE file for details.

---

<div align="center">
<sub>Built for defenders. Use responsibly.</sub>
</div>
