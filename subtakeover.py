#!/usr/bin/env python3
"""
subtakeover.py — subdomain enumeration + dangling-CNAME / subdomain-takeover checker.

Combines three ideas from well-known open-source tools into one script:
  - Enumeration via certificate-transparency logs (crt.sh)     [subdomain-enumeration]
  - DNS resolution + HTTP status reporting for each host       [SubStatus]
  - Fingerprint matching against known "claimable" services    [can-i-take-over-xyz]

IMPORTANT / SCOPE OF USE
-------------------------
This tool only performs passive reconnaissance (public CT logs, public DNS
resolution, and a GET request to hosts you point it at) and pattern-matches
responses against publicly documented signatures. It does NOT exploit, claim,
register, or take over any domain, cloud resource, or third-party account —
doing that requires an out-of-band step (e.g. actually creating an account or
resource with the abandoned name at the provider), which this tool never does.
Only run this against domains you own or are authorized to test.

Usage:
    python3 subtakeover.py enum  -d example.com [-o subs.txt]
    python3 subtakeover.py check -i subs.txt [-o report.json] [-t 30]
    python3 subtakeover.py scan  -d example.com [-o report.json] [-t 30]
"""

import argparse
import concurrent.futures
import json
import re
import socket
import sys
import time
from pathlib import Path

import requests
import dns.resolver
import dns.exception

FINGERPRINTS_PATH = Path(__file__).parent / "fingerprints.json"
USER_AGENT = "subtakeover-checker/1.0 (+authorized security testing)"

BANNER = r"""
███████╗██╗   ██╗██████╗ ████████╗ █████╗ ██╗  ██╗███████╗ ██████╗ ██╗   ██╗███████╗██████╗
██╔════╝██║   ██║██╔══██╗╚══██╔══╝██╔══██╗██║ ██╔╝██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗
███████╗██║   ██║██████╔╝   ██║   ███████║█████╔╝ █████╗  ██║   ██║██║   ██║█████╗  ██████╔╝
╚════██║██║   ██║██╔══██╗   ██║   ██╔══██║██╔═██╗ ██╔══╝  ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
███████║╚██████╔╝██████╔╝   ██║   ██║  ██║██║  ██╗███████╗╚██████╔╝ ╚████╔╝ ███████╗██║  ██║
╚══════╝ ╚═════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝

        Fast async subdomain HTTP status checker for security recon
                         github.com/Yahyaibr
"""


def print_banner():
    print(BANNER, file=sys.stderr)


# --------------------------------------------------------------------------
# 1. Enumeration (certificate transparency, like `subdomain-enumeration`)
# --------------------------------------------------------------------------
def enumerate_subdomains(domain: str, timeout: int = 20) -> list[str]:
    """Pull subdomains from crt.sh (Certificate Transparency logs)."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subs = set()
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
        data = resp.json()
        for entry in data:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name.endswith(domain):
                    subs.add(name)
    except Exception as e:
        print(f"[!] crt.sh enumeration failed: {e}", file=sys.stderr)
    return sorted(subs)


# --------------------------------------------------------------------------
# 2. DNS + HTTP status (like `SubStatus`)
# --------------------------------------------------------------------------
def resolve_cname_chain(hostname: str) -> tuple[list[str], bool]:
    """Return (cname_chain, nxdomain) for a hostname."""
    chain = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    current = hostname
    seen = set()
    try:
        while True:
            if current in seen:
                break
            seen.add(current)
            try:
                answer = resolver.resolve(current, "CNAME")
                target = str(answer[0].target).rstrip(".")
                chain.append(target)
                current = target
            except dns.resolver.NoAnswer:
                break
            except dns.resolver.NXDOMAIN:
                return chain, True
    except dns.exception.DNSException:
        pass

    # Confirm whether the final name resolves at all (A/AAAA)
    try:
        resolver.resolve(current, "A")
        return chain, False
    except dns.resolver.NXDOMAIN:
        return chain, True
    except dns.exception.DNSException:
        # Could not confirm either way (timeout, no A record but not NXDOMAIN, etc.)
        return chain, False


def fetch_http(hostname: str, timeout: int = 8) -> dict:
    """Try HTTPS then HTTP, return status code + truncated body."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}/"
        try:
            resp = requests.get(
                url,
                timeout=timeout,
                headers={"User-Agent": USER_AGENT},
                allow_redirects=True,
                verify=False,
            )
            return {
                "url": url,
                "status_code": resp.status_code,
                "body": resp.text[:5000],
                "error": None,
            }
        except requests.exceptions.SSLError:
            continue
        except Exception as e:
            last_error = str(e)
            continue
    return {"url": None, "status_code": None, "body": "", "error": last_error if 'last_error' in dir() else "unreachable"}


# --------------------------------------------------------------------------
# 3. Fingerprint matching (like `can-i-take-over-xyz`)
# --------------------------------------------------------------------------
def load_fingerprints() -> list[dict]:
    with open(FINGERPRINTS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def match_fingerprint(cname_chain: list[str], nxdomain: bool, body: str,
                       fingerprints: list[dict]) -> dict | None:
    """Match a resolved host's CNAME/response against known takeover signatures."""
    chain_lower = [c.lower() for c in cname_chain]

    for fp in fingerprints:
        cname_matches = any(
            any(service_cname.lower() in c for c in chain_lower)
            for service_cname in fp.get("cname", [])
        ) if fp.get("cname") else False

        # Only evaluate fingerprints for services whose CNAME pattern is present
        # (skip generic/no-cname entries unless there's no cname list at all,
        # in which case we can't safely correlate — so we require a cname hit).
        if not fp.get("cname"):
            continue
        if not cname_matches:
            continue

        if fp.get("nxdomain"):
            if nxdomain:
                return fp
            continue

        pattern = fp.get("fingerprint", "")
        if pattern and body:
            try:
                if re.search(pattern, body, re.IGNORECASE):
                    return fp
            except re.error:
                if pattern.lower() in body.lower():
                    return fp

    return None


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------
def check_host(hostname: str, fingerprints: list[dict], http_timeout: int) -> dict:
    result = {
        "hostname": hostname,
        "cname_chain": [],
        "nxdomain": False,
        "http_status": None,
        "http_error": None,
        "matched_service": None,
        "verdict": "not_vulnerable",
    }

    cname_chain, nxdomain = resolve_cname_chain(hostname)
    result["cname_chain"] = cname_chain
    result["nxdomain"] = nxdomain

    body = ""
    if not nxdomain:
        http_result = fetch_http(hostname, timeout=http_timeout)
        result["http_status"] = http_result["status_code"]
        result["http_error"] = http_result["error"]
        body = http_result["body"] or ""

    if cname_chain:  # only flag hosts that CNAME out to a third party
        match = match_fingerprint(cname_chain, nxdomain, body, fingerprints)
        if match:
            result["matched_service"] = match["service"]
            result["verdict"] = "LIKELY_VULNERABLE" if match.get("vulnerable") else "edge_case_review"
        elif nxdomain:
            result["verdict"] = "review_dangling_cname"  # CNAME + NXDOMAIN but no known fingerprint

    return result


def run_checks(hostnames: list[str], concurrency: int = 20, http_timeout: int = 8) -> list[dict]:
    fingerprints = load_fingerprints()
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {
            pool.submit(check_host, h, fingerprints, http_timeout): h
            for h in hostnames
        }
        for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
            h = futures[future]
            try:
                results.append(future.result())
            except Exception as e:
                results.append({"hostname": h, "error": str(e), "verdict": "error"})
            print(f"[{i}/{len(hostnames)}] checked {h}", file=sys.stderr)
    return results


def print_summary(results: list[dict]):
    vulnerable = [r for r in results if r.get("verdict") == "LIKELY_VULNERABLE"]
    review = [r for r in results if r.get("verdict") in ("edge_case_review", "review_dangling_cname")]

    print("\n" + "=" * 70)
    print("SUBDOMAIN TAKEOVER SCAN SUMMARY")
    print("=" * 70)
    print(f"Total hosts checked: {len(results)}")
    print(f"Likely vulnerable:   {len(vulnerable)}")
    print(f"Needs manual review: {len(review)}")
    print("=" * 70)

    if vulnerable:
        print("\n[LIKELY VULNERABLE]")
        for r in vulnerable:
            print(f"  - {r['hostname']}  ->  {r['cname_chain']}  ({r['matched_service']})")

    if review:
        print("\n[NEEDS MANUAL REVIEW]")
        for r in review:
            print(f"  - {r['hostname']}  ->  {r['cname_chain']}  (verdict: {r['verdict']})")

    if not vulnerable and not review:
        print("\nNo obvious takeover candidates found among the hosts checked.")

    print()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Subdomain enumeration + takeover checker")
    sub = parser.add_subparsers(dest="command", required=True)

    p_enum = sub.add_parser("enum", help="Enumerate subdomains via crt.sh")
    p_enum.add_argument("-d", "--domain", required=True)
    p_enum.add_argument("-o", "--output", help="Write subdomain list to file")

    p_check = sub.add_parser("check", help="Check a list of hosts for takeover risk")
    p_check.add_argument("-i", "--input", required=True, help="File with one hostname per line")
    p_check.add_argument("-o", "--output", help="Write JSON report to file")
    p_check.add_argument("-t", "--threads", type=int, default=20)
    p_check.add_argument("--http-timeout", type=int, default=8)

    p_scan = sub.add_parser("scan", help="Enumerate + check in one step")
    p_scan.add_argument("-d", "--domain", required=True)
    p_scan.add_argument("-o", "--output", help="Write JSON report to file")
    p_scan.add_argument("-t", "--threads", type=int, default=20)
    p_scan.add_argument("--http-timeout", type=int, default=8)

    args = parser.parse_args()
    print_banner()
    requests.packages.urllib3.disable_warnings()  # we intentionally allow self-signed/misconfigured certs here

    if args.command == "enum":
        subs = enumerate_subdomains(args.domain)
        print(f"[+] Found {len(subs)} unique subdomains for {args.domain}", file=sys.stderr)
        if args.output:
            Path(args.output).write_text("\n".join(subs) + "\n")
            print(f"[+] Wrote list to {args.output}", file=sys.stderr)
        else:
            print("\n".join(subs))

    elif args.command == "check":
        hosts = [l.strip() for l in Path(args.input).read_text().splitlines() if l.strip()]
        results = run_checks(hosts, concurrency=args.threads, http_timeout=args.http_timeout)
        print_summary(results)
        if args.output:
            Path(args.output).write_text(json.dumps(results, indent=2))
            print(f"[+] Full JSON report written to {args.output}", file=sys.stderr)

    elif args.command == "scan":
        subs = enumerate_subdomains(args.domain)
        print(f"[+] Found {len(subs)} unique subdomains for {args.domain}", file=sys.stderr)
        if not subs:
            print("[!] No subdomains found, nothing to check.", file=sys.stderr)
            return
        results = run_checks(subs, concurrency=args.threads, http_timeout=args.http_timeout)
        print_summary(results)
        if args.output:
            Path(args.output).write_text(json.dumps(results, indent=2))
            print(f"[+] Full JSON report written to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
