#!/usr/bin/env python3
"""Scan a public domain and score browser-requested third parties.

Exit codes: 0 done, 1 failed, 75 scan still running (rerun later or pass --wait).
"""

import argparse
import csv
import hashlib
import importlib.util
import ipaddress
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path


API = "https://whogetsmydata.com/api/v1"
TRANCO = "https://tranco-list.eu/top-1m.csv.zip"
RADAR_RAW = "https://raw.githubusercontent.com/duckduckgo/tracker-radar/main/build-data/generated"
WEB_DATA_API = "https://api.github.com/repos/patrickhulce/third-party-web/contents/data"
USER_AGENT = "third-party-scan/1.3 (+https://github.com/aaronjmars/3rd-party-audit)"
EXIT_PENDING = 75
INVENTORY_FIELDS = (
    "host", "service", "operator", "category", "evidence", "browser_requests",
    "script_tagged_requests", "resource_types", "example_url_without_query",
)


class ScanPending(Exception):
    """The public scan has not finished yet."""


def request(url, *, body=None, timeout=25):
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.read()
    except urllib.error.HTTPError as error:
        if error.code == 429:
            retry = error.headers.get("Retry-After", "a few minutes")
            raise RuntimeError(f"WhoGetsMyData rate limit reached; retry after {retry} seconds") from error
        raise


def request_json(url, *, body=None, timeout=25, missing_ok=False):
    try:
        return json.loads(request(url, body=body, timeout=timeout))
    except urllib.error.HTTPError as error:
        if missing_ok and error.code == 404:
            return None
        raise


def read_json(path, default=None):
    path = Path(path)
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def normalize_target(value):
    parsed = urllib.parse.urlsplit(value if "://" in value else "https://" + value)
    host = (parsed.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
    if parsed.scheme != "https" or not host or parsed.username or parsed.password or parsed.port:
        raise ValueError("Use a public HTTPS domain or URL without credentials or a custom port")
    if parsed.query or parsed.fragment:
        raise ValueError("Remove URL queries and fragments before submitting a public scan")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("Use a public domain, not an IP address")
    if host == "localhost" or host.endswith((".local", ".internal", ".test")) or "." not in host:
        raise ValueError("Use a public domain")
    path = parsed.path or "/"
    return host, path, urllib.parse.urlunsplit(("https", host, path, "", ""))


def site_key(domain):
    """WhoGetsMyData files www.example.com under example.com."""
    domain = (domain or "").lower().rstrip(".")
    return domain.removeprefix("www.")


def same_page(report_page, path):
    if not report_page:
        return False
    page_path = urllib.parse.urlsplit(report_page).path if "://" in report_page else report_page
    return (page_path or "/").rstrip("/") == path.rstrip("/")


def evidence_url(report):
    return (report.get("evidence") or {}).get("download_url") if isinstance(report, dict) else None


def is_fresh(report, max_age_hours):
    try:
        checked = datetime.fromisoformat(report["checked_at"].replace("Z", "+00:00"))
    except (KeyError, TypeError, AttributeError, ValueError):
        return False
    return bool(evidence_url(report)) and (datetime.now(timezone.utc) - checked).total_seconds() <= max_age_hours * 3600


def scan_report(host, path, url, *, cache_dir, max_age_hours, refresh, submit, wait_seconds):
    page = path != "/"
    website_url = f"{API}/websites/{urllib.parse.quote(host, safe='')}"
    page_index_path = cache_dir / "page-scans.json"
    page_index = read_json(page_index_path, {}) if page else {}
    if page:
        prior_id = page_index.get(url)
        prior = request_json(f"{API}/scans/{prior_id}", missing_ok=True) if prior_id else None
    else:
        prior = request_json(website_url, missing_ok=True)
    if prior and not refresh and is_fresh(prior, max_age_hours):
        return prior
    if not submit:
        raise RuntimeError(f"No report newer than {max_age_hours:g} hours and --no-submit is set; no scan was submitted")
    payload = {"url": url, "page": True} if page else {"url": host}
    try:
        report = request_json(f"{API}/scan", body=json.dumps(payload).encode(), timeout=150)
    except urllib.error.HTTPError:
        raise
    except (TimeoutError, urllib.error.URLError):
        report = None
    scan_id = report.get("scan_id") if isinstance(report, dict) else None
    if page and scan_id:
        page_index[url] = scan_id
        write_json(page_index_path, page_index)
    if evidence_url(report):
        return report
    deadline = time.monotonic() + wait_seconds
    while True:
        if scan_id:
            latest = request_json(f"{API}/scans/{scan_id}", missing_ok=True)
        elif not page:
            latest = request_json(website_url, missing_ok=True)
        else:
            latest = None
        if evidence_url(latest) and latest.get("scan_id") != (prior or {}).get("scan_id"):
            return latest
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(20, remaining))
    hint = f" (scan {scan_id})" if scan_id else ""
    raise ScanPending(f"Scan is still running{hint}; rerun the same command later or pass --wait. No second scan was submitted")


def evidence_from_zip(zip_path, expected_hash):
    with zipfile.ZipFile(zip_path) as archive:
        raw = archive.read("evidence.json")
    actual = hashlib.sha256(raw).hexdigest()
    if expected_hash and actual != expected_hash:
        raise ValueError(f"Evidence SHA-256 mismatch: expected {expected_hash}, got {actual}")
    return json.loads(raw)


def inventory(report, evidence):
    by_host = defaultdict(list)
    for item in evidence.get("requests", []):
        if item.get("found_in") == "browser" and item.get("third_party"):
            host = urllib.parse.urlsplit(item.get("url", "")).hostname
            if host:
                by_host[host.lower()].append(item)
    listed = {item["host"].lower(): item for item in report.get("third_parties") or [] if item.get("host")}
    services = {item["key"]: item for item in report.get("services") or [] if item.get("key")}
    companies = {item["company"]: item["name"] for item in report.get("recipients") or [] if item.get("company") and item.get("name")}
    rows = []
    for host in sorted(set(by_host) | set(listed)):
        requests = by_host.get(host, [])
        item = listed.get(host, {})
        service = services.get(item.get("service"), {})
        example = urllib.parse.urlsplit(requests[0]["url"]) if requests else None
        rows.append({
            "host": host,
            "service": service.get("name") or item.get("service") or "",
            "operator": service.get("company_name") or companies.get(item.get("company"), ""),
            "category": service.get("category", ""),
            "evidence": "browser request" if requests else "csp only" if item.get("policy_only") else "reference only",
            "browser_requests": len(requests),
            "script_tagged_requests": sum(req.get("type") == "script" for req in requests),
            "resource_types": ", ".join(sorted({req.get("type", "") for req in requests})),
            "example_url_without_query": urllib.parse.urlunsplit((example.scheme, example.netloc, example.path, "", "")) if example else "",
        })
    return rows, by_host


def write_csv(path, rows, fields):
    with path.open("w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def cached_download(url, path, *, max_age_seconds, offline=False):
    """Return a fresh or cached copy, or None when neither is available."""
    if path.exists() and (offline or time.time() - path.stat().st_mtime < max_age_seconds):
        return path
    if offline:
        return None
    try:
        content = request(url, timeout=45)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_bytes(content)
        temporary.replace(path)
    except (TimeoutError, urllib.error.URLError, RuntimeError) as error:
        if not path.exists():
            print(f"Warning: could not download {url} ({error}); scoring without it", file=sys.stderr)
            return None
        checked = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
        print(f"Warning: using cached dataset {path.name} from {checked}", file=sys.stderr)
    return path


def latest_web_usage(cache_dir, *, offline=False):
    pattern = re.compile(r"\d{4}-\d{2}-\d{2}-observed-domains\.json$")
    try:
        if offline:
            raise ValueError("offline")
        listing = request_json(WEB_DATA_API, timeout=20)
        candidates = [item for item in listing if pattern.fullmatch(item.get("name", ""))] if isinstance(listing, list) else []
        latest = max(candidates, key=lambda item: item["name"])
        path = cached_download(latest["download_url"], cache_dir / latest["name"], max_age_seconds=7 * 86400)
        if path:
            return path, latest["html_url"]
    except (TimeoutError, urllib.error.URLError, RuntimeError, ValueError):
        pass
    cached = sorted(path for path in cache_dir.glob("*-observed-domains.json") if pattern.fullmatch(path.name))
    if not cached:
        if not offline:
            print("Warning: Third Party Web dataset unavailable; scoring without HTTP Archive page counts", file=sys.stderr)
        return None, ""
    path = cached[-1]
    if not offline:
        print(f"Warning: using cached Third Party Web dataset {path.name}", file=sys.stderr)
    return path, f"https://github.com/patrickhulce/third-party-web/blob/master/data/{path.name}"


def mime_for_url(url):
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ""
    if parsed.scheme != "https" or host == "localhost" or host.endswith((".local", ".internal", ".test")):
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    try:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=12) as response:
            return response.headers.get_content_type()
    except urllib.error.HTTPError:
        pass  # some servers refuse HEAD (403/405) but answer GET
    except (TimeoutError, urllib.error.URLError, ValueError):
        return None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Range": "bytes=0-0"})
        with urllib.request.urlopen(req, timeout=12) as response:
            response.read(1)
            return response.headers.get_content_type()
    except (TimeoutError, urllib.error.URLError, ValueError):
        return None


def checked_mime(by_host):
    script_urls = {
        host: list(dict.fromkeys(item["url"] for item in requests if item.get("type") == "script"))
        for host, requests in by_host.items()
    }
    script_urls = {host: urls for host, urls in script_urls.items() if urls}
    found = defaultdict(list)
    with ThreadPoolExecutor(max_workers=6) as pool:
        jobs = {pool.submit(mime_for_url, url): host for host, urls in script_urls.items() for url in urls[:3]}
        for job in as_completed(jobs):
            mime = job.result()
            if mime:
                found[jobs[job]].append(mime)
    result = {}
    for host, urls in script_urls.items():
        types = found[host]
        if types and len(types) == min(3, len(urls)):
            if any(mime in ("application/javascript", "text/javascript", "text/js", "application/ecmascript") for mime in types):
                result[host] = "application/javascript"
            elif all(mime.startswith("image/") for mime in types):
                result[host] = types[0]
    return result


def sibling(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def vendor_inventory(args, report, by_host, host, url, out, cache, radar_map):
    reputation, vendors = sibling("reputation"), sibling("vendors")
    suffix_rules, _ = reputation.load_suffix_rules(args.psl_cache or cache / "public-suffix-list.dat", refresh=not args.offline)
    catalog_path = cached_download(f"{API}/catalog", cache / "whogetsmydata-catalog.json", max_age_seconds=7 * 86400, offline=args.offline)
    index = vendors.VendorIndex(read_json(catalog_path, {}) if catalog_path else {}, read_json(radar_map, {}) if radar_map else {},
                                suffix_rules, reputation.registered_domain)
    site = None
    if not (args.offline or args.no_site_fetch):
        site = vendors.fetch_site(url, USER_AGENT, index, max_pages=args.site_pages, max_files=args.max_site_scripts)
        if site["error"]:
            print(f"Warning: could not read the site's own code ({site['error']}); vendor list uses the scan only", file=sys.stderr)
        (out / "site-js-hosts.txt").write_text("".join(f"{h}\n" for h in sorted(site["unmapped_js_hosts"])), encoding="utf-8")
    earlier = [] if args.offline else vendors.history_reports(host, request_json, API, report.get("scan_id"), days=args.history_days)
    mentions = set()
    rows = vendors.build(report, set(by_host), host, index, site=site, earlier=earlier, mentions=mentions)
    write_csv(out / "vendors.csv", rows, vendors.VENDOR_FIELDS)
    (out / "page-mentions.txt").write_text("".join(f"{h}\n" for h in sorted(mentions)), encoding="utf-8")
    counts = {tier: sum(row["evidence"] == tier for row in rows) for tier in vendors.TIERS}
    return {
        "total": len(rows),
        "by_evidence": {vendors.TIERS[tier]: count for tier, count in counts.items()},
        "page_mentions_not_vendors": len(mentions),
        "site_fetch": None if site is None else {
            "status": site["status"], "error": site["error"] or None, "pages_read": site["pages_read"],
            "pages_failed": site["pages_failed"], "scripts_read": site["scripts_fetched"],
            "own_cdn_hosts_read": site["sister_hosts"],
            "megabytes_read": round(site["bytes"] / 1e6, 1), "hit_file_limit": site["capped"],
            "live_csp_hosts": len(site["csp_hosts"]), "unmapped_js_hosts": len(site["unmapped_js_hosts"]),
        },
        "earlier_scans": [{"scan_id": older.get("scan_id"), "checked_at": older.get("checked_at")} for older in earlier],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", help="Public domain or HTTPS URL")
    parser.add_argument("--output-dir", type=Path, help="Default: ./third-party-scans/<host>-<scan-id>")
    parser.add_argument("--cache-dir", type=Path, default=Path(tempfile.gettempdir()) / "third-party-scan-cache")
    parser.add_argument("--refresh", action="store_true", help="Submit a new scan even when a recent report exists")
    parser.add_argument("--max-age-hours", type=float, default=24, help="Reuse a report this recent (default 24)")
    parser.add_argument("--no-submit", action="store_true", help="Only read existing public reports; never submit a scan")
    parser.add_argument("--wait", type=float, default=0, metavar="SECONDS", help="Keep checking a running scan for up to this long")
    parser.add_argument("--offline", action="store_true", help="No network: needs --report-json, --evidence-zip and --psl-cache; other datasets optional")
    parser.add_argument("--report-json", type=Path, help="Use a saved report instead of calling the scan API")
    parser.add_argument("--evidence-zip", type=Path, help="Use a saved evidence ZIP with --report-json")
    parser.add_argument("--tranco-zip", type=Path)
    parser.add_argument("--tracker-radar-map", type=Path)
    parser.add_argument("--tracker-radar-prevalence", type=Path)
    parser.add_argument("--third-party-web-usage", type=Path)
    parser.add_argument("--third-party-web-source")
    parser.add_argument("--rdap-cache", type=Path)
    parser.add_argument("--psl-cache", type=Path)
    parser.add_argument("--owner-overrides", type=Path, help="JSON keyed by host: operator, publisher_domain, source")
    parser.add_argument("--company-sizes", type=Path, help="JSON keyed by publisher: employees, as_of, source")
    parser.add_argument("--mime-overrides", type=Path, help="JSON keyed by host: checked response Content-Type")
    parser.add_argument("--no-fetch-rdap", action="store_true", help="Skip registry lookups for domain age")
    parser.add_argument("--no-mime-check", action="store_true", help="Skip HEAD requests to third-party script URLs")
    parser.add_argument("--no-site-fetch", action="store_true", help="Do not read the site's live CSP and own JavaScript")
    parser.add_argument("--site-pages", type=int, default=6, help="Pages of the site to read, from different sections (default 6)")
    parser.add_argument("--max-site-scripts", type=int, default=400, help="Most of the site's own JavaScript files to read (default 400)")
    parser.add_argument("--history-days", type=float, default=30, help="Also merge earlier public scans this recent (default 30, 0 = off)")
    args = parser.parse_args()
    if bool(args.report_json) != bool(args.evidence_zip):
        parser.error("--report-json and --evidence-zip must be provided together")
    if args.offline and not (args.report_json and args.psl_cache and args.psl_cache.exists()):
        parser.error("--offline needs --report-json, --evidence-zip and an existing --psl-cache file")
    host, path, url = normalize_target(args.target)
    cache = args.cache_dir
    cache.mkdir(parents=True, exist_ok=True)
    if args.report_json:
        report = read_json(args.report_json)
    else:
        report = scan_report(host, path, url, cache_dir=cache, max_age_hours=args.max_age_hours,
                             refresh=args.refresh, submit=not args.no_submit, wait_seconds=args.wait)
    if site_key(report.get("domain")) != site_key(host):
        raise ValueError(f"Report domain {report.get('domain')!r} does not match target {host!r}")
    if path != "/" and not same_page(report.get("page"), path):
        raise ValueError("Report page does not match target URL")
    scan_id = report.get("scan_id")
    if scan_id is None:
        raise RuntimeError("Report has no scan_id")
    out = args.output_dir or Path.cwd() / "third-party-scans" / f"{host}-{scan_id}"
    out.mkdir(parents=True, exist_ok=True)
    evidence_zip = args.evidence_zip or out / "evidence.zip"
    if not args.evidence_zip:
        download = evidence_url(report)
        if not download:
            raise RuntimeError("This report has no evidence download (older or source-only scan); rerun with --refresh")
        parsed = urllib.parse.urlsplit(download)
        if parsed.scheme != "https" or parsed.hostname != "whogetsmydata.com":
            raise ValueError("Unexpected evidence download host")
        evidence_zip.write_bytes(request(download, timeout=45))
    evidence = evidence_from_zip(evidence_zip, (report.get("evidence") or {}).get("sha256"))
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.evidence_zip and evidence_zip.resolve() != (out / "evidence.zip").resolve():
        shutil.copy2(evidence_zip, out / "evidence.zip")
    rows, by_host = inventory(report, evidence)
    inventory_path = out / "inventory.csv"
    write_csv(inventory_path, rows, INVENTORY_FIELDS)
    week = 7 * 86400
    tranco = args.tranco_zip or cached_download(TRANCO, cache / "tranco-top-1m.zip", max_age_seconds=86400, offline=args.offline)
    radar_map = args.tracker_radar_map or cached_download(f"{RADAR_RAW}/domain_map.json", cache / "tracker-radar-domain-map.json", max_age_seconds=week, offline=args.offline)
    radar_prevalence = args.tracker_radar_prevalence or cached_download(f"{RADAR_RAW}/entity_prevalence.json", cache / "tracker-radar-entity-prevalence.json", max_age_seconds=week, offline=args.offline)
    if args.third_party_web_usage:
        web_usage = args.third_party_web_usage
        web_source = args.third_party_web_source or ""
    else:
        web_usage, web_source = latest_web_usage(cache, offline=args.offline)
    mime = {} if args.no_mime_check or args.offline else checked_mime(by_host)
    if args.mime_overrides:
        mime.update(read_json(args.mime_overrides))
    mime_path = out / "response-mime.json"
    write_json(mime_path, mime)
    score_path = out / "scored.csv"
    command = [sys.executable, str(Path(__file__).with_name("reputation.py")), str(inventory_path),
               "--rdap-cache", str(args.rdap_cache or cache / "rdap.json"),
               "--mime-overrides", str(mime_path), "--output", str(score_path),
               "--psl-cache", str(args.psl_cache or cache / "public-suffix-list.dat")]
    optional = {"--tranco-zip": tranco, "--tracker-radar-map": radar_map, "--tracker-radar-prevalence": radar_prevalence,
                "--third-party-web-usage": web_usage, "--owner-overrides": args.owner_overrides,
                "--company-sizes": args.company_sizes}
    for flag, value in optional.items():
        if value:
            command.extend([flag, str(value)])
    if web_usage:
        command.extend(["--third-party-web-source", web_source])
    if args.offline:
        command.append("--offline")
    elif not args.no_fetch_rdap:
        command.append("--fetch-rdap")
    completed = subprocess.run(command, check=False)
    if completed.returncode:
        raise RuntimeError(f"Scoring step failed (exit {completed.returncode}); inventory is at {inventory_path}")
    with score_path.open(newline="", encoding="utf-8") as source:
        scored = list(csv.DictReader(source))
    vendor_summary = vendor_inventory(args, report, by_host, host, url, out, cache, radar_map)
    summary = {
        "target": url, "scan_id": scan_id, "checked_at": report.get("checked_at"),
        "report_url": report.get("report_url"), "method": report.get("method"),
        "representative": report.get("representative"), "limitations": report.get("limitations") or [],
        "browser_third_party_requests": sum(len(items) for items in by_host.values()),
        "browser_third_party_hosts": len(by_host), "reference_only_hosts": sum(row["evidence"] == "reference only" for row in rows),
        "csp_only_hosts": sum(row["evidence"] == "csp only" for row in rows),
        "data_sources": {"scan": report.get("report_url"), "tranco": TRANCO if tranco else None,
                         "tracker_radar": RADAR_RAW if radar_map else None, "third_party_web": web_source or None},
        "vendors": vendor_summary,
        "top_risks": [
            {key: row[key] for key in ("host", "publisher", "risk_level", "footprint_risk_score_0_100",
                                         "reputation_footprint_score_0_100", "exposure", "score_confidence")}
            for row in scored[:5]
        ],
    }
    if report.get("representative") is False:
        print("Warning: the scanner was served a block or error page; results do not show what visitors get", file=sys.stderr)
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output_dir": str(out), **summary}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except ScanPending as error:
        print(error, file=sys.stderr)
        sys.exit(EXIT_PENDING)
    except (ValueError, RuntimeError, OSError, KeyError, zipfile.BadZipFile) as error:
        message = f"Scan failed: {error}"
        if "CERTIFICATE_VERIFY_FAILED" in str(error):
            message += "\nPython cannot verify HTTPS certificates. On macOS with a python.org install, run 'Install Certificates.command' from its Applications folder."
        sys.exit(message)
