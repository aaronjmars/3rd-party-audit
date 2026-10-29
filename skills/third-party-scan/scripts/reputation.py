#!/usr/bin/env python3
"""Add transparent reputation proxies to a third-party host inventory CSV."""

import argparse
import csv
import ipaddress
import json
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path


TRACKER_RADAR_MAP_URL = "https://github.com/duckduckgo/tracker-radar/blob/main/build-data/generated/domain_map.json"
USER_AGENT = "third-party-scan/1.1 (+https://github.com/aaronjmars/3rd-party-audit)"


def load_suffix_rules(path, refresh=True):
    path = Path(path)
    if refresh and (not path.exists() or time.time() - path.stat().st_mtime > 7 * 86400):
        request = urllib.request.Request(
            "https://publicsuffix.org/list/public_suffix_list.dat",
            headers={"User-Agent": USER_AGENT},
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                content = response.read()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        except (TimeoutError, urllib.error.URLError) as error:
            if not path.exists():
                raise RuntimeError(f"Public Suffix List unavailable ({error}); pass a local copy with --psl-cache") from error
            print(f"Warning: using cached Public Suffix List {path}", file=sys.stderr)
    if not path.exists():
        raise RuntimeError(f"Public Suffix List not found at {path}")
    public, private = set(), set()
    current = public
    for line in path.read_text(encoding="utf-8").splitlines():
        if "BEGIN PRIVATE DOMAINS" in line:
            current = private
        rule = line.strip().lower()
        if rule and not rule.startswith("//"):
            current.add(rule)
    return public, private


def shared_hosting_suffix(host, private_rules):
    for rule in private_rules:
        suffix = rule.lstrip("*.")
        if not rule.startswith("!") and host.endswith("." + suffix):
            return suffix
    return None


def registered_domain(host, suffix_rules):
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    parts = host.lower().rstrip(".").split(".")
    suffix_length = 1
    for index in range(len(parts)):
        candidate = ".".join(parts[index:])
        if "!" + candidate in suffix_rules:
            suffix_length = len(parts) - index - 1
            break
        if candidate in suffix_rules:
            suffix_length = max(suffix_length, len(parts) - index)
        if index and "*." + candidate in suffix_rules:
            suffix_length = max(suffix_length, len(parts) - index + 1)
    return ".".join(parts[-suffix_length - 1 :]) if len(parts) > suffix_length else None


def tranco_ranks(path, roots):
    with zipfile.ZipFile(path) as archive:
        name = archive.namelist()[0]
        with archive.open(name) as source:
            found = {}
            for raw in source:
                rank, _, domain = raw.decode("utf-8").strip().partition(",")
                if domain in roots and rank.isdigit():
                    found[domain] = int(rank)
            return found


def rdap_registry_bases():
    request = urllib.request.Request(
        "https://data.iana.org/rdap/dns.json",
        headers={"User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            bootstrap = json.load(response)
    except (TimeoutError, urllib.error.URLError, json.JSONDecodeError) as error:
        print(f"Warning: IANA RDAP map unavailable ({error}); trying WHOIS only", file=sys.stderr)
        return {}
    return {tld: urls[0] for tlds, urls in bootstrap["services"] for tld in tlds}


def registration_date(root, base):
    if not base:
        try:
            result = subprocess.run(["whois", root], capture_output=True, text=True, timeout=12, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return None
        match = re.search(r"(?im)^\s*(?:Creation Date|Created|Registered on|Registration Date|Domain Registration Date):\s*(\d{4}-\d{2}-\d{2}(?:T[^\s]+)?)", result.stdout)
        return match.group(1) if match else None
    request = urllib.request.Request(
        f"{base.rstrip('/')}/domain/{root}",
        headers={"Accept": "application/rdap+json", "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            data = json.load(response)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
        return None
    for event in data.get("events", []):
        if event.get("eventAction") == "registration":
            return event.get("eventDate")
    return None


def read_json(path, default=None):
    if not path:
        return default
    path = Path(path)
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def load_dates(cache_path, roots, fetch):
    dates = read_json(cache_path, {})
    missing = sorted(root for root in roots if not dates.get(root))
    if fetch and missing:
        bases = rdap_registry_bases()
        with ThreadPoolExecutor(max_workers=6) as pool:
            jobs = {pool.submit(registration_date, root, bases.get(root.rsplit('.', 1)[-1])): root for root in missing}
            for job in as_completed(jobs):
                dates[jobs[job]] = job.result()
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(dates, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return dates


def age_years(date_str, now):
    if not date_str:
        return None
    try:
        date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        if date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)
        return max(0, (now - date).days / 365.25)
    except ValueError:
        return None


def adoption_points(pages, prevalence):
    page_points = 20 if pages is not None and pages >= 1_000_000 else 15 if pages is not None and pages >= 100_000 else 10 if pages is not None and pages >= 10_000 else 5 if pages is not None and pages >= 100 else 0
    reach_points = 20 if prevalence is not None and prevalence >= 0.1 else 15 if prevalence is not None and prevalence >= 0.01 else 10 if prevalence is not None and prevalence >= 0.001 else 5 if prevalence is not None and prevalence >= 0.0001 else 0
    return max(page_points, reach_points)


def compatible_owner_labels(scanner_owner, radar_entry):
    if not scanner_owner or not radar_entry:
        return True
    def normalized(value):
        words = re.findall(r"[a-z0-9]+", value.lower())
        return " ".join(word for word in words if word not in {"inc", "llc", "ltd", "limited", "corp", "corporation", "company", "entities", "plc", "ag", "sa"})
    scanner = normalized(scanner_owner)
    labels = [radar_entry.get("entityName", ""), radar_entry.get("displayName", ""), *radar_entry.get("aliases", [])]
    return any(scanner == label or scanner in label or label in scanner for label in map(normalized, labels) if label)


def score_row(row, ranks, dates, mime_overrides, owner_overrides, suffix_rules, private_rules, radar_map, radar_prevalence, web_usage, web_usage_source, company_sizes, now):
    host = row["host"]
    root = registered_domain(host, suffix_rules)
    override = owner_overrides.get(host, {})
    score_root = override.get("publisher_domain") or root
    shared_suffix = shared_hosting_suffix(host, private_rules)
    shared = bool(shared_suffix and not override.get("publisher_domain"))
    radar_entry = radar_map.get(host) if not shared else None
    radar_match = "exact_host" if radar_entry else ""
    if not radar_entry and root and not shared:
        radar_entry = radar_map.get(root)
        radar_match = "registered_domain" if radar_entry else ""
    radar_owner = radar_entry.get("entityName", "") if radar_entry else ""
    scanner_owner = row.get("operator", "").strip() if not shared else ""
    aligned = compatible_owner_labels(scanner_owner, radar_entry)
    prevalence = radar_prevalence.get(radar_owner, {}).get("total") if radar_owner and aligned else None
    owner = override.get("operator") or scanner_owner or radar_owner
    owner_identified = bool(owner)
    owner_source = override.get("source") or ("scanner label" if scanner_owner else TRACKER_RADAR_MAP_URL if radar_owner else "")
    age = None if shared or not score_root else age_years(dates.get(score_root), now)
    rank = None if shared or not score_root else ranks.get(score_root)
    age_points = 20 if age is not None and age >= 10 else 15 if age is not None and age >= 5 else 10 if age is not None and age >= 2 else 5 if age is not None and age >= 1 else 0
    rank_points = 20 if rank and rank <= 10000 else 15 if rank and rank <= 100000 else 10 if rank else 0
    score = 40 + (20 if owner_identified else 0) + age_points + rank_points
    pages = web_usage.get(host)
    use_points = adoption_points(pages, prevalence)
    footprint_score = 40 + (20 if owner_identified else 0) + age_points + use_points
    company = company_sizes.get(owner, {})
    types = set(row.get("resource_types", "").split(", "))
    mime = mime_overrides.get(host, "").split(";", 1)[0].strip().lower()
    script_tagged = int(row.get("script_tagged_requests") or 0) > 0
    executable = "yes" if "javascript" in mime or mime in ("text/js", "application/ecmascript") else "no" if mime.startswith("image/") else "unknown" if script_tagged else "not_applicable"
    if executable == "yes":
        exposure = "confirmed_js"
        exposure_points = 100
    elif script_tagged and executable == "unknown":
        exposure = "script_tagged_mime_unknown"
        exposure_points = 85
    elif "iframe" in types:
        exposure = "iframe"
        exposure_points = 65
    elif "websocket" in types:
        exposure = "websocket_attempt"
        exposure_points = 50
    elif "xhr" in types or "fetch" in types:
        exposure = "api_or_xhr"
        exposure_points = 50
    elif "image" in types or "beacon" in types or mime.startswith("image/"):
        exposure = "pixel_or_image"
        exposure_points = 15
    else:
        exposure = "other"
        exposure_points = 25
    risk = round(0.4 * (100 - score) + 0.6 * exposure_points)
    footprint_risk = round(0.4 * (100 - footprint_score) + 0.6 * exposure_points)
    confidence = "lower" if shared or not root or age is None or not owner_identified or (radar_owner and not scanner_owner and not override.get("operator")) else "standard"
    return {
        **row,
        "registered_domain": root or "",
        "publisher": owner if owner_identified else "unknown",
        "publisher_source": owner_source,
        "tracker_radar_owner": radar_owner,
        "tracker_radar_match": radar_match,
        "tracker_radar_owner_alignment": "differs" if radar_owner and not aligned else "agrees" if radar_owner and scanner_owner else "candidate" if radar_owner else "",
        "tracker_radar_entity_reach_pct": round(prevalence * 100, 4) if prevalence is not None else "",
        "tracker_radar_source": TRACKER_RADAR_MAP_URL if radar_owner else "",
        "http_archive_pages_observed": pages if pages is not None else "",
        "http_archive_source": web_usage_source if pages is not None else "",
        "adoption_points_0_20": use_points,
        "company_employees": company.get("employees", ""),
        "company_size_as_of": company.get("as_of", ""),
        "company_size_source": company.get("source", ""),
        "reputation_domain": score_root if not shared and score_root else "",
        "publisher_identified": "yes" if owner_identified else "no",
        "registration_date": dates.get(score_root, "") if not shared and score_root else "",
        "domain_age_years": round(age, 1) if age is not None else "",
        "tranco_rank": rank or "",
        "reputation_score_0_100": score,
        "reputation_footprint_score_0_100": footprint_score,
        "score_confidence": confidence,
        "response_mime_checked": mime,
        "executable_js": executable,
        "exposure": exposure,
        "risk_score_0_100": risk,
        "footprint_risk_score_0_100": footprint_risk,
        "risk_level": "high" if footprint_risk >= 60 else "medium" if footprint_risk >= 40 else "low",
        "score_note": "Shared hosting: publisher unverified; host provider reputation excluded" if shared else "Shared hosting: scored documented publisher domain" if shared_suffix else "IP endpoint: publisher unverified" if not root else "RDAP/WHOIS age unavailable" if age is None else "",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory_csv", type=Path)
    parser.add_argument("--tranco-zip", type=Path, help="Tranco top 1M ZIP; omit to score without rank")
    parser.add_argument("--rdap-cache", required=True, type=Path)
    parser.add_argument("--mime-overrides", type=Path)
    parser.add_argument("--owner-overrides", type=Path)
    parser.add_argument("--tracker-radar-map", type=Path)
    parser.add_argument("--tracker-radar-prevalence", type=Path)
    parser.add_argument("--third-party-web-usage", type=Path)
    parser.add_argument("--third-party-web-source", default="")
    parser.add_argument("--company-sizes", type=Path)
    parser.add_argument("--psl-cache", type=Path, default=Path(tempfile.gettempdir()) / "third-party-public-suffix-list.dat")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--fetch-rdap", action="store_true")
    parser.add_argument("--offline", action="store_true", help="No network: use --psl-cache as is and skip RDAP")
    args = parser.parse_args()
    with args.inventory_csv.open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    rows = [row for row in rows if row.get("evidence") == "browser request"]
    suffix_rules, private_rules = load_suffix_rules(args.psl_cache, refresh=not args.offline)
    roots = {registered_domain(row["host"], suffix_rules) for row in rows if not shared_hosting_suffix(row["host"], private_rules)}
    roots.discard(None)
    owners = read_json(args.owner_overrides, {})
    radar_map = read_json(args.tracker_radar_map, {})
    radar_prevalence = read_json(args.tracker_radar_prevalence, {})
    web_usage = {item["domain"]: item["totalOccurrences"] for item in read_json(args.third_party_web_usage, [])}
    company_sizes = read_json(args.company_sizes, {})
    roots |= {item["publisher_domain"] for item in owners.values() if item.get("publisher_domain")}
    ranks = tranco_ranks(args.tranco_zip, roots) if args.tranco_zip else {}
    dates = load_dates(args.rdap_cache, roots, args.fetch_rdap and not args.offline)
    mime = read_json(args.mime_overrides, {})
    now = datetime.now(timezone.utc)
    output = [score_row(row, ranks, dates, mime, owners, suffix_rules, private_rules, radar_map, radar_prevalence, web_usage, args.third_party_web_source, company_sizes, now) for row in rows]
    output.sort(key=lambda row: (-row["footprint_risk_score_0_100"], row["host"]))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, fieldnames=list(output[0]) if output else ["host", "service", "operator", "evidence", "browser_requests", "script_tagged_requests", "resource_types"])
        writer.writeheader()
        writer.writerows(output)
    print(f"Scored {len(output)} browser-requested hosts; {sum(bool(row['tracker_radar_owner']) for row in output)} Tracker Radar matches, {sum(row['http_archive_pages_observed'] != '' for row in output)} HTTP Archive usage counts, {sum(bool(dates.get(root)) for root in roots)}/{len(roots)} registration dates", file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, OSError, KeyError, zipfile.BadZipFile) as error:
        sys.exit(f"Scoring failed: {error}")
