#!/usr/bin/env python3
"""Merge every source of third-party evidence into one vendor list.

Sources, strongest first: browser requests in the latest scan, services the scanner
saw load through the site's own domain, names in the page code, vendor domains in the
site's own JavaScript, the live and scanned Content Security Policy, and earlier scans.
"""

import re
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone


TIERS = {
    "loaded": "loaded in the browser",
    "loaded_via_site": "loaded through the site's own domain",
    "in_page_code": "named in the page code",
    "in_site_js": "named in the site's own JavaScript",
    "csp_allowed": "allowed by the security policy only",
    "earlier_scan": "seen in an earlier scan only",
}
RANK = {tier: index for index, tier in enumerate(TIERS)}
VENDOR_FIELDS = ("vendor", "company", "category", "evidence", "evidence_label", "all_evidence", "hosts", "note")
SCRIPT_SRC = re.compile(r"""<script\b[^>]*?\bsrc\s*=\s*["']([^"']+)["']""", re.I)
JS_URL = re.compile(r"""(?:https:)?//[a-z0-9.-]+\.[a-z]{2,24}/[^"'`\s<>()\\]+?\.m?js(?=[?"'`\s<>\\]|$)""", re.I)
JS_PATH = re.compile(r"""["'`]((?:/|\./)?(?:_next/)?static/chunks/[\w./~-]+?\.js|/[\w./~-]+?\.js)["'`]""")
URL_HOST = re.compile(r"(?:https?|wss?)://([a-z0-9][a-z0-9.-]*\.[a-z]{2,24})(?=[/:?#\"'`\s\\]|$)", re.I)
BARE_HOST = re.compile(r"(?<![\w.@-])((?:[a-z0-9-]+\.)+[a-z]{2,24})(?![\w-])", re.I)
CSP_SOURCE = re.compile(r"^(?:[a-z][a-z0-9+.-]*://)?(?:\*\.)?([a-z0-9.-]+\.[a-z]{2,24})(?::(?:\d+|\*))?(?:/.*)?$", re.I)


class VendorIndex:
    """Names a host: scanner service first, then the WhoGetsMyData catalog, then Tracker Radar."""

    def __init__(self, catalog, radar_map, suffix_rules, registered_domain):
        self.registered_domain = registered_domain
        self.services = (catalog or {}).get("services") or {}
        self.companies = (catalog or {}).get("companies") or {}
        self.radar = radar_map or {}
        self.suffix_rules = suffix_rules
        self.by_domain = {}
        for key, service in self.services.items():
            for domain in service.get("domains") or []:
                self.by_domain.setdefault(domain.lower(), key)

    def registered(self, host):
        return self.registered_domain(host, self.suffix_rules)

    def catalog_match(self, host):
        parts = host.split(".")
        for index in range(len(parts) - 1):
            key = self.by_domain.get(".".join(parts[index:]))
            if key:
                return key
        return None

    def service_owns(self, key, host):
        domains = (self.services.get(key) or {}).get("domains") or []
        return any(host == domain or host.endswith("." + domain) for domain in domains)

    def known(self, host):
        return bool(self.catalog_match(host))

    def describe(self, host):
        key = self.catalog_match(host)
        if key:
            service = self.services[key]
            company = self.companies.get(service.get("company"), {}).get("name", "")
            return service.get("name") or key, company, service.get("category", "")
        root = self.registered(host)
        entry = self.radar.get(host) or (self.radar.get(root) if root else None)
        if entry:
            name = entry.get("displayName") or entry.get("entityName", "")
            return name, entry.get("entityName", ""), ""
        return root or host, "", ""


def site_label(host, index):
    root = index.registered(host) or host
    return root.split(".", 1)[0]


def same_company(host, target, index):
    """A sister domain of the site, such as its CDN: same Tracker Radar owner, or a name that
    starts with the site's name (stripecdn.com for stripe.com)."""
    root, target_root = index.registered(host) or host, index.registered(target) or target
    label, target_label = root.split(".", 1)[0], target_root.split(".", 1)[0]
    if len(target_label) >= 5 and label.startswith(target_label):
        return True
    owner = (index.radar.get(root) or {}).get("entityName")
    return bool(owner) and owner == (index.radar.get(target_root) or {}).get("entityName")


def is_own_domain(host, target, index):
    """The target's own hosts, plus sibling domains with the same name (example.dev for example.com)."""
    target_root = index.registered(target) or target
    root = index.registered(host) or host
    if root == target_root:
        return True
    label = site_label(target, index)
    return len(label) >= 5 and root.split(".", 1)[0] == label


def csp_hosts(header):
    hosts = set()
    for token in re.split(r"[\s;]+", header or ""):
        if token.startswith("'"):
            continue
        match = CSP_SOURCE.match(token)
        if match:
            hosts.add(match.group(1).lower().rstrip("."))
    return hosts


def fetch(url, user_agent, timeout=20, limit=None):
    req = urllib.request.Request(url, headers={"User-Agent": user_agent, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        body = response.read(limit) if limit else response.read()
        return response.status, response.headers, body


PAGE_LINK = re.compile(r"""<a\b[^>]*?\bhref\s*=\s*["']([^"'#]+)["']""", re.I)
ASSET = re.compile(r"\.(?:js|css|png|jpe?g|gif|svg|webp|ico|json|xml|txt|pdf|zip|webmanifest|woff2?)(?:\?|$)", re.I)


def read_page(url, user_agent, result):
    """Fetch one page; add its CSP hosts to result and return its HTML ('' on failure)."""
    try:
        status, headers, body = fetch(url, user_agent, limit=10_000_000)
    except urllib.error.HTTPError as error:
        result["pages_failed"] += 1
        result["status"] = result["status"] or error.code
        if not result["pages_read"]:
            result["error"] = f"HTTP {error.code} (the site may block non-browser clients)"
        return ""
    except (TimeoutError, urllib.error.URLError, ValueError) as error:
        result["pages_failed"] += 1
        if not result["pages_read"]:
            result["error"] = str(error)
        return ""
    result["status"] = result["status"] or status
    result["pages_read"] += 1
    for name in ("Content-Security-Policy", "Content-Security-Policy-Report-Only"):
        for value in headers.get_all(name) or []:
            result["csp_hosts"] |= csp_hosts(value)
    html = body.decode("utf-8", "replace")
    for meta in re.findall(r"""<meta[^>]+http-equiv=["']content-security-policy["'][^>]*>""", html, re.I):
        content = re.search(r"""content=["']([^"']+)""", meta, re.I)
        if content:
            result["csp_hosts"] |= csp_hosts(content.group(1))
    return html


def fetch_site(url, user_agent, index, *, max_pages=6, max_files=400, max_bytes=60_000_000):
    """Read the live CSP and the vendor domains named in the site's own JavaScript.

    Starts at the target page, then a few internal pages from different sections, since
    other pages often load scripts the first one does not.
    """
    result = {"status": None, "error": "", "csp_hosts": set(), "js_hosts": set(), "unmapped_js_hosts": set(),
              "pages_read": 0, "pages_failed": 0, "scripts_fetched": 0, "bytes": 0, "capped": False, "sister_hosts": []}
    page_host = urllib.parse.urlsplit(url).hostname
    own_root = index.registered(page_host) or page_host

    sister = {}

    def same_site(target_url):
        parsed = urllib.parse.urlsplit(target_url)
        if parsed.scheme != "https" or not parsed.hostname:
            return False
        if (index.registered(parsed.hostname) or parsed.hostname) == own_root:
            return True
        if parsed.hostname not in sister:
            sister[parsed.hostname] = same_company(parsed.hostname, page_host, index)
        return sister[parsed.hostname]

    first = read_page(url, user_agent, result)
    if result["status"] and result["status"] != 200:
        result["error"] = f"HTTP {result['status']} instead of the page (likely a bot challenge); only its CSP header was read"
        return result
    if not first:
        return result
    pages, sections = [], {urllib.parse.urlsplit(url).path.strip("/").split("/")[0]}
    for href in PAGE_LINK.findall(first):
        link = urllib.parse.urljoin(url, href.strip())
        parsed = urllib.parse.urlsplit(link)
        section = parsed.path.strip("/").split("/")[0]
        if parsed.hostname != page_host or ASSET.search(parsed.path) or section in sections:
            continue
        sections.add(section)
        pages.append(urllib.parse.urlunsplit(("https", page_host, parsed.path or "/", "", "")))
        if len(pages) >= max_pages - 1:
            break
    texts = [first]
    with ThreadPoolExecutor(max_workers=4) as pool:
        texts += [html for html in pool.map(lambda page: read_page(page, user_agent, result), pages) if html]
    queue = []
    for page_url, html in zip([url, *pages], texts):
        # script tags, plus .js links in preload hints and inline app data
        found = SCRIPT_SRC.findall(html) + JS_URL.findall(html) + [path for path in JS_PATH.findall(html) if not path.startswith("./")]
        queue += [u for u in (urllib.parse.urljoin(page_url, src) for src in found) if same_site(u)]
    queue = list(dict.fromkeys(queue))
    seen = set(queue)
    while queue and result["scripts_fetched"] < max_files and result["bytes"] < max_bytes:
        batch, queue = queue[:16], queue[16:]
        batch = batch[: max_files - result["scripts_fetched"]]

        def get(script_url):
            try:
                return script_url, fetch(script_url, user_agent, limit=8_000_000)[2].decode("utf-8", "replace")
            except (TimeoutError, urllib.error.URLError, ValueError):
                return script_url, ""

        with ThreadPoolExecutor(max_workers=8) as pool:
            for script_url, text in pool.map(get, batch):
                if not text:
                    continue
                result["scripts_fetched"] += 1
                result["bytes"] += len(text)
                texts.append(text)
                base = f"https://{urllib.parse.urlsplit(script_url).hostname}/"
                for path in JS_PATH.findall(text) + JS_URL.findall(text):
                    if path.startswith("./"):
                        continue
                    if "static/chunks/" in path and not path.startswith("/"):
                        path = "/_next/" + path.split("_next/", 1)[-1] if "_next/" in path else "/_next/" + path
                    nested = urllib.parse.urljoin(base, path)
                    if nested not in seen and same_site(nested):
                        seen.add(nested)
                        queue.append(nested)
    result["capped"] = bool(queue)
    result["sister_hosts"] = sorted(host for host, own in sister.items() if own)
    for text in texts:
        text = urllib.parse.unquote(text)
        for host in URL_HOST.findall(text):
            host = host.lower().rstrip(".")
            (result["js_hosts"] if index.known(host) else result["unmapped_js_hosts"]).add(host)
        for host in BARE_HOST.findall(text):
            host = host.lower()
            if index.known(host):
                result["js_hosts"].add(host)
    for key in ("js_hosts", "unmapped_js_hosts"):
        result[key] = {host for host in result[key] if not is_own_domain(host, page_host, index)}
    return result


def history_reports(host, request_json, api, current_scan_id, *, days, limit=5):
    if days <= 0:
        return []
    listing = request_json(f"{api}/websites/{urllib.parse.quote(host, safe='')}/history", missing_ok=True) or {}
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    reports = []
    for scan in listing.get("scans") or []:
        scan_id = scan.get("scan_id") or scan.get("id")
        try:
            checked = datetime.fromisoformat(str(scan.get("checked_at")).replace("Z", "+00:00"))
        except ValueError:
            continue
        if scan_id and scan_id != current_scan_id and checked >= cutoff:
            report = request_json(f"{api}/scans/{scan_id}", missing_ok=True)
            if report:
                reports.append(report)
        if len(reports) >= limit:
            break
    return reports


def report_observations(report, browser_hosts, target, index, mentions=None):
    """(tier, host or None, service dict or None) for one scanner report.

    A host only mentioned in page text (a news link, a data URL) counts when it belongs to
    a known service; the rest go to `mentions`.
    """
    observations = []
    service_hosts = {h.lower() for service in report.get("services") or [] for h in service.get("hosts") or []}
    for item in report.get("third_parties") or []:
        host = (item.get("host") or "").lower()
        if not host or is_own_domain(host, target, index):
            continue
        tier = "loaded" if host in browser_hosts else "csp_allowed" if item.get("policy_only") else "in_page_code"
        if tier == "in_page_code" and host not in service_hosts and not index.known(host):
            if mentions is not None:
                mentions.add(host)
            continue
        observations.append((tier, host, None))
    for service in report.get("services") or []:
        hosts = [h.lower() for h in service.get("hosts") or []]
        own = [h for h in hosts if is_own_domain(h, target, index)]
        context = service.get("load_context") or ""
        if len(own) < len(hosts) and not (own and context == "browser"):
            continue  # named through its third-party hosts above
        if context == "browser":
            tier = "loaded_via_site"
        elif context == "csp":
            tier = "csp_allowed"
        else:
            tier = "in_page_code"
        observations.append((tier, None, service))
    return observations


def build(report, browser_hosts, target, index, *, site=None, earlier=(), mentions=None):
    services_for_host = {}
    for source in (report, *earlier):
        for service in source.get("services") or []:
            for host in service.get("hosts") or []:
                listed = services_for_host.setdefault(host.lower(), [])
                if service.get("name") not in [known.get("name") for known in listed]:
                    listed.append(service)
    for host, listed in services_for_host.items():
        # a hosting label such as "Cloudflare" (who serves a host) must not claim another vendor's host
        services_for_host[host] = [service for service in listed if service.get("category") != "infrastructure"
                                   or index.service_owns(service.get("key"), host)]
    vendor_labels = {}
    vendors = {}

    def label_vendor(host):
        """Unnamed hosts like intercom-attachments-1.com join a vendor already in the list."""
        label = (index.registered(host) or host).split(".", 1)[0]
        for prefix, name in vendor_labels.items():
            if label != prefix and label.startswith(prefix):
                return name
        return None

    def add(tier, host, service, note=""):
        if host and not service and len(services_for_host.get(host, [])) > 1:
            for known in services_for_host[host]:
                add(tier, host, known, note)
            return
        if service:
            name, company, category = service.get("name", ""), service.get("company_name", ""), service.get("category", "")
        else:
            known = (services_for_host.get(host) or [None])[0]
            if known:
                name, company, category = known.get("name", ""), known.get("company_name", ""), known.get("category", "")
            else:
                name, company, category = index.describe(host)
                if not index.known(host):
                    name = label_vendor(host) or name
            catalog_name, catalog_company, catalog_category = index.describe(host)
            company = company or catalog_company
            category = category or catalog_category
        if not name:
            return
        if host and same_company(host, target, index):
            note = note or "same company as the site"
        if host and index.known(host):
            label = (index.registered(host) or host).split(".", 1)[0]
            if len(label) >= 5:
                vendor_labels.setdefault(label, name)
        entry = vendors.setdefault(name.lower(), {"vendor": name, "company": company, "category": category,
                                                  "tiers": set(), "hosts": set(), "notes": []})
        entry["company"] = entry["company"] or company
        entry["category"] = entry["category"] or category
        entry["tiers"].add(tier)
        if host:
            entry["hosts"].add(host)
        if note and note not in entry["notes"]:
            entry["notes"].append(note)

    observations = report_observations(report, browser_hosts, target, index, mentions)
    if site:
        observations += [("in_site_js", host, None) for host in site["js_hosts"]]
        observations += [("csp_allowed", host, None) for host in site["csp_hosts"] if not is_own_domain(host, target, index)]
    # known vendors first, so unnamed hosts can join them by name
    observations.sort(key=lambda item: (not (item[2] or (item[1] and index.known(item[1]))), RANK[item[0]]))
    for tier, host, service in observations:
        add(tier, host, service, "via the site's own domain" if tier == "loaded_via_site" else "")
    current = set(vendors)
    for older in earlier:
        date = str(older.get("checked_at", ""))[:10]
        older_browser = {(item.get("host") or "").lower() for item in older.get("third_parties") or [] if item.get("loaded")}
        for tier, host, service in report_observations(older, older_browser, target, index):
            name = (service or {}).get("name") or ((services_for_host.get(host) or [{}])[0]).get("name") or index.describe(host)[0]
            if name.lower() not in current:
                add("earlier_scan", host, service, f"{TIERS[tier]} on {date}")
    rows = []
    for entry in vendors.values():
        tiers = sorted(entry["tiers"], key=RANK.get)
        rows.append({
            "vendor": entry["vendor"], "company": entry["company"], "category": entry["category"],
            "evidence": tiers[0], "evidence_label": TIERS[tiers[0]], "all_evidence": ", ".join(tiers),
            "hosts": ", ".join(sorted(entry["hosts"])[:12]) + (" ..." if len(entry["hosts"]) > 12 else ""),
            "note": "; ".join(entry["notes"]),
        })
    rows.sort(key=lambda row: (RANK[row["evidence"]], row["vendor"].lower()))
    return rows
