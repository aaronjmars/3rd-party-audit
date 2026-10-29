"""Offline tests: no network, no public scan. Run with `python -m unittest discover -s tests`."""

import csv
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import zipfile
from unittest import mock
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parent.parent / "skills" / "third-party-scan" / "scripts"


def load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scan = load("scan")
reputation = load("reputation")
vendors = load("vendors")

PSL = """// ===BEGIN ICANN DOMAINS===
com
org
uk
co.uk
*.ck
!www.ck
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io
// ===END PRIVATE DOMAINS===
"""

REPORT = {
    "domain": "example.com",
    "scan_id": 42,
    "checked_at": "2026-10-29T12:00:00+00:00",
    "report_url": "https://whogetsmydata.com/website/example.com",
    "method": "browser",
    "representative": True,
    "limitations": [],
    "third_parties": [
        {"host": "cdn.vendor.com", "service": "vendor-cdn", "company": "vendor"},
        {"host": "pixel.tracker.org", "service": "tracker", "company": "tracker"},
        {"host": "allowed.example.org", "policy_only": True},
        {"host": "someone.github.io"},
    ],
    "services": [
        {"key": "vendor-cdn", "name": "Vendor CDN", "company_name": "Vendor Inc", "category": "cdn"},
        {"key": "tracker", "name": "Tracker", "company_name": "Tracker LLC", "category": "analytics"},
    ],
    "recipients": [],
}

REQUESTS = [
    {"url": "https://cdn.vendor.com/lib.js?v=1", "type": "script", "third_party": True, "found_in": "browser"},
    {"url": "https://pixel.tracker.org/p.gif", "type": "image", "third_party": True, "found_in": "browser"},
    {"url": "https://someone.github.io/app.js", "type": "script", "third_party": True, "found_in": "browser"},
    {"url": "https://example.com/self.js", "type": "script", "third_party": False, "found_in": "browser"},
    {"url": "https://linked.example.org/", "type": "link", "third_party": True, "found_in": "static_html"},
]


class TargetTests(unittest.TestCase):
    def test_normalize_target(self):
        self.assertEqual(scan.normalize_target("Example.com"), ("example.com", "/", "https://example.com/"))
        self.assertEqual(scan.normalize_target("https://www.example.com/shop")[1], "/shop")
        for bad in ("http://example.com", "https://example.com:8443", "https://1.2.3.4", "localhost",
                    "https://user:pw@example.com", "https://example.com/?token=x", "intranet.local"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                scan.normalize_target(bad)

    def test_www_matches_apex_report(self):
        self.assertEqual(scan.site_key("www.example.com"), scan.site_key("example.com"))
        self.assertNotEqual(scan.site_key("docs.example.com"), scan.site_key("example.com"))

    def test_same_page(self):
        self.assertTrue(scan.same_page("https://www.example.com/shop/", "/shop"))
        self.assertTrue(scan.same_page("/shop", "/shop"))
        self.assertFalse(scan.same_page(None, "/shop"))
        self.assertFalse(scan.same_page("/other", "/shop"))

    def test_report_without_evidence(self):
        self.assertIsNone(scan.evidence_url({"evidence": None}))
        self.assertFalse(scan.is_fresh({"checked_at": "2026-10-29T12:00:00Z", "evidence": None}, 24))


class SuffixTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        path = Path(self.directory.name) / "psl.dat"
        path.write_text(PSL, encoding="utf-8")
        self.public, self.private = reputation.load_suffix_rules(path, refresh=False)

    def tearDown(self):
        self.directory.cleanup()

    def test_registered_domain(self):
        rules = self.public | self.private
        self.assertEqual(reputation.registered_domain("a.b.example.co.uk", rules), "example.co.uk")
        self.assertEqual(reputation.registered_domain("cdn.vendor.com", rules), "vendor.com")
        self.assertEqual(reputation.registered_domain("x.foo.ck", rules), "x.foo.ck")
        self.assertEqual(reputation.registered_domain("www.ck", rules), "www.ck")
        self.assertIsNone(reputation.registered_domain("1.2.3.4", rules))

    def test_shared_hosting(self):
        self.assertEqual(reputation.shared_hosting_suffix("someone.github.io", self.private), "github.io")
        self.assertIsNone(reputation.shared_hosting_suffix("cdn.vendor.com", self.private))


CATALOG = {
    "companies": {"intercom": {"name": "Intercom, Inc."}, "google": {"name": "Google LLC"}},
    "services": {
        "intercom": {"name": "Intercom", "company": "intercom", "category": "customer_support", "domains": ["intercom.io", "intercomcdn.com"]},
        "google-analytics": {"name": "Google Analytics", "company": "google", "category": "analytics", "domains": ["google-analytics.com"]},
        "google-tag-manager": {"name": "Google Tag Manager", "company": "google", "category": "tag_manager", "domains": ["googletagmanager.com"]},
        "cloudflare": {"name": "Cloudflare", "category": "infrastructure", "domains": ["cloudflare.com"]},
        "sentry": {"name": "Sentry", "category": "monitoring", "domains": ["sentry.io"]},
        "debugbear": {"name": "DebugBear RUM", "category": "monitoring", "domains": ["debugbear.com"]},
    },
}


class VendorTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        path = Path(self.directory.name) / "psl.dat"
        path.write_text(PSL, encoding="utf-8")
        public, _ = reputation.load_suffix_rules(path, refresh=False)
        radar = {"news.com": {"entityName": "News Corp"}, "bnbstatic.com": {"entityName": "Binance Holdings Ltd."},
                 "binance.com": {"entityName": "Binance Holdings Ltd."}}
        self.index = vendors.VendorIndex(CATALOG, radar, public, reputation.registered_domain)

    def tearDown(self):
        self.directory.cleanup()

    def test_csp_hosts(self):
        header = "default-src 'self'; script-src 'nonce-x' https://*.intercom.io cdn.example.org:443 data: https:; connect-src wss://ws.pusher.com"
        self.assertEqual(vendors.csp_hosts(header), {"intercom.io", "cdn.example.org", "ws.pusher.com"})

    def test_own_domains(self):
        self.assertTrue(vendors.is_own_domain("static.example.com", "example.com", self.index))
        self.assertTrue(vendors.is_own_domain("example.dev", "www.example.com", self.index))
        self.assertFalse(vendors.is_own_domain("intercom.io", "example.com", self.index))

    def test_sister_cdn_domains(self):
        self.assertTrue(vendors.same_company("b.stripecdn.com", "stripe.com", self.index))
        self.assertTrue(vendors.same_company("bin.bnbstatic.com", "www.binance.com", self.index))
        self.assertFalse(vendors.same_company("news.com", "binance.com", self.index))
        self.assertFalse(vendors.same_company("cdn.vendor.com", "stripe.com", self.index))

    def test_js_links_in_html(self):
        html = '<link rel="modulepreload" href="https://www.example.com/assets/c_Ke.js"><script>x={"u":"//cdn.example.com/a/b.mjs?v=1"}</script>'
        self.assertEqual(vendors.JS_URL.findall(html), ["https://www.example.com/assets/c_Ke.js", "//cdn.example.com/a/b.mjs"])

    def test_build_merges_every_source(self):
        report = {
            "third_parties": [
                {"host": "www.googletagmanager.com"},
                {"host": "widget.intercom.io"},
                {"host": "news.com"},
                {"host": "www.sentry.io"},
                {"host": "intercom-attachments-1.com", "policy_only": True},
            ],
            "services": [
                {"key": "google-analytics", "name": "Google Analytics", "load_context": "browser",
                 "hosts": ["example.com", "www.googletagmanager.com"]},
                {"key": "google-tag-manager", "name": "Google Tag Manager", "load_context": "browser",
                 "hosts": ["www.googletagmanager.com"]},
                {"key": "cloudflare", "name": "Cloudflare", "category": "infrastructure", "load_context": "browser",
                 "hosts": ["example.com", "widget.intercom.io"]},
                {"key": "segment", "name": "Segment", "load_context": "browser", "hosts": ["example.com"]},
            ],
        }
        earlier = [{"checked_at": "2026-10-01T00:00:00Z",
                    "third_parties": [{"host": "cdn.debugbear.com", "loaded": True}], "services": []}]
        site = {"js_hosts": {"o1.ingest.sentry.io"}, "csp_hosts": {"api.intercom.io", "example.com"}}
        mentions = set()
        rows = vendors.build(report, {"www.googletagmanager.com", "widget.intercom.io"}, "example.com", self.index,
                             site=site, earlier=earlier, mentions=mentions)
        by_name = {row["vendor"]: row for row in rows}
        self.assertEqual(by_name["Google Tag Manager"]["evidence"], "loaded")
        self.assertEqual(by_name["Google Analytics"]["evidence"], "loaded")
        self.assertEqual(by_name["Intercom"]["evidence"], "loaded")
        self.assertIn("intercom-attachments-1.com", by_name["Intercom"]["hosts"])
        self.assertEqual(by_name["Cloudflare"]["evidence"], "loaded_via_site")
        self.assertNotIn("widget.intercom.io", by_name["Cloudflare"]["hosts"])
        self.assertEqual(by_name["Segment"]["evidence"], "loaded_via_site")
        self.assertEqual(by_name["Sentry"]["evidence"], "in_page_code")
        self.assertIn("in_site_js", by_name["Sentry"]["all_evidence"])
        self.assertEqual(by_name["DebugBear RUM"]["evidence"], "earlier_scan")
        self.assertIn("2026-10-01", by_name["DebugBear RUM"]["note"])
        self.assertEqual(mentions, {"news.com"})
        self.assertNotIn("News Corp", by_name)


class OfflineRunTest(unittest.TestCase):
    def test_full_offline_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = json.dumps({"requests": REQUESTS}).encode()
            report = dict(REPORT, evidence={"sha256": hashlib.sha256(evidence).hexdigest(),
                                            "download_url": "https://whogetsmydata.com/scan/42/evidence.zip"})
            (root / "report.json").write_text(json.dumps(report), encoding="utf-8")
            with zipfile.ZipFile(root / "evidence.zip", "w") as archive:
                archive.writestr("evidence.json", evidence)
            (root / "psl.dat").write_text(PSL, encoding="utf-8")
            with zipfile.ZipFile(root / "tranco.zip", "w") as archive:
                archive.writestr("top-1m.csv", "1,google.com\n500,vendor.com\n\n")
            (root / "radar.json").write_text(json.dumps({"tracker.org": {"entityName": "Tracker LLC"}}), encoding="utf-8")
            (root / "prevalence.json").write_text(json.dumps({"Tracker LLC": {"total": 0.05}}), encoding="utf-8")
            (root / "usage.json").write_text(json.dumps([{"domain": "cdn.vendor.com", "totalOccurrences": 250000}]), encoding="utf-8")
            (root / "rdap.json").write_text(json.dumps({"vendor.com": "2005-01-01T00:00:00Z"}), encoding="utf-8")
            (root / "mime.json").write_text(json.dumps({"cdn.vendor.com": "text/javascript"}), encoding="utf-8")
            out = root / "out"
            result = subprocess.run(
                [sys.executable, "-I", str(SCRIPTS / "scan.py"), "www.example.com", "--offline",
                 "--report-json", str(root / "report.json"), "--evidence-zip", str(root / "evidence.zip"),
                 "--psl-cache", str(root / "psl.dat"), "--tranco-zip", str(root / "tranco.zip"),
                 "--tracker-radar-map", str(root / "radar.json"), "--tracker-radar-prevalence", str(root / "prevalence.json"),
                 "--third-party-web-usage", str(root / "usage.json"), "--rdap-cache", str(root / "rdap.json"),
                 "--mime-overrides", str(root / "mime.json"), "--cache-dir", str(root / "cache"), "--output-dir", str(out)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads(result.stdout)
            self.assertEqual(summary["browser_third_party_hosts"], 3)
            self.assertEqual(summary["csp_only_hosts"], 1)
            with (out / "scored.csv").open(newline="", encoding="utf-8") as source:
                scored = {row["host"]: row for row in csv.DictReader(source)}
            self.assertEqual(set(scored), {"cdn.vendor.com", "pixel.tracker.org", "someone.github.io"})
            vendor = scored["cdn.vendor.com"]
            self.assertEqual(vendor["exposure"], "confirmed_js")
            self.assertEqual((vendor["footprint_risk_score_0_100"], vendor["risk_level"]), ("62", "high"))
            self.assertEqual(scored["pixel.tracker.org"]["risk_level"], "low")
            self.assertEqual([(row["host"], row["risk_level"]) for row in summary["top_risks"][:2]], [("someone.github.io", "high"), ("cdn.vendor.com", "high")])
            self.assertEqual(vendor["tranco_rank"], "500")
            self.assertEqual(vendor["http_archive_pages_observed"], "250000")
            self.assertEqual(scored["pixel.tracker.org"]["exposure"], "pixel_or_image")
            self.assertEqual(scored["pixel.tracker.org"]["tracker_radar_owner_alignment"], "agrees")
            shared = scored["someone.github.io"]
            self.assertEqual(shared["exposure"], "script_tagged_mime_unknown")
            self.assertEqual(shared["score_confidence"], "lower")
            self.assertTrue(shared["score_note"].startswith("Shared hosting"))
            self.assertIn("vendors", summary)
            for name in ("report.json", "evidence.zip", "inventory.csv", "scored.csv", "summary.json", "vendors.csv"):
                self.assertTrue((out / name).exists(), name)

    def test_mime_falls_back_to_get_when_head_refused(self):
        response = mock.MagicMock()
        response.__enter__.return_value.headers.get_content_type.return_value = "application/javascript"
        refused = urllib.error.HTTPError("https://cdn.vendor.com/a.js", 403, "Forbidden", {}, None)
        with mock.patch.object(scan.urllib.request, "urlopen", side_effect=[refused, response]) as opened:
            self.assertEqual(scan.mime_for_url("https://cdn.vendor.com/a.js"), "application/javascript")
        second = opened.call_args_list[1].args[0]
        self.assertEqual((second.get_method(), second.get_header("Range")), ("GET", "bytes=0-0"))

    def test_mime_unreachable_host_skips_get(self):
        with mock.patch.object(scan.urllib.request, "urlopen", side_effect=urllib.error.URLError("down")) as opened:
            self.assertIsNone(scan.mime_for_url("https://cdn.vendor.com/a.js"))
        self.assertEqual(opened.call_count, 1)

    def test_tampered_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("evidence.json", "{}")
            with self.assertRaises(ValueError):
                scan.evidence_from_zip(path, "0" * 64)


if __name__ == "__main__":
    unittest.main()
