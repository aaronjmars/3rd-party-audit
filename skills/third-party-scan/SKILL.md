---
name: third-party-scan
description: Inventory a website's browser-visible third parties, identify their publishers, estimate cross-site adoption, score public reputation signals, and rank frontend supply-chain risks. Use when given a domain or URL to check external scripts, trackers, vendors, or weak links.
license: MIT
compatibility: Needs Python 3.9+ (standard library only) and internet access. The `whois` command is optional.
---

# Third-party scan

Given a domain or public URL, produce a sourced inventory of outside services and a short, evidence-based review queue. A vendor's presence is never evidence that it is compromised.

## Run the scanner

`scripts/scan.py` sits next to this file. Call it by its absolute path from any directory:

```sh
python3 <skill-dir>/scripts/scan.py example.com              # whole site (www. is fine)
python3 <skill-dir>/scripts/scan.py https://example.com/shop # one page
```

It reuses a WhoGetsMyData report checked within 24 hours (`--max-age-hours`), otherwise submits at most one public scan. Then it verifies the evidence hash, builds the browser-request inventory, merges every other source into one vendor list (see below), downloads current public reputation datasets (about 24 MB, cached for a day to a week), sends HEAD requests (or a 1-byte GET when HEAD is refused) to observed third-party script URLs to check their response type, and scores every browser-requested host. Outputs go to `./third-party-scans/<host>-<scan-id>/` (`--output-dir` to change): `vendors.csv` (every vendor, one row each), `scored.csv` (risk per loaded host), `inventory.csv`, `report.json`, `evidence.zip`, `response-mime.json`, `summary.json`, plus `page-mentions.txt` and `site-js-hosts.txt` for hosts that did not match a known vendor. Stdout is the summary as JSON; warnings go to stderr.

Exit codes: `0` done, `1` failed (message on stderr), `75` the scan is still running. On `75`, rerun the same command later, or pass `--wait 300` to keep checking for up to that many seconds; the script never submits a second scan for the same run.

Useful flags:

- `--no-submit`: only read reports that already exist; never send the site to the public scanner.
- `--refresh`: submit a new scan even when a recent report exists.
- `--no-mime-check`: do not contact third-party script hosts.
- `--no-site-fetch`: do not read the site's own pages and JavaScript. `--site-pages` (default 6) and `--max-site-scripts` (default 400) bound that read.
- `--history-days`: how far back to merge earlier public scans (default 30, `0` turns it off).
- `--report-json` + `--evidence-zip`: work from saved files. Add `--offline` (with `--psl-cache`) for no network at all.
- `--owner-overrides`, `--mime-overrides`, `--company-sizes`: supply checked facts, each with its source URL. See [references/scoring.md](references/scoring.md).

Before running, normalize the input to its hostname and keep the exact URL if the user named a particular page. Use only the named site. The scan is public: never submit account pages, tokens, or private URLs. If the script cannot run, follow [references/manual-workflow.md](references/manual-workflow.md) instead.

## Full vendor list

`vendors.csv` answers "which outside services does this site use" in one pass. It merges six sources and gives each vendor its strongest evidence:

| `evidence` | Meaning |
|---|---|
| `loaded` | the browser requested one of its hosts in the scan |
| `loaded_via_site` | the scanner saw it run through the site's own domain (a proxied tracker such as Segment, or the CDN in front of the site) |
| `in_page_code` | a known service named in the page HTML or inline scripts, not requested |
| `in_site_js` | a known vendor domain named in the site's own JavaScript, read from up to 6 pages in different sections, including code on the site's own CDN domains (same Tracker Radar owner, or a name like `stripecdn.com` for `stripe.com`) |
| `csp_allowed` | only allowed by the Content Security Policy (the scanned copy plus the live header) |
| `earlier_scan` | seen only in an earlier public scan within `--history-days` (the note says what and when) |

`all_evidence` lists every source that matched. Hosts only mentioned in page text, such as news links, are not vendors; they go to `page-mentions.txt`. Vendor names come from the scanner, then the WhoGetsMyData service catalog, then Tracker Radar; an unknown host keeps its domain as the name. Present the list grouped by evidence, strongest first, and say that `in_site_js` and `csp_allowed` show what could run, not what did. A site behind a bot wall may refuse the site read; the summary's `vendors.site_fetch.error` says so, and the list then rests on the scan.

## Read the results

1. Check `representative`, `method`, `checked_at` and `limitations` in `summary.json`. A bot-block page, source-only scan, or public homepage does not show what a signed-in user receives, and the scanner has not exercised a login, wallet, or payment flow unless the report says so.
2. `inventory.csv` separates three kinds of host. `browser request` means the browser fetched it in the scanned flow. `reference only` means it appeared in HTML or script text (often a plain outbound link, which is not a loaded integration). `csp only` means the Content Security Policy allows it, with no request seen.
3. A request `type` of `script` can reflect the embedding tag rather than the bytes. `executable_js` in `scored.csv` is `yes` only when the response type was checked; an image pixel requested through a script tag is not executable code. Unchecked types stay `unknown`.
4. When the user names a flow the scanner did not cover, capture it with a headless browser (any browser automation the agent has) or [urlscan's Result API](https://docs.urlscan.io/pages/result-api-reference), and say which flows were tested. A capture is a snapshot of that page, region, consent state, and time.

## Rank the risks

The risk score says how much harm a host could do if its code went bad, weighted by how little public track record it has. It is not a verdict that a provider is vulnerable. Rank candidates by concrete exposure:

- Highest: an external script confirmed to execute in the site's own page on login, wallet, payment, or another sensitive flow; a tag manager that can add scripts; an unexpected new script or changed host. Record its URL and the page or flow. A script loaded inside a cross-origin iframe has a different security boundary, so do not assume it can read the site's page.
- Next: external scripts on other pages, then cross-origin authentication or payment iframes and API integrations. Check for an integrity hash on a direct external script only when the page source makes that possible. Missing or unknown integrity is context, not proof of compromise.
- Lower: analytics endpoints, pixels, static assets, RPC calls, and infrastructure. CSP-only hosts belong in a separate "allowed, not observed" list until a request confirms use.

For the top candidates, check current first-party vendor advisories, status pages, and credible incident reporting. A CVE or package advisory applies only when the affected product and version are identified. Label ownership, version, integrity, and incident status `unknown` when unverified. Never infer that a named vendor is the breached one from co-occurrence on the page. Do not probe or exploit third-party systems as part of this inventory.

## Scores

`scored.csv` scores every browser-requested host; reference-only and CSP-only hosts are not scored. `reputation_footprint_score_0_100` is 40 baseline, plus 20 for an identified publisher, up to 20 for registered-domain age, and up to 20 for measured third-party adoption. `footprint_risk_score_0_100` weights observed exposure at 60% and inverse reputation at 40%; `risk_level` is `high` at 60 or more, `medium` at 40 to 59, `low` below 40. Missing signals add zero points and lower `score_confidence`. These are transparent public-footprint proxies, not security grades, malware verdicts, or proof of a compromised vendor. Formula details, datasets, overrides, and license notes are in [references/scoring.md](references/scoring.md).

## Report

Lead with scan time and coverage. When the user asks which third parties a site uses, answer from `vendors.csv` grouped by evidence. Otherwise give one compact table of observed or detected integrations and a separate short list of CSP-only possibilities. When scoring was requested, give the score formula, the top three to five risks, and the full scored CSV. Link the website report and any source used for a publisher or incident claim. State plainly when no actual weakness was verified.

The WhoGetsMyData API allows reuse with attribution and a link to the site's report (`report_url` in the summary).
