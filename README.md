# Third-party audit

**Find every outside service a website runs, and which ones to review first.**

`third-party-scan` is an agent skill and a standalone Python script. Give it a domain and it lists the website's third parties (scripts, trackers, embeds, APIs, CDNs), shows the evidence for each one, and ranks the hosts whose code runs on the page by risk.

Why it matters: in June 2026, attackers stole about $3M from Polymarket users without touching its servers or contracts. They compromised [a third-party vendor that injected a malicious script into the frontend](https://cside.com/blog/polymarket-client-side-supply-chain-attack). Every outside script a site loads can do the same. This tool shows you that list.

## Quick start

```sh
npx skills add aaronjmars/3rd-party-audit
```

Then ask your agent: *"Which third-party scripts does example.com load, and which are riskiest?"*

Or run it directly, no install needed:

```sh
git clone https://github.com/aaronjmars/3rd-party-audit
python3 3rd-party-audit/skills/third-party-scan/scripts/scan.py example.com
```

## What you get

One run takes 5 to 30 seconds once the datasets are cached (a brand new public scan can add a few minutes). Example for `aeon.fun` (2026-10-29), shortened:

**`vendors.csv`: every vendor, with its strongest evidence**

| Vendor | Company | Evidence |
|---|---|---|
| Google Tag Manager | Google LLC | loaded |
| Umami | Umami Software, Inc. | loaded |
| unpkg | unpkg | loaded |
| PostHog | PostHog Inc. | in_page_code |
| Sentry | Functional Software, Inc. | in_page_code |
| GitHub | GitHub, Inc. | in_site_js |
| Stripe | Stripe, Inc. | csp_allowed |
| WalletConnect | Reown (WalletConnect) | csp_allowed |

**`scored.csv`: risk for each host the browser loaded**

| Host | Publisher | Exposure | Risk | Level |
|---|---|---|---|---|
| cloud.umami.is | Umami Software, Inc. | confirmed_js | 66 | high |
| unpkg.com | unpkg | confirmed_js | 62 | high |
| www.googletagmanager.com | Google LLC | confirmed_js | 60 | high |
| gateway.umami.is | Umami Software, Inc. | api_or_xhr | 40 | medium |
| region1.google-analytics.com | Google LLC | api_or_xhr | 30 | low |

On a bigger site the list grows fast: polymarket.com gives 105 vendors, 18 of them actually running on the homepage.

## How it works

The script merges six sources into one vendor list and gives each vendor its strongest evidence:

| Evidence | What it means | Source |
|---|---|---|
| `loaded` | the browser requested it | a real browser scan by [WhoGetsMyData](https://whogetsmydata.com) (reused if under 24 hours old), with a verified evidence file |
| `loaded_via_site` | it runs through the site's own domain | services the scanner detected behind the site's domain, such as a proxied tracker or the site's CDN |
| `in_page_code` | named in the page, not requested | the page HTML and inline scripts |
| `in_site_js` | named in the site's own code | up to 6 pages of the site and their JavaScript, including the site's own CDN domains |
| `csp_allowed` | only allowed, never seen | the site's Content Security Policy, the live header and the scanned copy |
| `earlier_scan` | seen in a past scan only | public scans of the site from the last 30 days |

Hosts that are only mentioned in page text, such as news links, are kept out of the vendor list. Vendor names come from the scanner, then the WhoGetsMyData service catalog (about 3,000 services), then DuckDuckGo Tracker Radar.

**Risk score (0-100)** = 60% exposure + 40% unknown-ness.
- **Exposure** is how much the host's code can do on the page. Running JavaScript scores highest, then iframes, API calls and WebSockets; a tracking pixel scores lowest.
- **Unknown-ness** is 100 minus a public footprint score: whether the publisher is identified, how old the domain is, and how widely the host is used across the web (HTTP Archive, Tracker Radar).

Levels: high 60+, medium 40-59, low under 40. The score ranks what to review first. It does not mean a vendor is unsafe, and no vendor is called compromised for being present. Formulas and data sources: [references/scoring.md](skills/third-party-scan/references/scoring.md).

## Install

| Where | How |
|---|---|
| Any skills-aware agent (Claude Code, Codex, Cursor, Gemini CLI...) | `npx skills add aaronjmars/3rd-party-audit` |
| Claude Code plugin | `/plugin install third-party-scan --marketplace aaronjmars/3rd-party-audit` |
| Claude Code older than 2.1.275 | `/plugin marketplace add aaronjmars/3rd-party-audit`, then `/plugin install third-party-scan@3rd-party-audit` |
| By hand | copy `skills/third-party-scan/` into `~/.claude/skills/`, `~/.codex/skills/` or your agent's skills folder |

Needs Python 3.9 or newer, standard library only, nothing to `pip install`. The first run downloads about 24 MB of public datasets into a temp cache. `whois` is optional.

## Usage

```sh
python3 scan.py example.com                          # whole site (www. is fine)
python3 scan.py https://example.com/checkout         # one page
python3 scan.py example.com --wait 300               # wait up to 5 min for a new scan
python3 scan.py example.com --no-site-fetch --no-mime-check   # quiet: no direct contact
python3 scan.py example.com --no-submit              # never send a new public scan
```

| Option | Does |
|---|---|
| `--wait SECONDS` | keep checking a running scan instead of exiting with code 75 |
| `--refresh` | send a new scan even if a recent one exists |
| `--max-age-hours N` | reuse reports up to N hours old (default 24) |
| `--no-submit` | only read existing public reports |
| `--no-site-fetch` | do not read the site's pages and code |
| `--no-mime-check` | do not contact vendors' script servers |
| `--site-pages N`, `--max-site-scripts N` | how much of the site to read (default 6 pages, 400 files) |
| `--history-days N` | how far back to merge past scans (default 30, 0 = off) |
| `--output-dir DIR` | where results go (default `./third-party-scans/<host>-<scan-id>/`) |
| `--offline` | no network, from saved files (`--report-json`, `--evidence-zip`, `--psl-cache`) |

`--help` lists the rest (local dataset copies and owner, MIME or company-size overrides). Exit codes: `0` done, `1` failed, `75` scan still running. Stdout is the summary as JSON, warnings go to stderr.

**Output files:** `vendors.csv` (all vendors), `scored.csv` (risk per loaded host), `summary.json` (counts, coverage, top risks, data sources), `inventory.csv` (every host and its evidence), `report.json` and `evidence.zip` (the raw scan), `page-mentions.txt` and `site-js-hosts.txt` (hosts that matched no known vendor).

## Who sees your scan

| Who | What they see | Turn it off |
|---|---|---|
| WhoGetsMyData | the domain or page you scan; the report becomes public on whogetsmydata.com | `--no-submit` (existing reports only) |
| The target site | up to 6 page loads and 400 file downloads from your IP | `--no-site-fetch` |
| The site's vendors | one small request per external script, from your IP | `--no-mime-check` |

Direct requests carry an honest User-Agent, `third-party-scan (+https://github.com/aaronjmars/3rd-party-audit)`, so sites with bot walls may refuse them; the summary then says so. Never scan account pages or URLs with tokens in them.

## Limits

- It sees what a logged-out visitor's browser loads. Login, wallet, deposit and payment flows are only covered if the scan reached them, and a script injected for some users only may not show up.
- `in_site_js` and `csp_allowed` show what could run, not what did.
- Bot walls (Amazon WAF, Cloudflare challenges) can block the site read; the vendor list then rests on the public scan.
- Hosts with no entry in any catalog keep their domain as the vendor name.

## Data sources and credits

- [WhoGetsMyData](https://whogetsmydata.com/api): browser scans, evidence files and the service catalog. Free and keyless; reuse needs attribution and a link to the site's report (`report_url` in the summary).
- [Tranco](https://tranco-list.eu) top 1M ranking, [IANA RDAP](https://data.iana.org/rdap/dns.json) and WHOIS for domain age, the [Public Suffix List](https://publicsuffix.org).
- [DuckDuckGo Tracker Radar](https://github.com/duckduckgo/tracker-radar): vendor owners and reach. **CC BY-NC-SA 4.0**, check its terms before commercial use.
- [Third Party Web](https://github.com/patrickhulce/third-party-web): HTTP Archive usage counts.

## Development

```sh
python3 -m unittest discover -s tests -v
```

The tests run offline on built-in sample data and never send a scan. CI runs them on Linux, macOS and Windows with Python 3.9 and 3.13. The agent instructions live in [SKILL.md](skills/third-party-scan/SKILL.md).

## License

MIT, see [LICENSE](LICENSE). Made by Aaron Elijah Mars.
