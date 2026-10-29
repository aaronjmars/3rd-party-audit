# Scoring details

`scripts/reputation.py` scores an inventory CSV with at least `host`, `service`, `operator`, `evidence`, `browser_requests`, `script_tagged_requests`, and `resource_types`. Only `evidence=browser request` rows are scored; reference-only and CSP-only hosts stay separate. `scan.py` calls it for you; run it directly only to rescore an edited inventory (`--help` lists its flags).

## Formulas

- **Reputation signal score** (`reputation_score_0_100`): 40 baseline, plus 20 for an identified publisher, up to 20 for registered-domain age (1, 2, 5, or 10 years), and up to 20 for Tranco rank (top 1M, 100K, or 10K).
- **Footprint score** (`reputation_footprint_score_0_100`): the same, but the Tranco points are replaced by up to 20 points for measured third-party adoption, using HTTP Archive page-count or Tracker Radar reach bands.
- **Risk score** (`risk_score_0_100`, `footprint_risk_score_0_100`): 60% observed exposure plus 40% inverse reputation, so a host scores high when its code gets a lot of access to the page and little is publicly known about it. `risk_level` bands the footprint risk score: `high` 60+, `medium` 40-59, `low` below 40. Rows are sorted by `footprint_risk_score_0_100`. Exposure classes, highest first: `confirmed_js`, `script_tagged_mime_unknown`, `iframe`, `websocket_attempt` and `api_or_xhr`, `other`, `pixel_or_image`. A WebSocket request record does not prove the connection succeeded.

Missing signals add zero points and lower `score_confidence`. These are public-footprint proxies, not security grades.

## Data sources

- [Tranco Top 1M](https://tranco-list.eu/top-1m.csv.zip), refreshed daily.
- Domain age from authoritative registries via [IANA's RDAP map](https://data.iana.org/rdap/dns.json), falling back to `whois` for country-code domains. Results are cached in `rdap.json`.
- The [Public Suffix List](https://publicsuffix.org/list/public_suffix_list.dat). Its private-domain section withholds parent-domain age and popularity credit for shared hosting (for example `*.github.io`) unless the publisher is documented. Do not infer that a hosting provider owns tenant code.
- [DuckDuckGo Tracker Radar](https://github.com/duckduckgo/tracker-radar) `domain_map.json` and `entity_prevalence.json`: a candidate owner and the fraction of its crawled top sites that contacted that entity. **License CC BY-NC-SA 4.0**: check its terms before commercial reuse.
- The newest dated [Third Party Web observed-domain dataset](https://github.com/patrickhulce/third-party-web/tree/master/data): the number of HTTP Archive **pages** (not customers or distinct websites) that requested the exact hostname. The selected file URL is recorded in the output.

Absent from a dataset means unmeasured, not unused. Keep the scanner owner and independent owner side by side when they disagree (`tracker_radar_owner_alignment`); a conflicting publisher label does not get the other entity's prevalence. If a dataset cannot be downloaded and no cached copy exists, the run continues without it and `summary.json` lists it as `null`. Supply local copies with `--tranco-zip`, `--tracker-radar-map`, `--tracker-radar-prevalence`, `--third-party-web-usage` (+ `--third-party-web-source`), and `--psl-cache`.

## Overrides

All are JSON files; each entry should carry the source URL that backs it.

- `--owner-overrides`, keyed by host: `{"cdn.example.net": {"operator": "Example Inc", "publisher_domain": "example.com", "source": "https://..."}}`. Use only publisher identities backed by the publisher's own documentation.
- `--mime-overrides`, keyed by host: `{"cdn.example.net": "application/javascript"}`, for response types you actually checked.
- `--company-sizes`, keyed by publisher: `{"Example Inc": {"employees": 1200, "as_of": "2026-10-01", "source": "https://..."}}`.

Company headcount is shown separately because coverage is uneven. One optional source is the [Apollo Organization Enrichment API](https://docs.apollo.io/reference/organization-enrichment) (`estimated_num_employees`, 1 credit per company, needs an Apollo account): never spend credits without the user's approval. Without a reliable size source, leave the field blank rather than infer headcount from domain traffic. Free Wikidata employee counts can be old; inspect their point-in-time date before using them.
