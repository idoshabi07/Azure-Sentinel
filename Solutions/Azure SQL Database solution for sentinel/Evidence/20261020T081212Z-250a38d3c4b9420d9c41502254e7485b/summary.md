# Migration evidence — Azure SQL Database solution for sentinel

Solution: **Azure SQL Database solution for sentinel**
Run: `20261020T081212Z-250a38d3c4b9420d9c41502254e7485b`
Profile: **authoring**
Recorded workflow status: **blocked**
Current solution version at export: **3.0.0** (not a packaging claim)
Requested version action: **none**
Requested target solution version: **unknown (not recorded)** (not a packaged version)
Evidence exported at (UTC): **2026-10-20T08:17:59.469724+00:00**
Evidence exporter: **sentinel-xdr-migration 0.1.0** (export tool, not historical run version)
Exporter Python: **3.12.10**

**This is a local, curated snapshot, not trusted attestation or a new test run.**
Reported passes are not independently verified. Missing evidence is not a pass.
Content hashes describe export-time bytes, not proof of what historical tests ran.

## All workflow stages

| Stage | Recorded status | Attempts |
| --- | --- | --- |
| discovery | passed | 1 |
| conversion | blocked | 1 |
| validation | pending | 0 |
| packaging | pending | 0 |
| deployment | notRequired | 0 |
| mockIngestion | notRequired | 0 |
| alertParity | notRequired | 0 |
| report | pending | 0 |

## Evidence coverage

| Report | Availability | Recorded status | Items | Recorded item outcomes |
| --- | --- | --- | --- | --- |
| conversion | available | unknown | 10 | converted=10 |
| structural | missing | unknown | 0 | not-recorded |
| runtimeGraph | missing | unknown | 0 | not-recorded |
| runtimeTriage | missing | unknown | 0 | not-recorded |
| runtimeLogAnalytics | missing | unknown | 0 | not-recorded |
| runtimeAzureMonitorSdk | missing | unknown | 0 | not-recorded |
| packaging | missing | unknown | 0 | not-recorded |
| queryParity | missing | unknown | 0 | not-recorded |
| alertParity | missing | unknown | 0 | not-recorded |
| solutionReport | missing | unknown | 0 | not-recorded |

See `evidence.json` for every result (including failures, blocks and not-run),
relative paths, hashes, version decisions and provenance mismatches.

Source-query provenance mismatches detected: **0**.
Missing/unsupported provenance remains unverified, even when this count is zero.

## Limitations

- Raw messages, provider records, alerts, credentials and lab identities are omitted.
- Historical commands/tool versions and baseline decisions have no supported persisted contract.
- New runtime reports bind results to the exact source or Advanced Hunting query hash; legacy or mismatched hashes are stale/unbound. Hashes do not attest that a provider executed the query.
- Unknown fields/statuses are excluded or marked unknown, never interpreted as success.
- This directory is never read as workflow state or included in Marketplace packages.
