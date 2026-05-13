# TI Upload Indicators API — quick reference

Authoritative source: https://learn.microsoft.com/azure/sentinel/stix-objects-api

## Endpoint

```
POST https://api.ti.sentinel.azure.com/workspaces/{workspaceId}/threat-intelligence-stix-objects:upload?api-version=2024-02-01-preview
```

- `{workspaceId}` is the Log Analytics **workspace customer ID** (GUID), not the Azure resource ID.
- `api-version=2024-02-01-preview` at time of writing.

## Authentication

- OAuth 2.0 bearer token in the `Authorization: Bearer <token>` header.
- Token audience: `https://management.azure.com` (the ARM resource).
- Caller's identity needs `Microsoft.SecurityInsights/threatIntelligence/upload-stix-objects/action` — granted by the built-in role **Microsoft Sentinel Contributor**.

## Request body

```json
{
  "sourcesystem": "Anomali ThreatStream",
  "stixobjects": [ /* STIX 2.0 or 2.1 objects */ ]
}
```

- `sourcesystem` is required, and **must not** be `"Microsoft Sentinel"`. After upload it surfaces in `ThreatIntelIndicators.SourceSystem` and `ThreatIntelObjects.SourceSystem`.
- `stixobjects` is an array of STIX objects. Common types: `indicator`, `threat-actor`, `campaign`, `intrusion-set`, `malware`, `attack-pattern`, `identity`, `relationship`.

## Indicator object — common fields used by Anomali

| Field | Required | Notes |
| --- | --- | --- |
| `type` | yes | `"indicator"` |
| `spec_version` | yes | `"2.1"` |
| `id` | yes | `indicator--<uuid>` |
| `created` / `modified` | yes | ISO-8601 UTC, ends in `Z` |
| `pattern` | yes | STIX pattern: `[ipv4-addr:value = '1.2.3.4']`, `[domain-name:value = 'x.test']`, `[url:value = '...']`, `[file:hashes.'SHA-256' = '...']`, `[email-addr:value = '...']` |
| `pattern_type` | yes | usually `"stix"` |
| `valid_from` | yes | when the indicator becomes valid |
| `valid_until` | optional | when it expires; surfaces as `Data.valid_until` |
| `name` / `description` | optional | analyst-friendly text |
| `labels` | optional | array of strings (e.g. `["apt","c2","trickbot"]`) |
| `confidence` | optional | 0–100; surfaces as `ThreatIntelIndicators.Confidence` |
| `indicator_types` | optional | array (e.g. `["malicious-activity"]`) |
| `kill_chain_phases` | optional | array of `{kill_chain_name, phase_name}` |
| `external_references` | optional | array of `{source_name, external_id, url}` — Anomali uses this to backlink to the ThreatStream UI |
| `object_marking_refs` | optional | TLP marking IDs; surface as `AdditionalFields.TLPLevel` |

## Limits (enforced)

| Limit | Value |
| --- | --- |
| STIX objects per request | **100** |
| Requests per minute | **100** |
| Throughput | ~10,000 objects/minute |

Throttled responses return **HTTP 429**. The seed script in this repo batches at 100 and pauses between batches implicitly via the API call latency; for sustained ingest, add a `time.sleep(0.6)` between batches to stay under 100 req/min.

## Where the data lands

| STIX object kind | Sentinel table |
| --- | --- |
| `indicator` | `ThreatIntelIndicators` |
| `threat-actor`, `campaign`, `intrusion-set`, `malware`, `attack-pattern`, `identity`, `relationship`, etc. | `ThreatIntelObjects` |

> Important: the **legacy `ThreatIntelligenceIndicator` table was retired on July 31, 2025.** All new ingestion goes to `ThreatIntelIndicators` and `ThreatIntelObjects`. Update any analytics rules, workbooks, and detection content that still query the legacy table. This is the migration Michael Spence (Anomali engineering) has been working on.
