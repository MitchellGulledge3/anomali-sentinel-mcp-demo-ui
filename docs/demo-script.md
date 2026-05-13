# Demo script — Anomali Sentinel MCP

Short presenter script for a 15-minute demo. Assumes data is already seeded and tools already published.

## Open (1 min)

> "Anomali ThreatStream publishes STIX 2.1 indicators into Microsoft Sentinel via the Threat Intelligence Upload API. Today I'll show you that exact path — same endpoint, same payload shape — and then we'll turn six high-value KQL questions over those indicators into callable agent tools using Sentinel custom MCP. Then I'll prompt them from a terminal."

## Step 1 — Show the seed payload (2 min)

```bash
python3 seed/upload-anomali-indicators.py \
  --workspace-id "$WORKSPACE_ID" --count 5 --dry-run | head -60
```

Point out: `"sourcesystem": "Anomali ThreatStream"`, STIX 2.1 fields (`pattern`, `pattern_type`, `valid_from`, `valid_until`, `confidence`, `labels`, `external_references` with `source_name: "Anomali ThreatStream"`).

## Step 2 — Verify ingestion (1 min)

In the Sentinel KQL pane:

```kql
ThreatIntelIndicators
| where SourceSystem == "Anomali ThreatStream"
| summarize count() by tostring(AdditionalFields.TLPLevel)
```

## Step 3 — Run the terminal demo (10 min)

```bash
python3 terminal_demo.py --show-raw
```

In order, run these prompts:

1. `Summarize Anomali ThreatStream indicators` → `Anomali_Active_Indicator_Summary`
2. `Show the highest-confidence IOCs` → `Anomali_High_Confidence_IOC_Hunt`
3. **★ `Are any Anomali IOCs hitting in our workspace right now?` → `Anomali_IOC_Match_In_Workspace`** — pause here, this is the moment.
4. `Audit Anomali feed freshness` → `Anomali_Indicator_Freshness_Audit`
5. `Track Anomali campaigns and threat actors` → `Anomali_Campaign_Tracker`
6. `Break down indicators by observable type` → `Anomali_Top_Observable_Types`

## Close (2 min)

> "Six MCP tools, one tool collection, zero new infrastructure on the Anomali side. Once these are published, any MCP-aware agent — Security Copilot, VS Code, Foundry, Claude, ChatGPT — can call them. The next step is wiring Anomali ThreatStream's real production feed in place of the synthetic seed, and adding write-side tools like 'block this IOC across our feeds.'"
