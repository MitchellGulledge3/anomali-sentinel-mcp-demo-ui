# Working session guide — Anomali Sentinel MCP demo

This is the script for a live working session with an Anomali ThreatStream developer. It mirrors the working-session guide used for the Gigamon/Veeam/Rubrik/BigID repos.

## Roles

- **Microsoft host**: drives the screen, runs the commands, narrates each step.
- **Anomali developer**: confirms identity / permissions, suggests adjustments specific to their ThreatStream tenant.

## Preflight (5 min)

1. Confirm Azure subscription and Sentinel-enabled workspace.
2. Run `az login` and `az account show` together.
3. Find the workspace customer ID:
   ```bash
   az monitor log-analytics workspace show \
     --resource-group <rg> --workspace-name <ws> \
     --query customerId -o tsv
   ```
4. Confirm the identity has **Microsoft Sentinel Contributor** on the workspace (needed for both the TI Upload API and MCP publish).

## Step 1 — Seed Anomali indicators (5 min)

This is the part Anomali developers care about most. We use the **real** Threat Intelligence Upload Indicators API, with `sourcesystem: "Anomali ThreatStream"`.

```bash
export REPO_ROOT=$(pwd)
export WORKSPACE_ID=<workspace-customer-id>

# Optional preview
python3 "$REPO_ROOT/seed/upload-anomali-indicators.py" \
  --workspace-id "$WORKSPACE_ID" --count 5 --dry-run

# Real upload
python3 "$REPO_ROOT/seed/upload-anomali-indicators.py" \
  --workspace-id "$WORKSPACE_ID" --count 200 --include-actors
```

Talk track:

> "This is the exact API Anomali ThreatStream uses for the Sentinel Upload Indicators connector. The script wraps your STIX 2.1 objects in `sourcesystem + stixobjects` and POSTs to `https://api.ti.sentinel.azure.com/...` — same payload shape, same endpoint, same auth path. The only thing different in production is the source: real ThreatStream feeds instead of these synthetic indicators."

Wait 5 minutes, then verify in Sentinel:

```kql
ThreatIntelIndicators
| where SourceSystem == "Anomali ThreatStream"
| summarize Indicators=count(), FirstSeen=min(Created), LastSeen=max(Modified)
```

## Step 2 — Publish MCP tools (5 min)

```bash
python3 scripts/publish-mcp-tools.py \
  --collection Anomali-Sentinel-MCP-Demo \
  --workspace-id "$WORKSPACE_ID"
```

Talk track:

> "Each KQL file in `mcp-tools/` becomes a callable MCP tool. Sentinel hosts the collection — no Anomali server-side work to run a tool registry. You publish, the customer's Copilot / VS Code / Foundry agent calls."

## Step 3 — Run the terminal demo (10 min)

```bash
cp .env.example .env
# edit .env → MCP_DEFAULT_ARGUMENTS={"workspaceId":"<id>"}

python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python3 terminal_demo.py --show-raw
```

Demo flow (run in this order):

1. `Summarize Anomali ThreatStream indicators` — sets the baseline ("we have N active, M high-confidence...")
2. `Show the highest-confidence IOCs` — drills into the most-trusted indicators
3. `Are any Anomali IOCs hitting in our workspace right now?` ★ — **the flagship moment**. This joins indicators against live workspace telemetry. Even with synthetic data, this is the question every SOC asks.
4. `Audit Anomali feed freshness` — shows TIP hygiene story
5. `Track Anomali campaigns and threat actors` — uses the `ThreatIntelObjects` table for non-indicator STIX objects
6. `Break down indicators by observable type` — answers "what's in the feed"

## Customization points for the developer

| Want to | Edit |
| --- | --- |
| Add a new MCP tool | Drop a `.kql` file in `mcp-tools/`, add an entry to `DESCRIPTIONS` in `scripts/publish-mcp-tools.py`, rerun publisher |
| Change the source system label | Edit `SOURCE_SYSTEM` in `seed/upload-anomali-indicators.py` and the `where SourceSystem == ...` clause in every `.kql` |
| Use real ThreatStream data | Skip the seed step entirely; have the customer's existing Upload API or TAXII connector populate the tables — the MCP tools work unchanged |
| Add an Anomali-specific argument (e.g. `confidenceFloor`) | Extend the `arguments` schema in `tool_payload()` and parameterize the KQL with `let confidenceFloor = toint(confidenceFloor);` |

## Wrap (5 min)

- Save the published collection name; share with the Anomali product owner.
- Suggest follow-up: an Anomali-hosted MCP server that **writes** indicators on demand (e.g. "block this IOC across our feeds") — a natural extension to the read-only tools here.
