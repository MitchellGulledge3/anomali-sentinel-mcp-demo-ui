# Publish KQL files as Sentinel custom MCP tools — UI walkthrough

This repo intentionally has **no publisher script**. Instead, you save each KQL query in `mcp-tools/` as a custom Sentinel MCP tool by hand, using the **Save as tool** flow in the Microsoft Defender portal's Advanced Hunting experience.

This is the same outcome as a script-based publish, just via the UI. Use this when you want to demo the no-code path or when API publishing is not available in your tenant.

---

## Prerequisites

From the official docs:

- A workspace with **Microsoft Sentinel data lake** enabled and a **Microsoft Defender** license.
- One of these roles to create custom tools: **Security Operator**, **Security Admin**, or **Global Admin**.
- **Security Reader** or **Global Reader** to invoke them later.

Reference: [Create and use custom Microsoft Sentinel MCP tools (preview)](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-create-custom-tool)

---

## Step 0 — Seed Anomali indicators first

The KQL queries in this repo read from `ThreatIntelIndicators` / `ThreatIntelObjects` filtered to `SourceSystem == "Anomali ThreatStream"`. If your workspace has no Anomali data yet, run the seed step from the main README before continuing — otherwise the **Run** step (step 3 below) will return zero rows and the **Save as tool** option may stay disabled.

```bash
export WORKSPACE_ID=<workspace-customer-id>
python3 seed/upload-anomali-indicators.py --workspace-id "$WORKSPACE_ID" --count 200 --include-actors
```

Wait 5–10 minutes for ingestion before opening Advanced Hunting.

---

## Step-by-step

Repeat steps 1–6 once **per `.kql` file** in `mcp-tools/`.

### 1. Open the Defender portal Advanced Hunting page

Go to https://security.microsoft.com → **Investigation & response** → **Hunting** → **Advanced hunting**.

### 2. Paste the KQL query

Open the matching `mcp-tools/<ToolName>.kql` file in this repo, copy the full query, and paste it into the Advanced Hunting query window.

### 3. Run the query at least once to confirm it returns rows

This validates the query against the workspace before you save it as a tool. If it returns 0 rows, top up demo data with the seed script (step 0) before continuing.

### 4. Click **Save as tool**

Two places to find this:

- **Context menu** (right-click) on the saved query
- **KQL query box menu** (the "..." or kebab menu in the editor)

See the screenshots in the [official docs](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-create-custom-tool#create-custom-tools-with-kql-queries).

### 5. Fill in the **Save tool** flyout

| Field | What to enter |
| --- | --- |
| **Name** | Use the `.kql` filename (without extension), e.g. `Anomali_IOC_Match_In_Workspace`. The name should be discoverable so the AI model picks the right tool. |
| **Description** | Copy the matching description from the table at the bottom of this file. |
| **Collection** | First time through, click **Create new collection** and use `Anomali-Sentinel-MCP-Demo`. After that, pick the same collection for the remaining tools. |
| **Default workspace** | Pick the workspace you seeded Anomali indicators into. This becomes the default `workspaceId` used by the agent if a prompt doesn't specify one. |
| **Parameters (optional)** | Leave empty — the queries in this repo don't reference any `{ParameterName}` placeholders. |

### 6. Click **Save**

The tool is now visible in your custom MCP collection and any agent connected to that collection can call it.

---

## Verify the tools are live

After saving all six tools:

1. In the Defender portal go to **Sentinel** → **MCP** → **Tool collections** (or follow the link in the Save tool confirmation toast).
2. Confirm the collection exists with your six tools listed.
3. The collection MCP server URL is:

   ```
   https://sentinel.microsoft.com/mcp/custom/<your collection name>
   ```

   Use that URL when wiring the collection into VS Code, Copilot Studio, Foundry, or the terminal demo in this repo.

---

## Use the tools you just created

Once the tools are saved in the UI, point the included terminal demo at the collection (no script needed):

```bash
cd <this repo>
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env so SENTINEL_MCP_COLLECTION matches the collection name you typed in step 5
python3 terminal_demo.py --show-raw
```

Or wire the collection into another surface using these official guides:

- [Visual Studio Code](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-use-tool-visual-studio-code)
- [Microsoft Copilot Studio](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-use-tool-copilot-studio)
- [Microsoft Foundry](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-use-tool-azure-ai-foundry)
- [ChatGPT or Claude](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-chatgpt-claude-connector)

---

## Useful links

- [Create and use custom Microsoft Sentinel MCP tools (preview)](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-create-custom-tool)
- [Tool collection in Microsoft Sentinel MCP server (overview)](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-tools-overview)
- [Get started with Microsoft Sentinel MCP server](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-get-started)
- [Best practices for tool descriptions](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-create-custom-tool)
- [Advanced hunting in Microsoft Defender](https://learn.microsoft.com/defender-xdr/advanced-hunting-microsoft-defender)
- [Import threat intelligence to Microsoft Sentinel with the upload API](https://learn.microsoft.com/azure/sentinel/stix-objects-api)

---

## Per-tool details for this repo

Suggested **collection name:** `Anomali-Sentinel-MCP-Demo`

| `.kql` file | Tool name (use as-is) | Description |
| --- | --- | --- |
| `mcp-tools/Anomali_Active_Indicator_Summary.kql` | `Anomali_Active_Indicator_Summary` | Summarize active Anomali ThreatStream indicators by type, confidence bucket, TLP marking, and freshness. |
| `mcp-tools/Anomali_High_Confidence_IOC_Hunt.kql` | `Anomali_High_Confidence_IOC_Hunt` | Surface the highest-confidence active Anomali indicators (Confidence >= 80) with labels, kill-chain phase, and ThreatStream external_id for analyst pivot. |
| `mcp-tools/Anomali_IOC_Match_In_Workspace.kql` | `Anomali_IOC_Match_In_Workspace` | ★ Pivot Anomali IPv4 / domain / URL indicators against CommonSecurityLog and DnsEvents to find live IOC matches in the workspace over the last 24h. Highest-value tool — answers "are we seeing these threats right now?" |
| `mcp-tools/Anomali_Indicator_Freshness_Audit.kql` | `Anomali_Indicator_Freshness_Audit` | Audit Anomali feed hygiene: active vs revoked, last-update method breakdown, indicators stale > 14d, expiring within 7d, already expired. |
| `mcp-tools/Anomali_Campaign_Tracker.kql` | `Anomali_Campaign_Tracker` | Surface Anomali threat-actor / campaign / malware STIX objects from `ThreatIntelObjects` and the indicators they relate to via STIX `relationship` objects. |
| `mcp-tools/Anomali_Top_Observable_Types.kql` | `Anomali_Top_Observable_Types` | Break down active Anomali indicators by observable type (ipv4, domain, url, sha256, email) with average confidence and sample observables. |
