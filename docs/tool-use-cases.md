# Tool use cases — Anomali Sentinel MCP demo

For each MCP tool: what it answers, why Anomali is uniquely positioned to power it, and the analyst story.

## 1. `Anomali_Active_Indicator_Summary`

**Question:** *"What does our Anomali ThreatStream feed look like right now?"*

**Analyst story:** Executive / lead engineer wants one-line health on the TIP integration. The tool returns total active indicators, breakdown by type, confidence buckets (high / medium / low / unscored), and TLP marking distribution (white/green/amber/red). This is the screen Anomali shows during a QBR.

**Why Anomali:** Anomali curates IOCs across hundreds of sources; the confidence and TLP signals are Anomali's IP, not Microsoft's. The MCP tool surfaces those Anomali-specific signals through a Copilot prompt.

---

## 2. `Anomali_High_Confidence_IOC_Hunt`

**Question:** *"Show me Anomali's most trusted IOCs so I can prioritize detections."*

**Analyst story:** Detection engineer building a new analytics rule. Filters to `Confidence >= 80`, active, not revoked. Returns observable, name, description, labels, kill-chain phase, and Anomali external_id for one-click pivot back to ThreatStream UI.

**Why Anomali:** confidence-scoring is the differentiator vs. raw open-source feeds. This is where Anomali's analyst-curated trust shines.

---

## 3. ★ `Anomali_IOC_Match_In_Workspace` (FLAGSHIP)

**Question:** *"Are any indicators Anomali is tracking firing in MY environment right now?"*

**Analyst story:** This is the SOC's #1 question every shift. The tool joins active Anomali indicators (IPv4 / domain / URL) against `CommonSecurityLog` and `DnsEvents` over the last 24h and returns the matched observable, hit count, sample sources, and the Anomali confidence + labels behind each match.

**Why this is the flagship:** the value of a TIP isn't the size of the feed — it's whether anything in the feed is actually in your traffic. One MCP call answers that. EDR doesn't know which IOCs Anomali tracks; Anomali's UI doesn't see customer telemetry. Only Sentinel + MCP closes the loop.

---

## 4. `Anomali_Indicator_Freshness_Audit`

**Question:** *"Is the Anomali feed healthy and current?"*

**Analyst story:** TIP admin or content engineer needs to detect ingestion gaps. Returns total / active / revoked / deleted counts, last-24h and last-7d update volume, indicators stale >14d, indicators expiring soon, and a breakdown by `LastUpdateMethod` (so you can see when `LogARepublisher` vs `ThreatIntelUploadAPI` last ran).

**Why Anomali:** ThreatStream is the system of record for indicator lifecycle. This tool surfaces the lifecycle metadata Anomali already attaches to each indicator.

---

## 5. `Anomali_Campaign_Tracker`

**Question:** *"Which threat actors and campaigns is Anomali tracking, and which indicators relate to each?"*

**Analyst story:** Threat-intel team wants the actor-centric view. Pulls from `ThreatIntelObjects` (where threat-actor, campaign, intrusion-set, malware, and relationship STIX objects land) and joins via `relationship` objects to surface the indicator refs each actor owns.

**Why Anomali:** non-indicator STIX objects are where Anomali's analyst content lives — actor profiles, campaign descriptions, malware families. Most TIPs publish only indicators; Anomali ships the structured intel around them.

---

## 6. `Anomali_Top_Observable_Types`

**Question:** *"What's the shape of Anomali's feed by observable type?"*

**Analyst story:** Detection engineer sizing coverage. Returns counts and average / max confidence per type (ipv4-addr, domain-name, url, file:sha256, file:sha1, file:md5, email-addr), plus sample observables. Useful for deciding which analytic rules to invest in.

**Why Anomali:** Anomali normalizes IOC types across hundreds of feeds. The breakdown reflects Anomali's curation, not raw feed shape.

---

## How these chain in a Security Copilot session

```
Anomali_Active_Indicator_Summary
   ↓
Anomali_Top_Observable_Types        (coverage shape)
   ↓
Anomali_High_Confidence_IOC_Hunt    (which IOCs to trust)
   ↓
Anomali_IOC_Match_In_Workspace ★    (are they in our env right now?)
   ↓
Anomali_Campaign_Tracker            (what actor/campaign is behind the hit?)
   ↓
Anomali_Indicator_Freshness_Audit   (was this feed up-to-date when the hit happened?)
```

A Copilot agent can plan that chain itself. Each step is one MCP call.
