# Sample tool runs

These are the actual JSON responses returned by each MCP tool when run live
against a Microsoft Sentinel workspace that had **205 Anomali ThreatStream
indicators + 3 threat-actor objects** seeded via
[`seed/upload-anomali-indicators.py`](../seed/upload-anomali-indicators.py).

- Workspace region: `westus2`
- Run date: 2026-05-13
- Source: `ThreatIntelIndicators` / `ThreatIntelObjects` tables
- Per-tool raw JSON: [`docs/sample-runs/`](./sample-runs/)

Use these as a reference for what each tool returns so you can:
1. Validate your own seed run produced comparable output before publishing
   the tools.
2. Show partners / customers concrete evidence the demo works end-to-end.
3. Wire up downstream Security Copilot prompts against a known response shape.

---

## 1. `Anomali_Active_Indicator_Summary`

Executive roll-up of every active Anomali indicator in the workspace.

```json
{
  "ByType": "{\"domain-name\":1,\"file:sha256\":1,\"ipv4-addr\":1,\"email-addr\":1,\"url\":1}",
  "FirstCreated": "2026-05-13T19:41:12Z",
  "HighConfidence": "107",
  "LastModified": "2026-05-13T19:41:12Z",
  "LowConfidence": "29",
  "MediumConfidence": "69",
  "TlpAmber": "0",
  "TlpGreen": "0",
  "TlpRed": "0",
  "TlpWhite": "0",
  "TotalIndicators": "205",
  "UniqueObservables": "83",
  "Unscored": "0"
}
```

**Highlights:** 205 total, 107 high-confidence, 5 distinct indicator types,
83 unique observable values. Useful as the "are we connected and ingesting"
status check at the top of a Security Copilot session.

---

## 2. `Anomali_High_Confidence_IOC_Hunt`

Top 100 indicators with `Confidence >= 80`, each with the Anomali
ThreatStream external reference URL preserved for analyst pivot.

```json
{
  "Confidence": "100",
  "Created": "2026-05-13T19:41:12Z",
  "Description": "Anomali ThreatStream malicious IPv4 indicator (demo).",
  "ExtRefs": "[{\"external_id\":\"anomali-6df12b8560d6\",\"source_name\":\"Anomali ThreatStream\",\"url\":\"https://ui.threatstream.com/detail/indicator/anomali-6df12b8560d6\"}]",
  "Id": "QW5vbWFsaSBUaHJlYXRTdHJlYW0=---indicator--9ffe5a8c-731f-45b3-b80f-67563cdd20b0",
  "IndicatorType": "ipv4-addr",
  "KillChain": "[{\"kill_chain_name\":\"lockheed-martin-cyber-kill-chain\",\"phase_name\":\"exploitation\"}]",
  "Labels": "[\"exploit-kit\",\"credential-theft\",\"malware\"]",
  "Modified": "2026-05-13T19:41:12Z",
  "Name": "Anomali ThreatStream IP IOC 203.0.113.3",
  "ObservableValue": "203.0.113.3",
  "Pattern": "[ipv4-addr:value = '203.0.113.3']"
}
```

**Returned:** 100 rows (truncated to top 100 by Confidence/Modified).
Full payload in [`sample-runs/Anomali_High_Confidence_IOC_Hunt.json`](./sample-runs/Anomali_High_Confidence_IOC_Hunt.json).

---

## 3. `Anomali_Indicator_Freshness_Audit`

Lifecycle / hygiene view — answers "is our Anomali feed healthy?"

```json
{
  "Active": "205",
  "AlreadyExpired": "0",
  "ByUpdateMethod": "{\"ThreatIntelligenceUploadIndicatorsAPI\":1}",
  "Deleted": "0",
  "ExpiringSoon": "3",
  "NewestModified": "2026-05-13T19:41:12Z",
  "OldestModified": "2026-05-13T19:41:12Z",
  "Revoked": "0",
  "StaleOver14d": "0",
  "Total": "205",
  "UpdatedLast24h": "205",
  "UpdatedLast7d": "205"
}
```

**Highlights:** `ByUpdateMethod` confirms all 205 indicators came in via
`ThreatIntelligenceUploadIndicatorsAPI` — i.e., the new TI Upload API path,
not the deprecated `tiIndicators` endpoint.

---

## 4. `Anomali_Campaign_Tracker`

The three threat-actor STIX objects published alongside the indicators.

```json
[
  {
    "ActorCreated": "2026-05-13T19:41:21Z",
    "ActorId": "QW5vbWFsaSBUaHJlYXRTdHJlYW0=---threat-actor--6386451c-0450-4415-ac75-761af887f2a2",
    "ActorLabels": "[\"nation-state\",\"anomalithreatstream\"]",
    "ActorModified": "2026-05-13T19:41:21Z",
    "ActorName": "APT29",
    "ActorType": "threat-actor"
  },
  {
    "ActorName": "FIN7",
    "ActorLabels": "[\"criminal\",\"anomalithreatstream\"]",
    "ActorType": "threat-actor"
  },
  {
    "ActorName": "Lazarus Group",
    "ActorLabels": "[\"criminal\",\"anomalithreatstream\"]",
    "ActorType": "threat-actor"
  }
]
```

`IndicatorRefs` are empty here because the demo seeds actors as standalone
STIX objects; in a real Anomali tenant the `relationship` objects link them
to specific indicators and the tool will surface those refs.

---

## 5. `Anomali_Top_Observable_Types`

Coverage breakdown by indicator type with sample observables.

```json
[
  {
    "IndicatorType": "ipv4-addr",
    "IndicatorCount": "75",
    "UniqueObservables": "37",
    "AvgConfidence": "74.29",
    "MaxConfidence": "100",
    "HighConfidenceCount": "40",
    "SampleObservables": ["198.51.100.18","198.51.100.9","203.0.113.21","203.0.113.3","203.0.113.5"]
  },
  {
    "IndicatorType": "domain-name",
    "IndicatorCount": "70",
    "UniqueObservables": "11",
    "AvgConfidence": "69.29",
    "MaxConfidence": "100",
    "HighConfidenceCount": "31",
    "SampleObservables": ["phish-login.example.com","rare-beacon.bad-example.test","sliver-cnc.bad-example.test","emotet-delivery.bad-example.test","fastflux-c2.example.test"]
  },
  {
    "IndicatorType": "url",
    "IndicatorCount": "29",
    "UniqueObservables": "11",
    "AvgConfidence": "76.69",
    "MaxConfidence": "100",
    "HighConfidenceCount": "18"
  }
]
```

(file-hash and email rows omitted for brevity — see
[`sample-runs/Anomali_Top_Observable_Types.json`](./sample-runs/Anomali_Top_Observable_Types.json)
for the full set.)

---

## 6. `Anomali_IOC_Match_In_Workspace` ★ flagship

Pivots active Anomali indicators against `CommonSecurityLog` + `DnsEvents`
to answer **"are we seeing any Anomali-tracked threats right now in
our own telemetry?"** — the one question a TIP can't answer alone.

```json
[]
```

The demo workspace had no `CommonSecurityLog` or `DnsEvents` data, so the
join produced 0 matches. The query uses `union isfuzzy=true` so this is a
clean empty result rather than a semantic error.

**In a real customer workspace with network telemetry**, expect rows of:

```json
{
  "Ioc": "203.0.113.3",
  "IndicatorType": "ipv4-addr",
  "IocName": "Anomali ThreatStream IP IOC 203.0.113.3",
  "IocLabels": "[\"exploit-kit\",\"credential-theft\",\"malware\"]",
  "Source": "CommonSecurityLog",
  "HitCount": 17,
  "FirstSeen": "2026-05-13T03:11:00Z",
  "LastSeen": "2026-05-13T18:42:00Z",
  "SampleSrc": ["10.4.2.18","10.4.2.39"],
  "SampleDev": ["pa-fw-edge-01"],
  "MaxConfidence": 100
}
```

This is the row that turns "we have an Anomali feed" into "we have an
Anomali-driven detection."
