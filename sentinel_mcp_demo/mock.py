from __future__ import annotations

"""Mock MCP client used when the Anomali terminal demo runs without Azure connectivity."""

import json
from typing import Any

from .client import MCPTool, MCPToolResult


class MockSentinelMCPClient:
    """Return deterministic MCP-like results for offline presenter practice."""

    def __init__(self) -> None:
        self.tools = [
            MCPTool(
                name="Anomali_Active_Indicator_Summary",
                description="Summarize active Anomali ThreatStream indicators by type, confidence, TLP, freshness.",
                input_schema={"type": "object", "properties": {"workspaceId": {"type": "string"}}},
            ),
            MCPTool(
                name="Anomali_High_Confidence_IOC_Hunt",
                description="Surface high-confidence (>=80) Anomali indicators with labels and ThreatStream pivot.",
                input_schema={"type": "object", "properties": {"workspaceId": {"type": "string"}}},
            ),
            MCPTool(
                name="Anomali_IOC_Match_In_Workspace",
                description="Pivot Anomali IOCs against CommonSecurityLog + DnsEvents for live matches.",
                input_schema={"type": "object", "properties": {"workspaceId": {"type": "string"}}},
            ),
            MCPTool(
                name="Anomali_Indicator_Freshness_Audit",
                description="Audit feed hygiene: stale/expiring indicators, last-update method, ingestion gaps.",
                input_schema={"type": "object", "properties": {"workspaceId": {"type": "string"}}},
            ),
            MCPTool(
                name="Anomali_Campaign_Tracker",
                description="Surface threat-actor / campaign / malware STIX objects from ThreatStream.",
                input_schema={"type": "object", "properties": {"workspaceId": {"type": "string"}}},
            ),
            MCPTool(
                name="Anomali_Top_Observable_Types",
                description="Break down active indicators by observable type with sample observables.",
                input_schema={"type": "object", "properties": {"workspaceId": {"type": "string"}}},
            ),
        ]

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def list_tools(self) -> list[MCPTool]:
        return self.tools

    async def call_tool(self, tool_name: str, arguments: dict[str, Any] | None = None) -> MCPToolResult:
        args = arguments or {}
        workspace = args.get("workspaceId") or "mock-workspace"
        text = {
            "Anomali_Active_Indicator_Summary": (
                f"Anomali active indicator summary for {workspace}: 1,847 active indicators.\n"
                "- By type: ipv4-addr 742, domain-name 561, url 268, file:sha256 197, email-addr 79\n"
                "- High confidence (>=80): 1,015 | medium: 524 | low: 308\n"
                "- TLP: green 924, amber 461, white 369, red 93\n"
                "- Recommended next tool: Anomali_High_Confidence_IOC_Hunt or Anomali_IOC_Match_In_Workspace"
            ),
            "Anomali_High_Confidence_IOC_Hunt": (
                f"High-confidence Anomali IOCs for {workspace} (top 5 of 1,015):\n"
                "- 203.0.113.18  (conf 95, c2, trickbot)  — Anomali external_id anomali-3f29a8c1\n"
                "- rare-beacon.bad-example.test  (conf 92, c2, cobalt-strike)\n"
                "- https://phish-login.example.com/payload  (conf 88, phishing, credential-theft)\n"
                "- SHA-256 a14e...  (conf 85, loader, emotet)\n"
                "- Recommended next tool: Anomali_IOC_Match_In_Workspace"
            ),
            "Anomali_IOC_Match_In_Workspace": (
                f"★ Live IOC matches in {workspace} (last 24h):\n"
                "- 203.0.113.18  → 14 CommonSecurityLog hits  (confidence 95, label c2/trickbot)\n"
                "- rare-beacon.bad-example.test  → 7 DnsEvents hits  (confidence 92)\n"
                "- https://phish-login.example.com/payload  → 3 CommonSecurityLog hits  (confidence 88)\n"
                "- Recommended action: isolate top source IPs, escalate to incident response"
            ),
            "Anomali_Indicator_Freshness_Audit": (
                f"Anomali feed freshness audit for {workspace}:\n"
                "- Total: 2,140 | active 1,847 | revoked 168 | deleted 125\n"
                "- Updated last 24h: 412 | last 7d: 1,624 | stale >14d: 86\n"
                "- Expiring within 7d: 137 | already expired: 42\n"
                "- LastUpdateMethod: ThreatIntelUploadAPI 1,902 | LogARepublisher 238\n"
                "- Recommended action: triage 86 stale indicators, schedule refresh"
            ),
            "Anomali_Campaign_Tracker": (
                f"Anomali threat-actor / campaign tracker for {workspace}:\n"
                "- TA505  (criminal, anomalithreatstream) — 47 related indicators\n"
                "- APT29  (nation-state) — 31 related indicators\n"
                "- Wizard Spider  (criminal) — 22 related indicators\n"
                "- Recommended next tool: Anomali_IOC_Match_In_Workspace to pivot indicators into telemetry"
            ),
            "Anomali_Top_Observable_Types": (
                f"Anomali observable-type breakdown for {workspace}:\n"
                "- ipv4-addr 742  (avg conf 79, max 100)\n"
                "- domain-name 561  (avg conf 77, max 99)\n"
                "- url 268  (avg conf 72, max 95)\n"
                "- file:sha256 197  (avg conf 84, max 100)\n"
                "- email-addr 79  (avg conf 68, max 92)"
            ),
        }.get(tool_name, f"Mock result for {tool_name}:\n{json.dumps(args, indent=2)}")

        return MCPToolResult(
            tool_name=tool_name,
            content=[{"type": "text", "text": text}],
            is_error=False,
        )
