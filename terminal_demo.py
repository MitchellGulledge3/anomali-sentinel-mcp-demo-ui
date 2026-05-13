from __future__ import annotations

"""Interactive terminal demo for the Anomali Sentinel MCP tools."""

import argparse
import asyncio
import json
import os
from typing import Any

from dotenv import load_dotenv

from sentinel_mcp_demo.client import MCPToolResult, SentinelMCPClient
from sentinel_mcp_demo.mock import MockSentinelMCPClient


ANOMALI_TOOLS = {
    "summary":   "Anomali_Active_Indicator_Summary",
    "high":      "Anomali_High_Confidence_IOC_Hunt",
    "match":     "Anomali_IOC_Match_In_Workspace",
    "freshness": "Anomali_Indicator_Freshness_Audit",
    "campaign":  "Anomali_Campaign_Tracker",
    "types":     "Anomali_Top_Observable_Types",
}

TOOL_ROUTES = [
    (("match", "live", "hit", "pivot", "in our env", "workspace", "see this"), ANOMALI_TOOLS["match"]),
    (("high confidence", "high-confidence", "high conf", "top ioc", "trusted ioc"), ANOMALI_TOOLS["high"]),
    (("fresh", "stale", "expir", "hygiene", "audit", "last update"), ANOMALI_TOOLS["freshness"]),
    (("campaign", "actor", "apt", "malware family", "threat actor", "intrusion set"), ANOMALI_TOOLS["campaign"]),
    (("type", "observable", "breakdown", "by type", "ipv4", "domain", "sha"), ANOMALI_TOOLS["types"]),
    (("summary", "summarize", "posture", "overall", "feed status"), ANOMALI_TOOLS["summary"]),
]

EXAMPLE_PROMPTS = [
    "Summarize Anomali ThreatStream indicators",
    "Show the highest-confidence IOCs",
    "Are any Anomali IOCs hitting in our workspace right now?",
    "Audit Anomali feed freshness and expiring indicators",
    "Track Anomali campaigns and threat actors",
    "Break down indicators by observable type",
]


def parse_json_env(name: str, default: dict[str, Any]) -> dict[str, Any]:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{name} must be valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a JSON object.")
    return value


def render_arguments(message: str, template: str, defaults: dict[str, Any]) -> dict[str, Any]:
    rendered = template.replace("{message}", message)
    try:
        args = json.loads(rendered)
    except json.JSONDecodeError as exc:
        raise ValueError(f"MCP_TOOL_ARGUMENT_TEMPLATE rendered invalid JSON: {exc}") from exc
    if not isinstance(args, dict):
        raise ValueError("MCP_TOOL_ARGUMENT_TEMPLATE must render to a JSON object.")
    return {**args, **defaults}


def select_tool(prompt: str) -> str:
    configured = os.getenv("SENTINEL_MCP_TOOL", "").strip()
    prompt_lower = prompt.lower()
    for keywords, tool_name in TOOL_ROUTES:
        if any(keyword in prompt_lower for keyword in keywords):
            return tool_name
    return configured or ANOMALI_TOOLS["summary"]


def create_mcp_client() -> SentinelMCPClient | MockSentinelMCPClient:
    mode = os.getenv("MCP_DEMO_MODE", "mock").strip().lower()
    if mode == "real":
        return SentinelMCPClient(
            collection=os.getenv("SENTINEL_MCP_COLLECTION"),
            server_url=os.getenv("SENTINEL_MCP_SERVER_URL"),
        )
    if mode == "mock":
        return MockSentinelMCPClient()
    raise ValueError("MCP_DEMO_MODE must be 'mock' or 'real'.")


def dataset_rows(result: MCPToolResult) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in result.content:
        if item.get("type") != "text":
            continue
        text = str(item.get("text", ""))
        try:
            frames = json.loads(text)
        except json.JSONDecodeError:
            continue
        if not isinstance(frames, list):
            continue
        primary = next(
            (
                frame for frame in frames
                if isinstance(frame, dict)
                and frame.get("FrameType") == "DataTable"
                and frame.get("TableKind") == "PrimaryResult"
            ),
            None,
        )
        if not primary:
            continue
        columns = [column.get("ColumnName", "") for column in primary.get("Columns", [])]
        for row in primary.get("Rows", []):
            rows.append({columns[index]: value for index, value in enumerate(row) if index < len(columns)})
    return rows


def summarize(prompt: str, tool_name: str, rows: list[dict[str, Any]], raw_text: str) -> str:
    if not rows:
        return raw_text or f"{tool_name} completed for: {prompt}"
    row = rows[0]

    if tool_name == ANOMALI_TOOLS["summary"]:
        return (
            f"Anomali ThreatStream summary: {row.get('TotalIndicators')} active indicators "
            f"({row.get('UniqueObservables')} unique observables). "
            f"High conf: {row.get('HighConfidence')}, medium: {row.get('MediumConfidence')}, "
            f"low: {row.get('LowConfidence')}. "
            f"TLP — green:{row.get('TlpGreen')} amber:{row.get('TlpAmber')} red:{row.get('TlpRed')}."
        )
    if tool_name == ANOMALI_TOOLS["high"]:
        return (
            f"Top high-confidence Anomali IOC: {row.get('ObservableValue')} "
            f"(type {row.get('IndicatorType')}, confidence {row.get('Confidence')}). "
            f"Name: {row.get('Name')}. Labels: {row.get('Labels')}."
        )
    if tool_name == ANOMALI_TOOLS["match"]:
        return (
            f"★ Live IOC hit: {row.get('Ioc')} ({row.get('IndicatorType')}, conf {row.get('Confidence')}) "
            f"matched {row.get('HitCount')} times in {row.get('Source')}. "
            f"Sample sources: {row.get('SampleSources')}."
        )
    if tool_name == ANOMALI_TOOLS["freshness"]:
        return (
            f"Anomali feed freshness: total {row.get('Total')}, active {row.get('Active')}, "
            f"revoked {row.get('Revoked')}. Updated last 24h: {row.get('UpdatedLast24h')}. "
            f"Stale >14d: {row.get('StaleOver14d')}. Expiring soon: {row.get('ExpiringSoon')}. "
            f"Already expired: {row.get('AlreadyExpired')}."
        )
    if tool_name == ANOMALI_TOOLS["campaign"]:
        return (
            f"Anomali campaign tracker: {row.get('ActorName')} ({row.get('ActorType')}) — "
            f"aliases {row.get('ActorAliases')}, labels {row.get('ActorLabels')}. "
            f"Related indicator refs: {row.get('IndicatorRefs')}."
        )
    if tool_name == ANOMALI_TOOLS["types"]:
        return (
            f"Anomali observable types: top {row.get('IndicatorType')} — "
            f"{row.get('IndicatorCount')} indicators ({row.get('UniqueObservables')} unique). "
            f"Avg confidence {row.get('AvgConfidence')}, max {row.get('MaxConfidence')}. "
            f"Samples: {row.get('SampleObservables')}."
        )
    return f"{tool_name} returned {len(rows)} rows."


async def run_prompt(prompt: str, *, show_raw: bool) -> None:
    tool_name = select_tool(prompt)
    template = os.getenv("MCP_TOOL_ARGUMENT_TEMPLATE", '{"query":"{message}"}')
    defaults = parse_json_env("MCP_DEFAULT_ARGUMENTS", {})
    arguments = render_arguments(prompt, template, defaults)

    print(f"\nPrompt: {prompt}")
    print(f"Tool:   {tool_name}")
    print(f"Args:   {json.dumps(arguments, sort_keys=True)}")
    print("Status: calling Sentinel MCP...\n")

    client = create_mcp_client()
    await client.connect()
    try:
        result = await client.call_tool(tool_name, arguments)
    finally:
        await client.close()

    rows = dataset_rows(result)
    raw_text = result.text or json.dumps(result.content, indent=2)
    print("Summary")
    print("-------")
    print(summarize(prompt, tool_name, rows, raw_text))

    if show_raw:
        print("\nRaw MCP result")
        print("--------------")
        print(raw_text)


async def interactive_loop(show_raw: bool) -> None:
    print("Anomali Sentinel MCP Terminal Demo")
    print("Type a prompt and press Enter. Type 'examples' to list prompts or 'quit' to exit.\n")
    print("Examples:")
    for prompt in EXAMPLE_PROMPTS:
        print(f"  - {prompt}")

    while True:
        try:
            prompt = input("\nanomali-mcp> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if not prompt:
            continue
        if prompt.lower() in {"quit", "exit", "q"}:
            return
        if prompt.lower() == "examples":
            for example in EXAMPLE_PROMPTS:
                print(f"  - {example}")
            continue

        try:
            await run_prompt(prompt, show_raw=show_raw)
        except Exception as exc:
            print(f"Error: {exc}")


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Run the Anomali Sentinel MCP terminal demo.")
    parser.add_argument("--prompt", help="Run one prompt and exit instead of starting the interactive loop.")
    parser.add_argument("--show-raw", action="store_true", help="Print the formatted raw MCP/Kusto result.")
    args = parser.parse_args()

    if args.prompt:
        asyncio.run(run_prompt(args.prompt, show_raw=args.show_raw))
    else:
        asyncio.run(interactive_loop(show_raw=args.show_raw))


if __name__ == "__main__":
    main()
