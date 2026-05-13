from __future__ import annotations

"""Seed Anomali-shaped STIX 2.1 indicators into Microsoft Sentinel via the
Threat Intelligence Upload Indicators API.

This script is the Anomali equivalent of the LogSeeder step used by the other
partner demos in this series (Gigamon, Veeam, Rubrik, BigID). Anomali data
doesn't land in a custom *_CL table — it goes into Sentinel's managed
ThreatIntelIndicators / ThreatIntelObjects tables. The supported way to
populate those tables programmatically is the Threat Intelligence Upload API:

    POST https://api.ti.sentinel.azure.com/workspaces/{workspaceId}/threat-intelligence-stix-objects:upload?api-version=2024-02-01-preview

This is the same API Anomali ThreatStream uses for the
"Upload Indicators API" connector, so the payload shape and SourceSystem value
match what a real Anomali tenant would push.

References:
  https://learn.microsoft.com/azure/sentinel/stix-objects-api
  https://learn.microsoft.com/azure/sentinel/connect-threat-intelligence-upload-api
"""

import argparse
import datetime
import json
import random
import subprocess
import sys
import urllib.error
import urllib.request
import uuid

API_VERSION = "2024-02-01-preview"
UPLOAD_RESOURCE = "https://management.azure.com"
UPLOAD_HOST = "https://api.ti.sentinel.azure.com"
SOURCE_SYSTEM = "Anomali ThreatStream"

# Anomali ThreatStream commonly publishes these labels alongside indicators.
LABEL_POOL = [
    "anomalithreatstream", "apt", "c2", "phishing", "malware", "ransomware",
    "trojan", "loader", "infostealer", "rat", "exploit-kit", "credential-theft",
    "high", "medium", "low",
]

KILL_CHAIN_PHASES = [
    {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "reconnaissance"},
    {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "delivery"},
    {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "exploitation"},
    {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "command-and-control"},
    {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "actions-on-objectives"},
]

# Sample observable pools — RFC5737 / RFC2606 / example.com / TLD `.test`
# safe-by-design ranges so demo data never collides with real assets.
IPV4_POOL = [f"203.0.113.{i}" for i in range(2, 30)] + [f"198.51.100.{i}" for i in range(2, 20)]
DOMAIN_POOL = [
    "rare-beacon.bad-example.test", "phish-login.example.com", "fastflux-c2.example.test",
    "credentials-update.example.test", "ransom-payment.example.test",
    "exfil-storage.bad-example.test", "trickbot-c2.bad-example.test",
    "emotet-delivery.bad-example.test", "sliver-cnc.bad-example.test",
    "cobalt-beacon.bad-example.test", "loader-stage1.bad-example.test",
]
URL_POOL = [f"https://{d}/payload" for d in DOMAIN_POOL]
SHA256_POOL = [uuid.uuid4().hex + uuid.uuid4().hex[:0] for _ in range(20)]
EMAIL_POOL = ["billing@phish-login.example.com", "support@ransom-payment.example.test"]

ACTOR_NAMES = ["TA505", "APT29", "FIN7", "Wizard Spider", "Lazarus Group"]


def now_z() -> str:
    """Return UTC timestamp in STIX `YYYY-MM-DDTHH:MM:SS.sssZ` format."""

    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def stix_indicator(pattern: str, name: str, description: str, *, confidence: int,
                   labels: list[str], external_id: str, tlp: str) -> dict:
    """Build one STIX 2.1 indicator object shaped like an Anomali ThreatStream upload."""

    indicator_id = f"indicator--{uuid.uuid4()}"
    created = now_z()
    valid_from = created
    valid_until = (datetime.datetime.now(datetime.timezone.utc) +
                   datetime.timedelta(days=random.randint(7, 90))).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": created,
        "modified": created,
        "name": name,
        "description": description,
        "indicator_types": ["malicious-activity"],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": valid_from,
        "valid_until": valid_until,
        "labels": labels,
        "confidence": confidence,
        "kill_chain_phases": [random.choice(KILL_CHAIN_PHASES)],
        "external_references": [
            {
                "source_name": SOURCE_SYSTEM,
                "external_id": external_id,
                "url": f"https://ui.threatstream.com/detail/indicator/{external_id}",
            }
        ],
        "object_marking_refs": [
            {
                "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
                "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
                "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
                "red":   "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
            }[tlp]
        ],
    }


def build_indicator_batch(count: int) -> list[dict]:
    """Return a deterministic-ish mix of Anomali-shaped indicators."""

    indicators: list[dict] = []
    for i in range(count):
        kind = random.choices(
            ["ipv4", "domain", "url", "sha256", "email"],
            weights=[40, 30, 15, 10, 5],
            k=1,
        )[0]

        confidence = random.choices(
            [random.randint(80, 100), random.randint(50, 79), random.randint(15, 49)],
            weights=[55, 30, 15],
            k=1,
        )[0]
        tlp = random.choices(["white", "green", "amber", "red"], weights=[20, 50, 25, 5], k=1)[0]
        labels = random.sample(LABEL_POOL, k=random.randint(2, 4))
        external_id = f"anomali-{uuid.uuid4().hex[:12]}"

        if kind == "ipv4":
            value = random.choice(IPV4_POOL)
            pattern = f"[ipv4-addr:value = '{value}']"
            name = f"Anomali ThreatStream IP IOC {value}"
            desc = "Anomali ThreatStream malicious IPv4 indicator (demo)."
        elif kind == "domain":
            value = random.choice(DOMAIN_POOL)
            pattern = f"[domain-name:value = '{value}']"
            name = f"Anomali ThreatStream Domain IOC {value}"
            desc = "Anomali ThreatStream malicious domain indicator (demo)."
        elif kind == "url":
            value = random.choice(URL_POOL)
            pattern = f"[url:value = '{value}']"
            name = f"Anomali ThreatStream URL IOC"
            desc = "Anomali ThreatStream malicious URL indicator (demo)."
        elif kind == "sha256":
            value = uuid.uuid4().hex + uuid.uuid4().hex
            pattern = f"[file:hashes.'SHA-256' = '{value}']"
            name = "Anomali ThreatStream File SHA-256 IOC"
            desc = "Anomali ThreatStream malicious file hash indicator (demo)."
        else:
            value = random.choice(EMAIL_POOL)
            pattern = f"[email-addr:value = '{value}']"
            name = f"Anomali ThreatStream Email IOC {value}"
            desc = "Anomali ThreatStream malicious email indicator (demo)."

        indicators.append(
            stix_indicator(
                pattern=pattern, name=name, description=desc,
                confidence=confidence, labels=labels,
                external_id=external_id, tlp=tlp,
            )
        )
    return indicators


def build_actor_objects() -> list[dict]:
    """Build a small set of non-indicator STIX objects (threat-actors + relationships)."""

    objects: list[dict] = []
    for actor in random.sample(ACTOR_NAMES, k=3):
        actor_id = f"threat-actor--{uuid.uuid4()}"
        objects.append(
            {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": actor_id,
                "created": now_z(),
                "modified": now_z(),
                "name": actor,
                "description": f"Anomali ThreatStream-tracked threat actor {actor} (demo).",
                "labels": ["nation-state" if "APT" in actor else "criminal", "anomalithreatstream"],
                "external_references": [
                    {
                        "source_name": SOURCE_SYSTEM,
                        "external_id": f"anomali-actor-{uuid.uuid4().hex[:10]}",
                    }
                ],
            }
        )
    return objects


def az_token() -> str:
    """Return an ARM bearer token from Azure CLI (used to call the TI Upload API)."""

    completed = subprocess.run(
        ["az", "account", "get-access-token",
         "--resource", UPLOAD_RESOURCE,
         "--query", "accessToken", "-o", "tsv"],
        check=True, capture_output=True, text=True,
    )
    return completed.stdout.strip()


def post_batch(workspace_id: str, token: str, stix_objects: list[dict]) -> dict:
    """POST one batch of STIX objects to the TI Upload Indicators API."""

    url = (f"{UPLOAD_HOST}/workspaces/{workspace_id}"
           f"/threat-intelligence-stix-objects:upload?api-version={API_VERSION}")
    payload = {"sourcesystem": SOURCE_SYSTEM, "stixobjects": stix_objects}
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as response:
            text = response.read().decode("utf-8")
            return {"status": response.status, "body": text}
    except urllib.error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"POST {url} failed: HTTP {exc.code}: {details}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Seed Anomali-shaped STIX indicators into Sentinel via the TI Upload API.")
    parser.add_argument("--workspace-id", required=True,
                        help="Log Analytics workspace customer ID (GUID).")
    parser.add_argument("--count", type=int, default=200,
                        help="Total indicator objects to publish (default 200).")
    parser.add_argument("--batch-size", type=int, default=100,
                        help="Objects per request (API limit: 100). Default 100.")
    parser.add_argument("--include-actors", action="store_true",
                        help="Also publish a small set of threat-actor STIX objects.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the first batch payload to stdout and exit.")
    args = parser.parse_args()

    indicators = build_indicator_batch(args.count)
    print(f"Built {len(indicators)} indicators (sourcesystem={SOURCE_SYSTEM}).")

    if args.dry_run:
        sample = {"sourcesystem": SOURCE_SYSTEM, "stixobjects": indicators[: args.batch_size]}
        print(json.dumps(sample, indent=2))
        return 0

    token = az_token()
    total_posted = 0
    for offset in range(0, len(indicators), args.batch_size):
        batch = indicators[offset: offset + args.batch_size]
        result = post_batch(args.workspace_id, token, batch)
        total_posted += len(batch)
        print(f"  POSTed batch {offset // args.batch_size + 1}: "
              f"{len(batch)} objects, HTTP {result['status']}")

    if args.include_actors:
        actors = build_actor_objects()
        result = post_batch(args.workspace_id, token, actors)
        print(f"  POSTed {len(actors)} threat-actor objects, HTTP {result['status']}")

    print(f"\nDone. Total objects uploaded: {total_posted}"
          + (f" + actors ({len(actors)})" if args.include_actors else ""))
    print("Query in Sentinel:")
    print('  ThreatIntelIndicators | where SourceSystem == "Anomali ThreatStream" | take 20')
    return 0


if __name__ == "__main__":
    sys.exit(main())
