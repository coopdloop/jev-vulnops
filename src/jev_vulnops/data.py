"""Fixture vulnerabilities + assets used for the offline demo.

Deliberately varied: a KEV-listed RCE on an exposed tier-0 asset, a couple of
reasonable accept-risk cases, and intentionally vague vendor advisories that
should (a) pick needs-intel with low confidence and (b) trip the analyst
review gate. Asset context rides in the state alongside the CVE text.
"""

from __future__ import annotations

VULNS: list[dict] = [
    {
        "cve_id": "CVE-2025-31404",
        "title": "LogaFetch pre-auth RCE in TLS terminator",
        "description": (
            "A stack-based buffer overflow in LogaFetch <= 2.1.7 allows an "
            "unauthenticated remote attacker to achieve remote code execution on "
            "TLS termination endpoints. Public exploit code exists and CISA KEV "
            "lists active exploitation."
        ),
        "cvss": 9.8,
        "epss": 0.86,
        "known_exploited": True,
        "asset": {
            "name": "billing-db",
            "internet_exposed": True,
            "criticality_tier": "tier-0",
            "data_classification": "payments",
        },
    },
    {
        "cve_id": "CVE-2024-44199",
        "title": "libxmlx use-after-free on admin-only network",
        "description": (
            "A use after free in the XML parser of libxmlx is reachable only from "
            "the admin network segment of the internal-wiki service; the parser is "
            "exercised on page import."
        ),
        "cvss": 6.1,
        "epss": 0.02,
        "known_exploited": False,
        "asset": {
            "name": "internal-wiki",
            "internet_exposed": False,
            "criticality_tier": "tier-3",
            "data_classification": "internal",
        },
    },
    {
        "cve_id": "CVE-2025-20777",
        "title": "payments-api SSRF via webhook callback",
        "description": (
            "An SSRF vulnerability in the webhook callback validation of the "
            "payments-api service allows an unauthenticated remote party to reach "
            "internal endpoints; no exploitation observed so far."
        ),
        "cvss": 7.3,
        "epss": 0.21,
        "known_exploited": False,
        "asset": {
            "name": "payments-api",
            "internet_exposed": True,
            "criticality_tier": "tier-1",
            "data_classification": "payments",
        },
    },
    {
        "cve_id": "CVE-2025-30333",
        "title": "vendor advisory: possible corruption in sync module",
        "description": "Vendor note: possible memory corruption. Under review.",
        "cvss": 5.0,
        "epss": 0.01,
        "known_exploited": False,
        "asset": {
            "name": "customer-saas",
            "internet_exposed": True,
            "criticality_tier": "tier-2",
            "data_classification": "internal",
        },
    },
    {
        "cve_id": "CVE-2025-50002",
        "title": "reportql deserialization in unreachable code path",
        "description": (
            "A deserialization flaw in the reportql library could in principle "
            "allow remote code execution, but the affected code path is not "
            "reachable from the deployed configuration of the internal report "
            "generator."
        ),
        "cvss": 8.8,
        "epss": 0.04,
        "known_exploited": False,
        "asset": {
            "name": "report-generator",
            "internet_exposed": False,
            "criticality_tier": "tier-3",
            "data_classification": "internal",
        },
    },
    {
        "cve_id": "CVE-2025-40980",
        "title": "mail-relay authenticated command injection",
        "description": (
            "A command injection in the mail-relay admin console is exploitable by "
            "users holding the relay-admin role; successful exploitation would "
            "give control of outbound queue handling."
        ),
        "cvss": 8.1,
        "epss": 0.11,
        "known_exploited": False,
        "asset": {
            "name": "mail-relay",
            "internet_exposed": True,
            "criticality_tier": "tier-1",
            "data_classification": "corporate",
        },
    },
    {
        "cve_id": "CVE-2025-60001",
        "title": "vendor note: deferred fix for edge-proxy",
        "description": "Vendor notes a deferred fix window for versions < 1.0.",
        "cvss": 5.0,
        "epss": 0.01,
        "known_exploited": False,
        "asset": {
            "name": "edge-proxy",
            "internet_exposed": True,
            "criticality_tier": "tier-1",
            "data_classification": "corporate",
        },
    },
    {
        "cve_id": "CVE-2025-10890",
        "title": "artifact upload path traversal on ci-runner",
        "description": (
            "A path traversal in artifact upload allows limited writes into the "
            "agent workspace of an internal CI runner."
        ),
        "cvss": 5.6,
        "epss": 0.03,
        "known_exploited": False,
        "asset": {
            "name": "ci-runner",
            "internet_exposed": False,
            "criticality_tier": "tier-3",
            "data_classification": "internal",
        },
    },
]
