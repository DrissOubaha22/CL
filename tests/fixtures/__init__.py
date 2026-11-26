"""Trimmed, shape-accurate samples of each upstream feed response."""

from __future__ import annotations

from typing import Any

KEV_CATALOGUE: dict[str, Any] = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.11.26",
    "dateReleased": "2026-11-26T12:00:00.0000Z",
    "count": 3,
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-104286",
            "vendorProject": "Fortinet",
            "product": "FortiMail",
            "vulnerabilityName": "Fortinet FortiMail Command Injection",
            "dateAdded": "2026-11-10",
            "shortDescription": "FortiMail contains a command injection flaw.",
            "requiredAction": "Apply mitigations per vendor instructions.",
            "dueDate": "2026-12-01",
            "knownRansomwareCampaignUse": "Known",
            "notes": "https://example.test/psirt/FG-IR-26-001",
            "cwes": ["CWE-78"],
        },
        {
            "cveID": "CVE-2026-200001",
            "vendorProject": "Citrix",
            "product": "NetScaler",
            "vulnerabilityName": "Citrix NetScaler Buffer Overflow",
            "dateAdded": "2026-11-20",
            "shortDescription": "NetScaler contains a buffer overflow.",
            "requiredAction": "Apply updates.",
            "dueDate": "2026-12-11",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
            "cwes": ["CWE-787"],
        },
        {
            # Malformed on purpose: a bad id must be rejected, not repaired.
            "cveID": "NOT-A-CVE",
            "vendorProject": "Acme",
            "product": "Widget",
            "vulnerabilityName": "Bad record",
            "dateAdded": "2026-11-21",
            "shortDescription": "Should be rejected.",
            "requiredAction": "n/a",
            "dueDate": "2026-12-12",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ],
}

EPSS_RESPONSE: dict[str, Any] = {
    "status": "OK",
    "status-code": 200,
    "version": "1.0",
    "access": "public",
    "total": 2,
    "offset": 0,
    "limit": 100,
    "data": [
        {
            "cve": "CVE-2026-104286",
            "epss": "0.94132",
            "percentile": "0.99871",
            "date": "2026-11-26",
        },
        {
            "cve": "CVE-2026-200001",
            "epss": "0.00042",
            "percentile": "0.08120",
            "date": "2026-11-26",
        },
    ],
}

NVD_RESPONSE: dict[str, Any] = {
    "resultsPerPage": 2,
    "startIndex": 0,
    "totalResults": 2,
    "format": "NVD_CVE",
    "version": "2.0",
    "timestamp": "2026-11-26T12:00:00.000",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2026-104286",
                "sourceIdentifier": "psirt@fortinet.com",
                "published": "2026-11-05T10:15:00.000",
                "lastModified": "2026-11-25T18:30:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {"lang": "es", "value": "Una vulnerabilidad."},
                    {"lang": "en", "value": "A command injection in FortiMail."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            },
                        },
                        {
                            "source": "secondary@example.test",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
                                "baseScore": 3.1,
                            },
                        },
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {"lang": "en", "value": "CWE-78"},
                            {"lang": "en", "value": "NVD-CWE-noinfo"},
                        ],
                    }
                ],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:fortinet:fortimail:*:*:*:*:*:*:*:*",
                                        "versionEndExcluding": "7.6.3",
                                        "matchCriteriaId": "1",
                                    },
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:fortinet:fortimail:*:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "7.4.0",
                                        "versionEndExcluding": "7.4.8",
                                        "matchCriteriaId": "2",
                                    },
                                    {
                                        # Platform context, not itself vulnerable.
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:o:fortinet:fortios:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "3",
                                    },
                                    {
                                        # Unparseable: must be dropped, not stored.
                                        "vulnerable": True,
                                        "criteria": "not-a-cpe",
                                        "matchCriteriaId": "4",
                                    },
                                ],
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://example.test/psirt/FG-IR-26-001",
                        "source": "psirt@fortinet.com",
                        "tags": ["Vendor Advisory", "Patch"],
                    },
                    {
                        "url": "https://example.test/news",
                        "source": "cve@mitre.org",
                        "tags": ["Press/Media Coverage"],
                    },
                ],
            }
        },
        {
            "cve": {
                "id": "CVE-2026-300002",
                "published": "2026-11-20T00:00:00.000",
                "lastModified": "2026-11-24T00:00:00.000",
                "vulnStatus": "Awaiting Analysis",
                "descriptions": [{"lang": "en", "value": "No metrics yet."}],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "references": [],
            }
        },
    ],
}
