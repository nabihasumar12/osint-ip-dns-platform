#!/usr/bin/env python3
"""Passive, API-based website OSINT comparison with Excel export."""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from dotenv import load_dotenv
from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

load_dotenv()

MAX_IPS = 5
TIMEOUT_SECONDS = 20
MAX_CELL_LENGTH = 32_000
USER_AGENT = "authorized-passive-osint-comparison/1.0"


class ProviderError(Exception):
    """An API request failed without exposing request credentials."""


@dataclass
class ProviderResult:
    service: str
    status: str
    findings: str
    error: str
    responses: list[tuple[str, Any]]


def parse_domain(value: str) -> str:
    candidate = value.strip()
    if "://" not in candidate:
        candidate = "//" + candidate
    parsed = urllib.parse.urlsplit(candidate)
    if parsed.username or parsed.password or not parsed.hostname:
        raise ValueError("Enter a domain name or website URL with a hostname.")

    hostname = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("Enter a DNS hostname, not a bare IP address.")

    if len(hostname) > 253 or any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        for label in hostname.split(".")
    ):
        raise ValueError("The hostname is not a valid DNS name.")
    if any(not all(char.isalnum() or char == "-" for char in label)
           for label in hostname.split(".")):
        raise ValueError("The hostname contains invalid characters.")
    return hostname


def resolve_public_ips(domain: str) -> list[str]:
    addresses: list[str] = []
    try:
        results = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return addresses

    for result in results:
        address = result[4][0]
        if ipaddress.ip_address(address).is_global and address not in addresses:
            addresses.append(address)
        if len(addresses) == MAX_IPS:
            break
    return addresses


def request_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
) -> Any:
    if params:
        separator = "&" if "?" in url else "?"
        url += separator + urllib.parse.urlencode(params)
    request_headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    request_headers.update(headers or {})
    request = urllib.request.Request(url, headers=request_headers)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            payload = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read(1000).decode("utf-8", errors="replace").strip()
        raise ProviderError(f"HTTP {exc.code}: {detail or exc.reason}") from None
    except (urllib.error.URLError, TimeoutError) as exc:
        reason = getattr(exc, "reason", exc)
        raise ProviderError(f"Connection failed: {reason}") from None
    try:
        return json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ProviderError("The provider returned an invalid JSON response.") from None


def format_findings(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=True, separators=(",", ":"), default=str)
    return text if len(text) <= MAX_CELL_LENGTH else text[:MAX_CELL_LENGTH] + "… (truncated)"


def vt_findings(response: Any) -> dict[str, Any]:
    attributes = response.get("data", {}).get("attributes", {})
    return {
        "reputation": attributes.get("reputation"),
        "last_analysis_stats": attributes.get("last_analysis_stats"),
        "categories": attributes.get("categories"),
        "last_analysis_date": attributes.get("last_analysis_date"),
    }


def securitytrails_findings(response: Any) -> dict[str, Any]:
    return {
        "hostname": response.get("hostname"),
        "current_dns": response.get("current_dns"),
        "alexa": response.get("alexa"),
    }


def shodan_findings(responses: list[tuple[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "ip": ip,
            "organization": response.get("org"),
            "country": response.get("country_name"),
            "last_update": response.get("last_update"),
            "ports": response.get("ports", []),
        }
        for ip, response in responses
    ]


def censys_findings(response: Any) -> list[dict[str, Any]]:
    hits = response.get("result", {}).get("hits", [])
    return [
        {
            "ip": hit.get("ip"),
            "names": hit.get("names"),
            "services": [
                {"port": service.get("port"), "service_name": service.get("service_name")}
                for service in hit.get("services", [])
            ],
        }
        for hit in hits
    ]


def abuseipdb_findings(responses: list[tuple[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for ip, response in responses:
        data = response.get("data", {})
        findings.append({
            "ip": ip,
            "abuseConfidenceScore": data.get("abuseConfidenceScore"),
            "totalReports": data.get("totalReports"),
            "lastReportedAt": data.get("lastReportedAt"),
        })
    return findings


def collect_single(
    service: str,
    missing: list[str],
    operation: Any,
    summarize: Any,
) -> ProviderResult:
    if missing:
        return ProviderResult(
            service, "missing key", "", "Set " + ", ".join(missing), []
        )
    try:
        response = operation()
    except ProviderError as exc:
        return ProviderResult(service, "error", "", str(exc), [])
    return ProviderResult(
        service, "success", format_findings(summarize(response)), "", [("domain", response)]
    )


def collect_multi(
    service: str,
    missing: list[str],
    items: list[str],
    operation: Any,
    summarize: Any,
) -> ProviderResult:
    if missing:
        return ProviderResult(
            service, "missing key", "", "Set " + ", ".join(missing), []
        )
    if not items:
        return ProviderResult(
            service, "no public IPs", "[]",
            "No public IP addresses resolved for the hostname.", []
        )

    responses: list[tuple[str, Any]] = []
    errors: list[str] = []
    for item in items:
        try:
            responses.append((item, operation(item)))
        except ProviderError as exc:
            errors.append(f"{item}: {exc}")
    if not responses:
        status = "error"
    elif errors:
        status = "partial"
    else:
        status = "success"
    return ProviderResult(
        service,
        status,
        format_findings(summarize(responses)),
        "; ".join(errors),
        [(item, response) for item, response in responses],
    )


def collect_results(domain: str) -> tuple[list[str], list[ProviderResult]]:
    ips = resolve_public_ips(domain)

    vt_key = os.getenv("VT_API_KEY", "")
    st_key = os.getenv("SECURITYTRAILS_API_KEY", "")
    shodan_key = os.getenv("SHODAN_API_KEY", "")
    censys_id = os.getenv("CENSYS_API_ID", "")
    censys_secret = os.getenv("CENSYS_API_SECRET", "")
    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "")

    results = [
        collect_single(
            "VirusTotal",
            [] if vt_key else ["VT_API_KEY"],
            lambda: request_json(
                f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain, safe='')}",
                headers={"x-apikey": vt_key},
            ),
            vt_findings,
        ),
        collect_single(
            "SecurityTrails",
            [] if st_key else ["SECURITYTRAILS_API_KEY"],
            lambda: request_json(
                f"https://api.securitytrails.com/v1/domain/{urllib.parse.quote(domain, safe='')}",
                headers={"APIKEY": st_key},
            ),
            securitytrails_findings,
        ),
    ]

    def shodan_lookup(ip: str) -> Any:
        return request_json(
            f"https://api.shodan.io/shodan/host/{urllib.parse.quote(ip, safe='')}",
            params={"key": shodan_key, "minify": "true"},
        )

    results.append(collect_multi(
        "Shodan",
        [] if shodan_key else ["SHODAN_API_KEY"],
        ips,
        shodan_lookup,
        shodan_findings,
    ))

    censys_missing = [
        name for name, value in (
            ("CENSYS_API_ID", censys_id), ("CENSYS_API_SECRET", censys_secret)
        ) if not value
    ]
    censys_auth = base64.b64encode(
        f"{censys_id}:{censys_secret}".encode("utf-8")
    ).decode("ascii")
    censys_result = collect_single(
        "Censys",
        censys_missing,
        lambda: request_json(
            "https://search.censys.io/api/v2/hosts/search",
            headers={"Authorization": f"Basic {censys_auth}"},
            params={"q": f"parsed.names: {domain}", "per_page": "5"},
        ),
        censys_findings,
    )
    results.append(censys_result)

    def abuse_lookup(ip: str) -> Any:
        return request_json(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": abuse_key},
            params={"ipAddress": ip, "maxAgeInDays": "90"},
        )

    results.append(collect_multi(
        "AbuseIPDB",
        [] if abuse_key else ["ABUSEIPDB_API_KEY"],
        ips,
        abuse_lookup,
        abuseipdb_findings,
    ))
    return ips, results


def safe_excel_text(value: str) -> str:
    if value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def write_workbook(
    path: str,
    domain: str,
    ips: list[str],
    results: list[ProviderResult],
) -> None:
    workbook = Workbook()
    summary = workbook.active
    summary.title = "Comparison"
    summary.append(["Service", "Target", "Resolved public IPs", "Status", "Key findings", "Error"])
    ip_text = ", ".join(ips) if ips else "None"
    for result in results:
        summary.append([
            result.service,
            domain,
            ip_text,
            result.status,
            safe_excel_text(result.findings),
            safe_excel_text(result.error),
        ])

    details = workbook.create_sheet("Raw responses")
    details.append(["Service", "Queried item", "Response JSON"])
    for result in results:
        for item, response in result.responses:
            details.append([
                result.service,
                item,
                safe_excel_text(format_findings(response)),
            ])

    metadata = workbook.create_sheet("Info")
    metadata.append(["Generated (UTC)", datetime.now(timezone.utc).isoformat()])
    metadata.append(["Target", domain])
    metadata.append(["Resolved public IPs", ip_text])
    metadata.append([
        "Scope",
        "Passive provider API lookups only; no port scanning or website probing.",
    ])
    metadata.append([
        "Data handling",
        "VirusTotal notes that queried indicators may be added to its dataset. "
        "Do not query sensitive or confidential domains.",
    ])

    header_fill = PatternFill("solid", fgColor="1F4E78")
    for sheet in workbook.worksheets:
        sheet.freeze_panes = "A2" if sheet.title != "Info" else "A1"
        if sheet.title != "Info":
            sheet.auto_filter.ref = sheet.dimensions
            for cell in sheet[1]:
                cell.font = Font(color="FFFFFF", bold=True)
                cell.fill = header_fill
        for column in sheet.columns:
            max_length = max(
                (len(str(cell.value or "")) for cell in column),
                default=0,
            )
            sheet.column_dimensions[get_column_letter(column[0].column)].width = min(
                max(max_length + 2, 14), 60
            )
        for row in sheet.iter_rows():
            for cell in row:
                cell.alignment = Alignment(vertical="top", wrap_text=True)
    workbook.save(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare passive website OSINT API results in an Excel workbook."
    )
    parser.add_argument("target", help="Authorized DNS hostname or website URL")
    parser.add_argument("-o", "--output", default="osint_comparison.xlsx")
    args = parser.parse_args(argv)

    try:
        domain = parse_domain(args.target)
        ips, results = collect_results(domain)
        write_workbook(args.output, domain, ips, results)
    except (ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    for result in results:
        print(f"{result.service}: {result.status}" +
              (f" — {result.error}" if result.error else ""))
    print(f"Workbook written to {args.output}")
    return 0 if all(result.status == "success" for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
