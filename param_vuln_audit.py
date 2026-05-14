#!/usr/bin/env python3
"""
ParamVulnAudit - audit indikasi kerentanan pada parameter URL.

Gunakan hanya pada aplikasi/domain yang Anda miliki atau punya izin tertulis.
Tool ini memakai probe ringan untuk menemukan indikasi awal, bukan eksploitasi.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Iterable


USER_AGENT = "ParamVulnAudit/1.0 (+authorized parameter audit)"
DEFAULT_TIMEOUT = 10

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "postgresql query failed",
    "sqlite error",
    "ora-01756",
    "microsoft ole db provider for sql server",
    "syntax error at or near",
]

LFI_MARKERS = [
    "root:x:0:0:",
    "[boot loader]",
    "for 16-bit app support",
]

COMMAND_MARKERS = [
    "PVACMDOK",
]

SSTI_MARKERS = [
    "490049",
]


@dataclass
class ResponseData:
    url: str
    status: int
    headers: dict[str, str]
    body: str
    elapsed: float


@dataclass
class Finding:
    severity: str
    category: str
    parameter: str
    detail: str
    evidence: str
    test_url: str


@dataclass
class AuditResult:
    target: str
    tested_parameters: list[str]
    baseline_status: int | None = None
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add(self, severity: str, category: str, parameter: str, detail: str, evidence: str, test_url: str) -> None:
        self.findings.append(Finding(severity, category, parameter, detail, evidence[:300], test_url))


def normalize_url(raw: str) -> str:
    value = raw.strip()
    if "://" not in value:
        value = "https://" + value
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("URL harus valid dan memakai http/https.")
    if not parsed.query:
        raise ValueError("URL harus punya query parameter, contoh: https://site.test/page?id=1")
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))


def query_pairs(url: str) -> list[tuple[str, str]]:
    parsed = urllib.parse.urlparse(url)
    return urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)


def replace_param(url: str, parameter: str, value: str) -> str:
    parsed = urllib.parse.urlparse(url)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    changed = [(name, value if name == parameter else old) for name, old in pairs]
    query = urllib.parse.urlencode(changed, doseq=True)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", query, ""))


def send_get(url: str, timeout: int) -> ResponseData:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,text/plain;q=0.8,*/*;q=0.5",
        },
    )
    start = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(500_000).decode("utf-8", errors="ignore")
            headers = {k.lower(): v for k, v in response.headers.items()}
            return ResponseData(response.geturl(), response.status, headers, body, time.monotonic() - start)
    except urllib.error.HTTPError as exc:
        body = exc.read(500_000).decode("utf-8", errors="ignore")
        headers = {k.lower(): v for k, v in exc.headers.items()}
        return ResponseData(exc.geturl(), exc.code, headers, body, time.monotonic() - start)


def similarity(a: str, b: str) -> float:
    a = a[:50_000]
    b = b[:50_000]
    return difflib.SequenceMatcher(None, a, b).ratio()


def reflected(value: str, body: str) -> bool:
    return value in body or urllib.parse.quote(value) in body


def has_any_marker(body: str, markers: Iterable[str]) -> str:
    lower = body.lower()
    for marker in markers:
        if marker.lower() in lower:
            return marker
    return ""


def header_location(resp: ResponseData) -> str:
    return resp.headers.get("location", "")


def run_probe(
    result: AuditResult,
    base_url: str,
    baseline: ResponseData,
    parameter: str,
    category: str,
    payload: str,
    timeout: int,
) -> ResponseData | None:
    test_url = replace_param(base_url, parameter, payload)
    try:
        return send_get(test_url, timeout)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        result.errors.append(f"{category}/{parameter}: {exc}")
        return None


def audit_parameter(
    result: AuditResult,
    url: str,
    baseline: ResponseData,
    parameter: str,
    timeout: int,
    delay: float,
) -> None:
    probes = [
        ("Reflected XSS", "<pvaxss-1337>\"'"),
        ("SQL Injection Error", "'\"))("),
        ("Open Redirect", "https://example.com/pva-open-redirect"),
        ("LFI / Path Traversal", "../../../../../../../../etc/passwd"),
        ("Command Injection Indicator", ";echo PVACMDOK;"),
        ("SSTI Indicator", "{{700*700+49}}"),
        ("Numeric Tampering", "999999999"),
    ]

    for category, payload in probes:
        resp = run_probe(result, url, baseline, parameter, category, payload, timeout)
        if resp is None:
            time.sleep(delay)
            continue

        test_url = replace_param(url, parameter, payload)
        body = resp.body
        body_lower = body.lower()

        if category == "Reflected XSS" and reflected(payload, body):
            result.add(
                "medium",
                category,
                parameter,
                "Payload terlihat kembali pada response. Periksa encoding output dan konteks HTML/JS.",
                payload,
                test_url,
            )

        elif category == "SQL Injection Error":
            marker = has_any_marker(body, SQL_ERRORS)
            if marker:
                result.add(
                    "high",
                    category,
                    parameter,
                    "Response memuat pesan error database setelah input karakter khusus.",
                    marker,
                    test_url,
                )

        elif category == "Open Redirect":
            location = header_location(resp)
            if location.startswith("https://example.com/pva-open-redirect") or resp.url.startswith(
                "https://example.com/pva-open-redirect"
            ):
                result.add(
                    "high",
                    category,
                    parameter,
                    "Parameter tampak mengontrol redirect eksternal.",
                    location or resp.url,
                    test_url,
                )

        elif category == "LFI / Path Traversal":
            marker = has_any_marker(body, LFI_MARKERS)
            if marker:
                result.add(
                    "critical",
                    category,
                    parameter,
                    "Response memuat marker file sistem setelah payload traversal.",
                    marker,
                    test_url,
                )

        elif category == "Command Injection Indicator":
            marker = has_any_marker(body, COMMAND_MARKERS)
            if marker:
                result.add(
                    "critical",
                    category,
                    parameter,
                    "Response memuat marker command probe. Verifikasi segera di lingkungan yang diizinkan.",
                    marker,
                    test_url,
                )

        elif category == "SSTI Indicator":
            marker = has_any_marker(body, SSTI_MARKERS)
            if marker:
                result.add(
                    "high",
                    category,
                    parameter,
                    "Ekspresi template tampak dievaluasi oleh server.",
                    marker,
                    test_url,
                )

        elif category == "Numeric Tampering":
            sim = similarity(baseline.body, body)
            if resp.status != baseline.status or sim < 0.75:
                result.add(
                    "info",
                    category,
                    parameter,
                    "Perubahan nilai numerik menghasilkan response berbeda. Ini kandidat untuk dicek manual.",
                    f"status {baseline.status}->{resp.status}, similarity={sim:.2f}",
                    test_url,
                )

        if resp.status >= 500 and baseline.status < 500:
            result.add(
                "medium",
                "Server Error",
                parameter,
                f"Probe {category} memicu status 5xx. Ini bisa menandakan validasi input lemah.",
                str(resp.status),
                test_url,
            )

        time.sleep(delay)


def audit(args: argparse.Namespace) -> AuditResult:
    url = normalize_url(args.url)
    params = sorted({name for name, _ in query_pairs(url)})
    if args.param:
        missing = [name for name in args.param if name not in params]
        if missing:
            raise ValueError(f"Parameter tidak ada di URL: {', '.join(missing)}")
        params = args.param

    if len(params) > args.max_params:
        params = params[: args.max_params]

    result = AuditResult(target=url, tested_parameters=params)
    baseline = send_get(url, args.timeout)
    result.baseline_status = baseline.status

    for parameter in params:
        audit_parameter(result, url, baseline, parameter, args.timeout, args.delay)

    return result


def render_text(result: AuditResult) -> str:
    lines = [
        f"Target             : {result.target}",
        f"Baseline HTTP      : {result.baseline_status}",
        f"Parameter diuji    : {', '.join(result.tested_parameters)}",
        f"Jumlah temuan      : {len(result.findings)}",
        "",
    ]

    if result.findings:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for finding in sorted(result.findings, key=lambda item: order.get(item.severity, 9)):
            lines.append(f"[{finding.severity.upper()}] {finding.category} pada `{finding.parameter}`")
            lines.append(f"  Detail : {finding.detail}")
            lines.append(f"  Bukti  : {finding.evidence}")
            lines.append(f"  URL    : {finding.test_url}")
            lines.append("")
    else:
        lines.append("Tidak ada indikasi kerentanan dari probe ringan ini.")

    if result.errors:
        lines.append("")
        lines.append(f"Error ringan: {len(result.errors)}")
        for error in result.errors[:5]:
            lines.append(f"- {error}")

    return "\n".join(lines).rstrip()


def render_json(result: AuditResult) -> str:
    return json.dumps(
        {
            "target": result.target,
            "baseline_status": result.baseline_status,
            "tested_parameters": result.tested_parameters,
            "findings": [finding.__dict__ for finding in result.findings],
            "errors": result.errors,
        },
        indent=2,
        ensure_ascii=False,
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit indikasi kerentanan parameter URL secara ringan dan terkontrol."
    )
    parser.add_argument("url", help="URL lengkap dengan parameter, contoh: https://site.test/item?id=1&q=test")
    parser.add_argument("-p", "--param", action="append", help="Parameter tertentu yang diuji. Bisa dipakai berulang.")
    parser.add_argument("--max-params", type=int, default=10, help="Batas maksimal parameter yang diuji.")
    parser.add_argument("--delay", type=float, default=0.5, help="Jeda antar request dalam detik.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Timeout request dalam detik.")
    parser.add_argument("--json", action="store_true", help="Output JSON.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.max_params < 1 or args.delay < 0:
        print("Argumen max-params dan delay harus valid.", file=sys.stderr)
        return 2

    try:
        result = audit(args)
    except ValueError as exc:
        print(f"Input salah: {exc}", file=sys.stderr)
        return 2
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"Gagal mengakses target: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Dibatalkan.", file=sys.stderr)
        return 130

    print(render_json(result) if args.json else render_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
