"""Step 1: Infrastructure Recon (基础设施侦察).

DNS / WHOIS / TLS cert / HTTP headers / homepage body preview.
Informational only — does not feed the 6D risk matrix.
"""
from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError as urllib_error_HTTPError

STEP_NAME_CN = "基础设施侦察"


# ============================================================
# Step 1 private helpers
# ============================================================

def _compact_multiline(text, max_lines=6):
    """Collapse a verbose multi-line tool output into a compact inline string."""
    if not text:
        return None
    lines = [line.strip() for line in str(text).splitlines() if line.strip()]
    if not lines:
        return None
    return " | ".join(lines[:max_lines])


def _run_optional_command(argv, timeout=10, max_lines=None):
    """Run an optional local binary and return combined stdout/stderr text.

    Missing executables are treated as an unavailable signal rather than
    as a hard error in the report.
    """
    if not argv or shutil.which(argv[0]) is None:
        return None
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return None
    parts = []
    if r.stdout:
        parts.append(r.stdout.strip())
    if r.stderr:
        parts.append(r.stderr.strip())
    text = "\n".join(part for part in parts if part).strip()
    if not text:
        return None
    if max_lines is not None:
        text = "\n".join(text.splitlines()[:max_lines])
    return text


def _resolve_dns_records(domain):
    """Resolve A records via stdlib and optional CNAME/NS via nslookup."""
    records = {}

    try:
        infos = socket.getaddrinfo(domain, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        ipv4s = sorted({info[4][0] for info in infos})
        records["A"] = ", ".join(ipv4s) if ipv4s else "(empty)"
    except Exception as e:
        records["A"] = f"error: {e}"

    for rtype in ("CNAME", "NS"):
        raw = _run_optional_command(["nslookup", f"-type={rtype}", domain], timeout=10, max_lines=20)
        records[rtype] = _compact_multiline(raw) or "nslookup not available on this host"

    return records


def _format_x509_name(name):
    parts = []
    for group in name or []:
        for key, value in group:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _fetch_tls_certificate_summary(domain):
    """Fetch peer cert metadata without requiring openssl on the host."""
    context = ssl._create_unverified_context()
    try:
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()
    except Exception:
        return None

    if not cert:
        return None

    lines = []
    subject = _format_x509_name(cert.get("subject"))
    issuer = _format_x509_name(cert.get("issuer"))
    if subject:
        lines.append(f"subject={subject}")
    if issuer:
        lines.append(f"issuer={issuer}")
    if cert.get("notBefore"):
        lines.append(f"notBefore={cert['notBefore']}")
    if cert.get("notAfter"):
        lines.append(f"notAfter={cert['notAfter']}")
    sans = [value for kind, value in cert.get("subjectAltName", []) if kind == "DNS"]
    if sans:
        lines.append("subjectAltName=" + ", ".join(sans[:20]))
    return "\n".join(lines) if lines else None


def _response_to_snapshot(resp, read_body=False, max_body_chars=500):
    body_preview = ""
    if read_body:
        try:
            body_preview = resp.read(max_body_chars).decode("utf-8", errors="replace")
        except Exception:
            body_preview = ""
    return {
        "status": getattr(resp, "status", None) or getattr(resp, "code", None),
        "url": resp.geturl() if hasattr(resp, "geturl") else None,
        "headers": dict(resp.headers.items()) if getattr(resp, "headers", None) else {},
        "body_preview": body_preview,
    }


def _fetch_http_snapshot(url, method="GET", max_body_chars=500):
    """Fetch headers/body preview via stdlib urllib instead of curl/head."""
    request = Request(
        url,
        headers={"User-Agent": "api-relay-audit/step1"},
        method=method,
    )
    context = ssl._create_unverified_context() if url.lower().startswith("https://") else None
    try:
        with urlopen(request, timeout=10, context=context) as resp:
            return _response_to_snapshot(
                resp,
                read_body=(method != "HEAD"),
                max_body_chars=max_body_chars,
            )
    except urllib_error_HTTPError as e:
        return _response_to_snapshot(
            e,
            read_body=(method != "HEAD"),
            max_body_chars=max_body_chars,
        )
    except Exception as e:
        return {"error": str(e)}


def _format_http_headers(snapshot, limit=20):
    if not snapshot or snapshot.get("error"):
        return None
    lines = []
    status = snapshot.get("status")
    final_url = snapshot.get("url")
    if status or final_url:
        label = f"HTTP {status}" if status else "HTTP"
        if final_url:
            label += f" {final_url}"
        lines.append(label)
    for idx, (key, value) in enumerate(snapshot.get("headers", {}).items()):
        if idx >= limit:
            break
        lines.append(f"{key}: {value}")
    return "\n".join(lines) if lines else None


def _lookup_whois(domain):
    return _run_optional_command(["whois", domain], timeout=10, max_lines=30)


# ============================================================
# Step 1 public entry
# ============================================================

def run(client, report, **kwargs) -> None:
    """Public entry. Reads base_url off the APIClient."""
    report.h2(f"1. {STEP_NAME_CN}")
    base_url = client.base_url
    domain = urlparse(base_url).hostname

    # DNS
    report.h3("1.1 DNS Records")
    dns_records = _resolve_dns_records(domain)
    for rtype in ["A", "CNAME", "NS"]:
        report.p(f"**{rtype}**: `{dns_records.get(rtype, '(empty)')}`")

    # WHOIS
    report.h3("1.2 WHOIS")
    parts = domain.split(".")
    main_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    whois = _lookup_whois(main_domain)
    report.code(whois) if whois else report.p("whois not available on this host")

    # SSL
    report.h3("1.3 SSL Certificate")
    ssl_info = _fetch_tls_certificate_summary(domain)
    report.code(ssl_info) if ssl_info else report.p("Unable to retrieve SSL certificate")

    # HTTP headers
    report.h3("1.4 HTTP Response Headers")
    headers_snapshot = _fetch_http_snapshot(base_url, method="HEAD")
    if headers_snapshot.get("error"):
        headers_snapshot = _fetch_http_snapshot(base_url, method="GET")
    headers = _format_http_headers(headers_snapshot)
    report.code(headers) if headers else report.p("Unable to retrieve response headers")

    # System identification
    report.h3("1.5 System Identification")
    homepage_snapshot = _fetch_http_snapshot(base_url, method="GET")
    homepage = homepage_snapshot.get("body_preview") if homepage_snapshot else None
    if homepage:
        report.code(homepage[:500])

    # 信息性步骤：汇总关键发现作为结论，避免前端显示"(本项无明确结论)"。
    findings = []
    if dns_records.get("A") and dns_records["A"] != "(empty)" and not dns_records["A"].startswith("error"):
        findings.append(f"DNS A={dns_records['A']}")
    if ssl_info:
        # 提取 issuer 摘要
        for line in ssl_info.split("\n"):
            if line.startswith("issuer="):
                findings.append(f"SSL {line}")
                break
    if headers_snapshot and not headers_snapshot.get("error"):
        srv = headers_snapshot.get("headers", {}).get("Server") or headers_snapshot.get("headers", {}).get("server")
        if srv:
            findings.append(f"Server: {srv}")
    summary = "Infrastructure recon completed" + (f" ({'; '.join(findings)})" if findings else "")
    report.flag("green", summary)
    print("  Done: infrastructure recon")
