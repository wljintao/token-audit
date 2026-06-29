"""Step 11: Infrastructure Fingerprinting (基础设施指纹).

3 个未授权 GET 探测，匹配已知中继框架的响应头/正文特征。
Informational only — 不进 6D 风险矩阵。
返回 (framework, confidence)。
"""
from __future__ import annotations

from collections import Counter

from step_helpers import format_diagnosis, _diagnosis_for_error

STEP_NAME_CN = "基础设施指纹"


# ============================================================
# Step 11 private helpers (moved from main.py lines 4015-4245)
# ============================================================

FRAMEWORK_SIGNATURES = [
    ("litellm", [
        ("header_prefix:x-litellm-", ""),
    ]),
    ("helicone", [
        ("header_prefix:helicone-", ""),
    ]),
    ("portkey", [
        ("header_prefix:x-portkey-", ""),
    ]),
    ("kong-gateway", [
        ("header_prefix:x-kong-", ""),
    ]),
    ("alibaba-dashscope", [
        ("header_prefix:x-dashscope-", ""),
    ]),
    ("azure-foundry", [
        ("header:apim-request-id", ""),
    ]),
    ("new-api", [
        ("body", "new api"),
        ("body", "calcium-ion/new-api"),
        ("body", "new-api"),
        ("header:x-powered-by", "new-api"),
    ]),
    ("one-api", [
        ("body", "one api"),
        ("body", "songquanpeng/one-api"),
        ("body", "oneapi"),
        ("header:x-powered-by", "one-api"),
    ]),
    ("lobechat-relay", [
        ("body", "lobechat"),
        ("body", "lobe-chat"),
    ]),
    ("fastgpt", [
        ("body", "fastgpt"),
        ("body", "labring/fastgpt"),
    ]),
    ("cloudflare", [
        ("header:cf-ray", ""),
        ("header:server", "cloudflare"),
    ]),
    ("nginx-raw", [
        ("header:server", "nginx/"),
    ]),
    ("caddy-raw", [
        ("header:server", "caddy"),
    ]),
]


INFORMATIVE_HEADERS = (
    "server", "x-powered-by", "via", "cf-ray", "x-served-by", "x-cache",
    "x-request-id", "x-frame-options", "x-litellm-version", "helicone-id",
    "x-portkey-request-id", "apim-request-id",
)


_BODY_SCAN_LIMIT = 8192


def _match_signal(signal, headers_lower, body_lower):
    source, needle = signal
    needle_lower = needle.lower()
    if source == "body":
        return needle_lower in body_lower
    if source.startswith("header:"):
        header_name = source.split(":", 1)[1].lower()
        if needle_lower == "":
            return header_name in headers_lower
        value = headers_lower.get(header_name, "")
        return needle_lower in value.lower()
    if source.startswith("header_prefix:"):
        prefix = source.split(":", 1)[1].lower()
        return any(k.startswith(prefix) for k in headers_lower)
    return False


def classify_framework(headers, body):
    """Classify a single response into ``(framework_name, matched_signals)``."""
    if headers is None:
        headers = {}
    if body is None:
        body = ""
    headers_lower = {str(k).lower(): str(v) for k, v in headers.items()}
    body_lower = body[:_BODY_SCAN_LIMIT].lower()

    for framework, signals in FRAMEWORK_SIGNATURES:
        hits = [s for s in signals if _match_signal(s, headers_lower, body_lower)]
        if hits:
            return framework, hits
    return None, []


def extract_informative_headers(headers):
    """Return the subset of headers in ``INFORMATIVE_HEADERS`` (case-insensitive)."""
    if not headers:
        return {}
    out = {}
    for k, v in headers.items():
        if str(k).lower() in INFORMATIVE_HEADERS:
            out[str(k)] = str(v)
    return out


def aggregate_framework(results):
    """Pick the single most-confident framework across all probe results."""
    frameworks = [r["framework"] for r in results if r.get("framework")]
    if not frameworks:
        return None, "unknown"
    counts = Counter(frameworks)
    top, n = counts.most_common(1)[0]
    confidence = "confirmed" if n >= 2 else "tentative"
    return top, confidence


def run_infra_fingerprint(client):
    """Fire the 3 infrastructure probes and return per-probe results."""
    probes = [
        ("landing", "GET", "/"),
        ("models", "GET", "/v1/models"),
        ("notfound", "GET", "/nonexistent-abc12345xyz"),
    ]
    results = []
    for name, method, path in probes:
        r = client.raw_request(
            method=method, path=path, headers={}, body=b"",
            content_type="application/json", timeout=15,
        )
        status = r.get("status", 0)
        headers = r.get("headers", {}) or {}
        body = r.get("body", "") or ""
        error = r.get("error")

        framework, signals = classify_framework(headers, body)
        info_headers = extract_informative_headers(headers)

        results.append({
            "probe": name,
            "path": path,
            "status": status,
            "error": error,
            "framework": framework,
            "signals": signals,
            "headers": info_headers,
            "body_preview": body[:200],
        })
    return results


# ============================================================
# Step 11 public entry
# ============================================================

def run(client, report, **kwargs):
    """Infrastructure fingerprint (v1.8). Informational only."""
    report.h2(f"11. {STEP_NAME_CN}")
    report.p(
        "Probe the relay's ``/``, ``/v1/models``, and a nonexistent "
        "endpoint with unauthenticated GET requests, then match "
        "response headers and body against a small database of known "
        "relay-framework signatures. Rationale: Zhang et al., *Real "
        "Money, Fake Models*, arXiv:2603.01919, reports 11 of 17 "
        "identified shadow APIs are built on OneAPI / NewAPI forks. "
        "Framework identification is **informational only** in v1.8 "
        "-- it does not feed into the overall risk rating.\n"
    )

    results = run_infra_fingerprint(client)

    report.p("| Probe | Path | Status | Framework | Signals |")
    report.p("|-------|------|--------|-----------|---------|")
    error_diagnostics = []
    for r in results:
        name = r["probe"]
        path = r["path"]
        status_cell = str(r["status"]) if r["status"] else "—"
        if r["error"]:
            error_diagnostics.append((name, r["error"]))
            status_cell = f"ERR: {r['error'][:40]}"
        framework = r["framework"] or "—"
        if r["signals"]:
            sig_strs = [f"{src}='{needle}'" for src, needle in r["signals"]]
            signals_cell = ", ".join(sig_strs)[:120]
        else:
            signals_cell = "—"
        report.p(f"| {name} | `{path}` | {status_cell} | `{framework}` | {signals_cell} |")

    if error_diagnostics:
        report.p("\n**Transport error diagnostics:**")
        for name, error in error_diagnostics:
            report.p(f"- {name}: {format_diagnosis(_diagnosis_for_error(error))}")

    merged_headers = {}
    for r in results:
        for k, v in r["headers"].items():
            merged_headers.setdefault(k, v)
    if merged_headers:
        report.p("\n**Operator-profile headers**:")
        for k, v in merged_headers.items():
            report.p(f"- `{k}`: `{v[:120]}`")

    framework, confidence = aggregate_framework(results)

    if confidence == "confirmed":
        report.flag(
            "green",
            f"Relay framework identified: **{framework}** "
            f"(confirmed by multiple probes). Informational only in v1.8.",
        )
    elif confidence == "tentative":
        report.flag(
            "green",
            f"Relay framework possibly **{framework}** "
            f"(single probe hit). Informational only in v1.8.",
        )
    else:
        report.flag(
            "green",
            "No framework branding detected. Likely a direct reverse "
            "proxy, a custom backend, or a stripped-branding fork.",
        )

    print(f"  Done: infra fingerprint ({framework or 'unknown'}/{confidence})")
    return framework, confidence
