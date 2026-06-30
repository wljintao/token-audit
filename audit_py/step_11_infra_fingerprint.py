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
        "使用未认证的 GET 请求探测中转站的 `/`、`/v1/models` 和一个不存在的端点，"
        "然后将响应头和响应体与已知中转站框架的特征库进行匹配。"
        "背景：Zhang et al., *Real Money, Fake Models*, arXiv:2603.01919 "
        "报告称，17 个已识别的影子 API 中有 11 个基于 OneAPI / NewAPI 分支构建。"
        "框架识别在 v1.8 中**仅为信息性**——不纳入整体风险评级。\n"
    )

    results = run_infra_fingerprint(client)

    report.p("| 探测点 | 路径 | 状态码 | 框架 | 匹配信号 |")
    report.p("|--------|------|--------|------|----------|")
    error_diagnostics = []
    for r in results:
        name = _probe_name_cn(r["probe"])
        path = r["path"]
        status_cell = str(r["status"]) if r["status"] else "—"
        if r["error"]:
            error_diagnostics.append((name, r["error"]))
            status_cell = f"错误：{r['error'][:40]}"
        framework = r["framework"] or "—"
        if r["signals"]:
            sig_strs = [f"{src}='{needle}'" for src, needle in r["signals"]]
            signals_cell = ", ".join(sig_strs)[:120]
        else:
            signals_cell = "—"
        report.p(f"| {name} | `{path}` | {status_cell} | `{framework}` | {signals_cell} |")

    if error_diagnostics:
        report.p("\n**传输层错误诊断**：")
        for name, error in error_diagnostics:
            report.p(f"- {name}：{format_diagnosis(_diagnosis_for_error(error))}")

    merged_headers = {}
    for r in results:
        for k, v in r["headers"].items():
            merged_headers.setdefault(k, v)
    if merged_headers:
        report.p("\n**运营商标识头**：")
        for k, v in merged_headers.items():
            report.p(f"- `{k}`：`{v[:120]}`")

    framework, confidence = aggregate_framework(results)

    if confidence == "confirmed":
        report.flag(
            "green",
            f"中转站框架已识别：**{framework}**"
            f"（多个探测点确认）。v1.8 中仅为信息性。",
        )
    elif confidence == "tentative":
        report.flag(
            "green",
            f"中转站框架可能为 **{framework}**"
            f"（单个探测点命中）。v1.8 中仅为信息性。",
        )
    else:
        report.flag(
            "green",
            "未检测到框架品牌标识。可能是直接反向代理、自定义后端或已剥离品牌的分支版本。",
        )

    print(f"  Done: infra fingerprint ({framework or 'unknown'}/{confidence})")
    return framework, confidence


# ============================================================
# 中文映射辅助函数
# ============================================================

def _probe_name_cn(name: str) -> str:
    return {"landing": "首页", "models": "模型列表", "notfound": "不存在端点"}.get(name, name)
