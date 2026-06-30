"""Step 9: Error Response Leakage (AC-2 adjacent) (错误响应泄露测试).

发送 7 个确定性故意破坏的请求（malformed JSON / 无效 model / 错误 content-type
/ 缺字段 / 未知端点 / 强制上游错误 / auth echo），捕获响应体和响应头，扫描
凭证回显、上游 URL、环境变量名、文件系统路径、堆栈标记。
返回 (severity, inconclusive) 喂入风险矩阵 d4 / d4m / d4i。
"""
from __future__ import annotations

import json
import re

from step_helpers import format_diagnosis, _diagnosis_for_error

STEP_NAME_CN = "错误响应泄露测试 (AC-2)"


# ============================================================
# Step 9 private helpers (moved from main.py lines 3110-3607)
# ============================================================

# Upstream provider hostnames. If any of these appear in a relay's error
# response, the relay is exposing its internal plumbing -- which maps onto
# the attacker's credential-collection surface.
UPSTREAM_HOSTS = (
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
    "openrouter.ai",
    "api.mistral.ai",
    "api.deepseek.com",
    "api.together.xyz",
    "api.groq.com",
)

# Environment variable names whose presence in an error body means the
# relay's error handler is dumping its own process environment. Any
# OPENAI_API_KEY / ANTHROPIC_API_KEY echo is a direct credential leak for
# OTHER users of the same relay, even if our own key is not echoed.
ENV_VAR_MARKERS = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENROUTER_API_KEY",
    "GEMINI_API_KEY",
    "DEEPSEEK_API_KEY",
    "MISTRAL_API_KEY",
    "API_KEY=",
    "SECRET_KEY=",
)

# Filesystem path prefixes that signal a server-side path leak. Captures
# both POSIX and Windows deployment layouts.
PATH_PREFIXES = (
    "/home/",
    "/root/",
    "/var/www/",
    "/var/lib/",
    "/app/",
    "/opt/",
    "/usr/local/",
    "C:\\Users\\",
    "C:\\ProgramData\\",
)

# Stack trace markers from common server-side languages. Any of these in
# an error body means the relay is propagating an unhandled exception all
# the way out to the client.
STACK_TRACE_MARKERS = (
    "Traceback (most recent call last)",
    'File "',
    "at <anonymous>",
    "at Object.",
    "at async ",
    "goroutine 1 [",
    "panic: ",
)

# LiteLLM internal field names that should NEVER appear in a client-facing
# error body.
LITELLM_INTERNAL_MARKERS = (
    "user_api_key_user_email",
    "requester_ip_address",
    "UserAPIKeyAuth",
    "previous_models",
    "litellm_params",
    '"user_api_key"',
    '"model_list"',
)

# PII echo markers from provider-side guardrails.
PII_ECHO_MARKERS = (
    '"piiEntities"',
    "sensitiveInformationPolicy",
)

# Secret shape patterns adapted from LiteLLM ``_logging.py``.
SECRET_REGEX_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9\-_]{20,}"),                      "sk_prefix_secret"),
    (re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]{20,}=*"),         "bearer_token"),
    (re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),                   "aws_access_key"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"),                      "google_api_key"),
    (re.compile(r"[?&]key=[A-Za-z0-9_\-]{25,}"),                "google_key_url_param"),
    (re.compile(r"ya29\.[A-Za-z0-9_.~+/\-]{20,}"),              "gcp_oauth_token"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*"), "jwt_token"),
    (re.compile(
        r"-----BEGIN[A-Z \-]*PRIVATE KEY-----[\s\S]*?-----END[A-Z \-]*PRIVATE KEY-----"
    ),                                                           "pem_private_key"),
    (re.compile(r"(?<=://)[^\s'\"]*:[^\s'\"@]+(?=@)"),          "db_connstring_password"),
]


def _build_triggers(aggressive: bool):
    """Build the list of error-probe request specs."""
    valid_body = json.dumps({
        "model": "claude-opus-4-6",
        "max_tokens": 10,
        "messages": [{"role": "user", "content": "hi"}],
    }).encode("utf-8")

    triggers = [
        ("malformed_json",   "POST", "/v1/messages", b"{not json", "application/json", None),
        ("invalid_model",    "POST", "/v1/messages",
         json.dumps({
             "model": "nonexistent-xyz-999",
             "max_tokens": 10,
             "messages": [{"role": "user", "content": "hi"}],
         }).encode("utf-8"), "application/json", None),
        ("wrong_content_type", "POST", "/v1/messages", valid_body, "text/plain", None),
        ("missing_messages", "POST", "/v1/messages",
         b'{"model":"claude-opus-4-6","max_tokens":10}', "application/json", None),
        ("unknown_endpoint", "POST", "/v1/nonexistent-route", b"{}", "application/json", None),
        ("force_upstream_error", "POST", "/v1/messages",
         json.dumps({
             "model": "claude-opus-4-6",
             "max_tokens": 99999999,
             "messages": [{"role": "user", "content": "hi"}],
         }).encode("utf-8"), "application/json", None),
        ("auth_probe", "POST", "/v1/messages", valid_body, "application/json",
         {
             "Authorization": "Bearer nothing-fake-token-xyz-999-auth-probe",
             "x-api-key": "sk-fake-xapi-probe-nothing-real-xyz99999",
         }),
    ]
    if aggressive:
        filler = "A" * (256 * 1024)
        big_body = json.dumps({
            "model": "claude-opus-4-6",
            "max_tokens": 10,
            "messages": [{"role": "user", "content": filler}],
        }).encode("utf-8")
        triggers.append((
            "oversized_context",
            "POST", "/v1/messages",
            big_body,
            "application/json",
            None,
        ))
    return triggers


def _redact_api_key(text: str, api_key: str) -> str:
    """Replace api_key occurrences with ``<REDACTED_API_KEY>``."""
    if not api_key or not text:
        return text
    text = text.replace(api_key, "<REDACTED_API_KEY>")
    if len(api_key) >= 8:
        text = re.sub(
            re.escape(api_key[:8]) + r"[A-Za-z0-9\-_]*",
            "<REDACTED_PREFIX>",
            text,
        )
    return text


def _mk_hit(severity: str, kind: str, snippet: str, where: str, api_key: str) -> dict:
    """Build a single hit dict with snippet redaction applied unconditionally."""
    return {
        "severity": severity,
        "kind": kind,
        "snippet": _redact_api_key(snippet, api_key),
        "where": where,
    }


def scan_for_leaks(body: str, response_headers: dict, api_key: str, base_url: str) -> list:
    """Scan the response body and response headers for credential leaks."""
    del base_url
    hits = []
    targets = [("body", body or "")]
    if response_headers:
        for k, v in response_headers.items():
            targets.append((f"header: {k}", str(v)))

    first8 = api_key[:8] if api_key and len(api_key) >= 8 else ""

    for where, text in targets:
        if not text:
            continue
        text_lower = text.lower()
        claimed_spans = []

        # CRITICAL: full api key echo
        if api_key and api_key in text:
            idx = text.index(api_key)
            claimed_spans.append((idx, idx + len(api_key)))
            raw = text[max(0, idx - 40):idx + len(api_key) + 40]
            hits.append(_mk_hit("critical", "full_api_key_echo", raw, where, api_key))
        elif first8 and first8 in text:
            idx = text.index(first8)
            claimed_spans.append((idx, idx + len(first8)))
            raw = text[max(0, idx - 40):idx + len(first8) + 40]
            hits.append(_mk_hit("high", "api_key_prefix", raw, where, api_key))

        # HIGH: secret shape regex
        for pattern, kind in SECRET_REGEX_PATTERNS:
            m = pattern.search(text)
            if not m:
                continue
            start, end = m.start(), m.end()
            if any(start < ce and end > cs for cs, ce in claimed_spans):
                continue
            raw = text[max(0, start - 20):min(len(text), end + 20)]
            hits.append(_mk_hit("high", kind, raw, where, api_key))

        # HIGH: upstream provider host
        for host in UPSTREAM_HOSTS:
            if host in text_lower:
                idx = text_lower.index(host)
                raw = text[max(0, idx - 30):idx + len(host) + 30]
                hits.append(_mk_hit("high", "upstream_host", raw, where, api_key))
                break

        # HIGH: env var name
        for env in ENV_VAR_MARKERS:
            if env in text:
                idx = text.index(env)
                raw = text[max(0, idx - 20):idx + len(env) + 40]
                hits.append(_mk_hit("high", "env_var", raw, where, api_key))
                break

        # MEDIUM: filesystem path
        for prefix in PATH_PREFIXES:
            if prefix in text:
                idx = text.index(prefix)
                raw = text[max(0, idx):idx + 80]
                hits.append(_mk_hit("medium", "fs_path", raw, where, api_key))
                break

        # MEDIUM: stack trace
        for marker in STACK_TRACE_MARKERS:
            if marker in text:
                idx = text.index(marker)
                raw = text[max(0, idx):idx + 120]
                hits.append(_mk_hit("medium", "stack_trace", raw, where, api_key))
                break

        # MEDIUM: litellm internal
        for marker in LITELLM_INTERNAL_MARKERS:
            if marker in text:
                idx = text.index(marker)
                raw = text[max(0, idx - 20):idx + len(marker) + 60]
                hits.append(_mk_hit("medium", "litellm_internal_leak", raw, where, api_key))
                break

        # MEDIUM: PII echo
        for marker in PII_ECHO_MARKERS:
            if marker in text:
                idx = text.index(marker)
                raw = text[max(0, idx):idx + 120]
                hits.append(_mk_hit("medium", "pii_echo", raw, where, api_key))
                break

    return hits


def _highest_severity(hits: list) -> str:
    if not hits:
        return "none"
    order = ("critical", "high", "medium")
    for level in order:
        if any(h["severity"] == level for h in hits):
            return level
    return "none"


def run_error_leakage_test(client, api_key: str, base_url: str, aggressive: bool = False):
    """Run all error-leakage probes against the client.

    Returns ``(results, severity, inconclusive)``.
    """
    triggers = _build_triggers(aggressive)
    default_auth_headers = {
        "x-api-key": api_key,
        "Authorization": f"Bearer {api_key}",
        "anthropic-version": "2023-06-01",
    }

    results = []
    for name, method, path, body, content_type, header_override in triggers:
        if header_override:
            auth_headers = {**default_auth_headers, **header_override}
        else:
            auth_headers = default_auth_headers
        r = client.raw_request(
            method=method,
            path=path,
            headers=auth_headers,
            body=body,
            content_type=content_type,
            timeout=30,
        )
        status = r.get("status", 0)
        body_text = r.get("body", "") or ""
        resp_headers = r.get("headers", {}) or {}
        error = r.get("error")

        hits = []
        if error is None and status != 0:
            hits = scan_for_leaks(body_text, resp_headers, api_key, base_url)

        severity = _highest_severity(hits)
        preview = _redact_api_key(body_text[:400], api_key)

        results.append({
            "trigger": name,
            "status": status,
            "error": error,
            "hits": hits,
            "severity": severity,
            "body_preview": preview,
        })

    all_hits = [h for r in results for h in r["hits"]]
    overall_severity = _highest_severity(all_hits)

    all_200 = all(r["status"] == 200 for r in results)
    all_errors = all(
        r["error"] is not None or r["status"] == 0 for r in results
    )
    inconclusive = all_200 or all_errors

    return results, overall_severity, inconclusive


# ============================================================
# Step 9 public entry
# ============================================================

def run(client, report, **kwargs) -> tuple[str, bool]:
    """Error response leakage test (AC-2 adjacent).

    Returns ``(severity, inconclusive)`` where severity is one of
    ``"none"``, ``"medium"``, ``"high"``, ``"critical"``.
    """
    args = kwargs.get("args")
    report.h2(f"9. {STEP_NAME_CN}")
    report.p(
        "向中转站发送一系列确定性构造的错误请求（畸形 JSON、无效模型名、"
        "错误 Content-Type、缺失字段、未知端点、强制上游错误、认证探测），"
        "扫描错误响应体和响应头中是否泄露凭证、上游 URL、环境变量名、"
        "文件系统路径和堆栈标记。"
        "参考文献：Liu et al., *Your Agent Is Mine*, arXiv:2604.08407 "
        "图 3（AC-2 凭证滥用：4.25% 的免费中转站存在此问题，"
        "比 AC-1 代码注入高 2 倍）。\n"
    )
    if args.aggressive_error_probes:
        report.p("_激进探测已启用：包含 256 KB 超大上下文请求。_\n")

    results, severity, inconclusive = run_error_leakage_test(
        client, args.key, client.base_url,
        aggressive=args.aggressive_error_probes,
    )

    report.p("| 触发类型 | HTTP 状态码 | 严重程度 | 泄露类型 |")
    report.p("|----------|-------------|----------|----------|")
    transport_error_diagnostics = []
    for r in results:
        name = r["trigger"]
        status_cell = str(r["status"]) if r["status"] else "—"
        if r["error"]:
            transport_error_diagnostics.append((name, r["error"]))
            status_cell = f"错误：{r['error'][:40]}"
        sev = r["severity"]
        if sev == "critical":
            sev_cell = "\U0001f534 严重"
        elif sev == "high":
            sev_cell = "\U0001f534 高危"
        elif sev == "medium":
            sev_cell = "\U0001f7e1 中等"
        else:
            sev_cell = "\U0001f7e2 无"
        leak_kinds = sorted({h["kind"] for h in r["hits"]})
        leaks_cell = ", ".join(leak_kinds) if leak_kinds else "—"
        report.p(f"| {_trigger_name_cn(name)} | {status_cell} | {sev_cell} | {leaks_cell} |")

    if transport_error_diagnostics:
        report.p("\n**传输层错误诊断：**")
        for name, error in transport_error_diagnostics:
            report.p(f"- {_trigger_name_cn(name)}：{format_diagnosis(_diagnosis_for_error(error))}")

    any_hits = [r for r in results if r["hits"]]
    if any_hits:
        report.p("")
        for r in any_hits:
            report.h3(f"触发详情：`{r['trigger']}`（{_severity_cn(r['severity'])}）")
            report.p(f"HTTP 状态码：**{r['status']}**")
            report.p("响应体预览（已脱敏）：")
            report.code(r["body_preview"] or "(空)")
            report.p("检测到的泄露：")
            for h in r["hits"]:
                report.p(
                    f"- `{h['kind']}` @ {h['where']} [{_severity_cn(h['severity'])}]："
                    f"`{h['snippet'][:200].replace('`', '')}`"
                )

    if severity == "critical":
        report.flag(
            "red",
            "错误响应泄露了完整 API Key（AC-2 直接凭证回显）。"
            "请立即停止使用该中转站。",
        )
    elif severity == "high":
        report.flag(
            "red",
            "错误响应泄露了部分凭证、上游提供商 URL 或环境变量名。"
            "中转站正在暴露内部架构，攻击者可借此收集凭证。",
        )
    elif severity == "medium":
        report.flag(
            "yellow",
            "错误响应泄露了文件系统路径或堆栈跟踪。"
            "存在信息泄露但尚未直接暴露凭证。",
        )
    elif inconclusive:
        report.flag(
            "yellow",
            "错误泄露测试结果不确定：所有探测均返回 HTTP 200 "
            "或传输层错误，无法检查错误响应面。"
            "一个将畸形 JSON 静默吞入成功响应的中转站本身就很可疑。",
        )
    else:
        report.flag("green", "错误响应中未检测到凭证回显或上游信息泄露")

    state = severity if severity != "none" else ("inconclusive" if inconclusive else "clean")
    print(f"  Done: error response leakage ({state})")
    return severity, inconclusive


# ============================================================
# 中文映射辅助函数
# ============================================================

_TRIGGER_NAME_CN = {
    "malformed_json": "畸形 JSON",
    "invalid_model": "无效模型名",
    "wrong_content_type": "错误 Content-Type",
    "missing_messages": "缺失 messages 字段",
    "unknown_endpoint": "未知端点",
    "force_upstream_error": "强制上游错误",
    "auth_probe": "认证探测",
    "oversized_context": "超大上下文",
}


def _trigger_name_cn(name: str) -> str:
    return _TRIGGER_NAME_CN.get(name, name)


def _severity_cn(sev: str) -> str:
    return {"critical": "严重", "high": "高危", "medium": "中等", "none": "无"}.get(sev, sev)
