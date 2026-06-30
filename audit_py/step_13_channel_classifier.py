"""Step 13: Upstream Channel Classifier (上游通道分类).

3 层规则识别上游服务通道（AWS Bedrock / Google Vertex / AWS API Gateway /
Anthropic 官方 / OpenRouter / Cloudflare AI Gateway / transparent Anthropic relay）。
Informational only — 不进 6D 风险矩阵。
"""
from __future__ import annotations

import json
import re

from step_helpers import format_diagnosis, _diagnosis_for_error

STEP_NAME_CN = "上游通道分类"


# ============================================================
# Step 13 private helpers (moved from main.py lines 4545-4842)
# ============================================================

TIER1_RULES = [
    ("openrouter", "id_prefix", "gen-"),
    ("openrouter", "header_value_prefix", ("x-generation-id", "gen-")),
    ("cloudflare-ai-gateway", "header_prefix", "cf-aig-"),
]


TIER2_WEIGHTS = {
    "aws-bedrock": [
        ("header_prefix", "x-amzn-bedrock-", 1.0),
        ("id_prefix", "msg_bdrk_", 1.0),
        ("body", "bedrock-2023-05-31", 0.9),
    ],
    "google-vertex": [
        ("id_prefix", "msg_vrtx_", 1.0),
        ("body", "vertex-2023-10-16", 0.9),
    ],
    "aws-apigateway": [
        ("header", "x-amz-apigw-id", 0.8),
        ("header", "apigw-requestid", 0.8),
    ],
    "anthropic-official": [
        ("header_prefix", "anthropic-ratelimit-", 0.95),
        ("header_prefix", "anthropic-priority-", 0.95),
        ("header_prefix", "anthropic-fast-", 0.95),
        ("header_value_prefix", ("request-id", "req_"), 0.6),
    ],
}


TIER2_PRIORITY = ("aws-bedrock", "google-vertex", "aws-apigateway", "anthropic-official")


TIER3_RELAY_ID_PATTERN = re.compile(r"^msg_01[A-Za-z0-9]{22,}$")
TIER3_RELAY_CONFIDENCE = 0.5

_CHANNEL_BODY_SCAN_LIMIT = 8192


def _signal_fires(signal_type, signal_value, headers_lower, message_id, body_truncated):
    """Return True if the (type, value) signal fires against the inputs."""
    if signal_type == "id_prefix":
        return bool(message_id) and message_id.startswith(signal_value)
    if signal_type == "header":
        return signal_value.lower() in headers_lower
    if signal_type == "header_prefix":
        return any(k.startswith(signal_value.lower()) for k in headers_lower)
    if signal_type == "header_value_prefix":
        name, prefix = signal_value
        value = headers_lower.get(name.lower(), "")
        return value.startswith(prefix)
    if signal_type == "header_value_contains":
        name, needle = signal_value
        value = headers_lower.get(name.lower(), "")
        return needle.lower() in value.lower()
    if signal_type == "body":
        return signal_value in body_truncated
    return False


def _evidence_string(signal_type, signal_value):
    if signal_type == "id_prefix":
        return f"id_prefix:{signal_value}"
    if signal_type == "header":
        return f"header:{signal_value}"
    if signal_type == "header_prefix":
        return f"header_prefix:{signal_value}"
    if signal_type == "header_value_prefix":
        return f"header:{signal_value[0]}={signal_value[1]}*"
    if signal_type == "header_value_contains":
        return f"header:{signal_value[0]}~{signal_value[1]}"
    if signal_type == "body":
        return f"body:{signal_value}"
    return f"{signal_type}:{signal_value}"


def classify_channel(headers, message_id, raw_body):
    """Classify a single response into upstream channel + confidence + evidence."""
    if headers is None:
        headers = {}
    headers_lower = {str(k).lower(): str(v) for k, v in headers.items()}
    message_id = message_id or ""
    body_truncated = (raw_body or "")[:_CHANNEL_BODY_SCAN_LIMIT]

    # Tier 1
    for label, signal_type, signal_value in TIER1_RULES:
        if _signal_fires(signal_type, signal_value, headers_lower, message_id, body_truncated):
            return {
                "channel": label,
                "confidence": 1.0,
                "evidence": [_evidence_string(signal_type, signal_value)],
            }

    # Tier 2
    scores = {label: 0.0 for label in TIER2_WEIGHTS}
    fired_signals = {label: [] for label in TIER2_WEIGHTS}
    for label, signals in TIER2_WEIGHTS.items():
        for signal_type, signal_value, weight in signals:
            if _signal_fires(signal_type, signal_value, headers_lower, message_id, body_truncated):
                scores[label] += weight
                fired_signals[label].append(_evidence_string(signal_type, signal_value))

    max_score = max(scores.values())
    if max_score > 0:
        winner = None
        for label in TIER2_PRIORITY:
            if scores[label] == max_score:
                winner = label
                break
        confidence = round(min(max_score, 1.0), 2)
        return {
            "channel": winner,
            "confidence": confidence,
            "evidence": fired_signals[winner],
        }

    # Tier 3
    if TIER3_RELAY_ID_PATTERN.match(message_id):
        return {
            "channel": "anthropic-relay",
            "confidence": TIER3_RELAY_CONFIDENCE,
            "evidence": [f"id_pattern:{TIER3_RELAY_ID_PATTERN.pattern}"],
        }

    return {"channel": "unknown", "confidence": 0.0, "evidence": []}


def _extract_message_id(body):
    """Pull the top-level `id` field from a JSON response body."""
    if not body:
        return None
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None
    msg_id = parsed.get("id")
    if isinstance(msg_id, str):
        return msg_id
    return None


def _build_auth_headers(client):
    """Build the auth headers for an authenticated /v1/messages call."""
    api_key = getattr(client, "api_key", "") or ""
    return {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "Authorization": f"Bearer {api_key}",
    }


def run_channel_classifier(client):
    """Fire a minimal authenticated /v1/messages probe and classify."""
    model = getattr(client, "model", None) or "claude-haiku-4-5-20251001"
    payload = json.dumps({
        "model": model,
        "max_tokens": 4,
        "messages": [{"role": "user", "content": "ping"}],
    }).encode("utf-8")

    try:
        r = client.raw_request(
            method="POST", path="/v1/messages",
            headers=_build_auth_headers(client), body=payload,
            content_type="application/json", timeout=30,
        )
    except Exception as exc:
        return {
            "channel": "unknown", "confidence": 0.0, "evidence": [],
            "raw_status": 0, "message_id": None,
            "error": f"probe-exception: {exc}", "verdict": "inconclusive",
        }

    status = r.get("status", 0)
    headers = r.get("headers", {}) or {}
    body = r.get("body", "") or ""
    error = r.get("error")

    if error or status != 200:
        return {
            "channel": "unknown", "confidence": 0.0, "evidence": [],
            "raw_status": status, "message_id": None,
            "error": error, "verdict": "inconclusive",
        }

    message_id = _extract_message_id(body)
    classification = classify_channel(headers, message_id, body)
    classification["raw_status"] = status
    classification["message_id"] = message_id
    classification["error"] = error
    classification["verdict"] = (
        "no-signal" if classification["channel"] == "unknown" else "classified"
    )
    return classification


# ============================================================
# Step 13 public entry
# ============================================================

def run(client, report, **kwargs):
    """Upstream channel classifier (v1.9). Informational only."""
    report.h2(f"13. {STEP_NAME_CN}")
    report.p(
        "发送一个最小的 `/v1/messages` 探测请求（`max_tokens=4`），"
        "从响应头、消息 `id` 和响应体中分类上游服务通道。"
        "补充步骤 11 的检测，识别仅在认证响应中出现的上游路径特征"
        "（`msg_bdrk_*` 表示 Bedrock，`msg_vrtx_*` 表示 Vertex，"
        "`anthropic-ratelimit-*` 表示 Anthropic 直连等）。"
        "v1.9 中**仅为信息性**——不纳入整体风险评级。"
        "非 Anthropic 上游本身不构成欺诈，需结合步骤 5 的身份检测结果。\n"
    )

    result = run_channel_classifier(client)
    channel = result["channel"]
    confidence = result["confidence"]
    evidence = result["evidence"]
    raw_status = result["raw_status"]
    message_id = result["message_id"]
    error = result["error"]
    verdict = result["verdict"]

    report.p("| 字段 | 值 |")
    report.p("|------|-----|")
    if error:
        report.p(f"| HTTP 状态码 | 错误：{error[:80]} |")
    else:
        report.p(f"| HTTP 状态码 | {raw_status if raw_status else '—'} |")
    report.p(f"| 消息 ID | `{message_id or '—'}` |")
    report.p(f"| 分类通道 | `{channel}` |")
    report.p(f"| 置信度 | {confidence:.2f} |")
    report.p(f"| 判定结果 | `{verdict}` |")
    if evidence:
        ev_str = ", ".join(evidence)[:200]
        report.p(f"| 证据 | {ev_str} |")
    else:
        report.p("| 证据 | — |")

    if error:
        report.p("\n**传输层错误诊断**：")
        report.p(format_diagnosis(_diagnosis_for_error(error)))
    elif verdict == "inconclusive" and raw_status:
        report.p("\n**HTTP 状态码诊断**：")
        report.p(format_diagnosis(_diagnosis_for_error(None, status=raw_status)))

    if verdict == "inconclusive":
        if error:
            report.flag(
                "yellow",
                f"通道分类器**结果不确定**：探测传输错误"
                f"（{error[:120]}）。无法分类上游通道。",
            )
        else:
            report.flag(
                "yellow",
                f"通道分类器**结果不确定**：探测返回状态码 "
                f"{raw_status}（预期 200）。可能是认证拒绝、模型名称不匹配"
                "或上游错误封装。请使用有效的密钥和支持的模型重新运行以启用分类。",
            )
    elif channel == "anthropic-relay":
        report.flag(
            "green",
            f"上游为**透明 Anthropic 中继**（置信度 {confidence:.2f}，"
            "基于原生 `msg_01...` ID 的 Tier 3 推断，无速率限制头）。"
            "中继原样转发 Anthropic 的 ID 但剥离了 Anthropic 的响应头。"
            "v1.9 中仅为信息性。",
        )
    elif channel == "unknown":
        report.flag(
            "green",
            "上游通道**未知**：探测成功（200）但无 Tier 1/2/3 信号触发。"
            "中继剥离或重写了所有上游标识符，或此组合不在我们的特征库中。"
            "v1.9 中仅为信息性。",
        )
    else:
        report.flag(
            "green",
            f"上游通道：**{channel}**（置信度 {confidence:.2f}）。"
            "v1.9 中仅为信息性。",
        )

    print(f"  Done: channel classifier ({channel}, conf={confidence:.2f}, "
          f"verdict={verdict})")
    return result
