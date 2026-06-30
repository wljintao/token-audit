"""Step 10: Stream Integrity (流完整性测试).

打开一个带 thinking 的 Anthropic 格式流式请求，捕获所有 SSE 事件到
StreamSignals，跑 analyze_stream 给出三态判定。
返回 (verdict, inconclusive) 喂入风险矩阵 d5 / d5i。
"""
from __future__ import annotations

from main import KNOWN_SSE_EVENT_TYPES, StreamSignals
from step_helpers import format_diagnosis, _diagnosis_for_error

STEP_NAME_CN = "流完整性测试"


# ============================================================
# Step 10 private helpers (moved from main.py lines 380-576)
# ============================================================

MAX_UNKNOWN_EVENTS_REPORTED = 6


def _check_usage_monotonic(signals: "StreamSignals") -> bool:
    """``output_tokens_samples`` must be monotonically non-decreasing."""
    samples = signals.output_tokens_samples
    if len(samples) <= 1:
        return True
    for i in range(1, len(samples)):
        if samples[i] < samples[i - 1]:
            return False
    return True


def _check_usage_consistent(signals: "StreamSignals") -> bool:
    """``message_delta`` ``input_tokens`` samples must agree with the
    ``input_tokens`` reported by the initial ``message_start``."""
    if signals.input_tokens is None:
        return True
    if not signals.message_delta_input_tokens_samples:
        return True
    return all(
        sample == signals.input_tokens
        for sample in signals.message_delta_input_tokens_samples
    )


def _check_stream_model(signals: "StreamSignals") -> bool:
    """``message_start.message.model`` should contain ``"claude"`` for
    an Anthropic-format streaming response."""
    if not signals.message_start_model:
        return False
    return "claude" in signals.message_start_model.lower()


def analyze_stream(signals: "StreamSignals") -> dict:
    """Analyze a populated :class:`StreamSignals` for integrity anomalies.

    Returns a dict with keys: verdict, event_shape, unknown_events,
    usage_monotonic, usage_consistent, signature_valid, stream_model_name,
    stream_model_is_claude, findings.
    """
    if signals.transport_error:
        return {
            "verdict": "inconclusive",
            "event_shape": "weak",
            "unknown_events": [],
            "usage_monotonic": True,
            "usage_consistent": True,
            "signature_valid": True,
            "stream_model_name": signals.message_start_model,
            "stream_model_is_claude": True,
            "findings": [f"Stream transport error: {signals.transport_error}"],
        }

    non_ping_events = [e for e in signals.event_types if e != "ping"]
    if signals.raw_event_count == 0 or not non_ping_events:
        return {
            "verdict": "inconclusive",
            "event_shape": "weak",
            "unknown_events": [],
            "usage_monotonic": True,
            "usage_consistent": True,
            "signature_valid": True,
            "stream_model_name": signals.message_start_model,
            "stream_model_is_claude": True,
            "findings": [
                "Stream opened but produced no non-ping events — the "
                "relay is either broken or does not speak Anthropic SSE"
            ],
        }

    unknown_events = sorted({
        e for e in signals.event_types if e not in KNOWN_SSE_EVENT_TYPES
    })
    unknown_events_capped = unknown_events[:MAX_UNKNOWN_EVENTS_REPORTED]

    usage_monotonic = _check_usage_monotonic(signals)
    usage_consistent = _check_usage_consistent(signals)
    signature_valid = signals.empty_signature_delta_count == 0
    stream_model_is_claude = _check_stream_model(signals)

    findings = []
    if unknown_events:
        suffix = " (+more, capped)" if len(unknown_events) > MAX_UNKNOWN_EVENTS_REPORTED else ""
        findings.append(
            f"Stream contained {len(unknown_events)} unknown SSE event "
            f"type(s): {', '.join(unknown_events_capped)}{suffix}"
        )
    if not usage_monotonic:
        findings.append(
            "output_tokens samples across message_delta events went "
            "backwards at least once — a relay is rewriting usage fields"
        )
    if not usage_consistent:
        findings.append(
            f"input_tokens at message_start ({signals.input_tokens}) "
            f"disagrees with message_delta samples "
            f"({signals.message_delta_input_tokens_samples}) — usage rewrite"
        )
    if not signature_valid:
        findings.append(
            f"{signals.empty_signature_delta_count} signature_delta event(s) "
            "had empty signatures — thinking block downgrade or rewriter"
        )
    if not stream_model_is_claude:
        if signals.message_start_model:
            findings.append(
                f"Stream's message_start.message.model = "
                f"{signals.message_start_model!r} does not contain 'claude' — "
                "relay may be routing to a substitute model"
            )
        else:
            findings.append(
                "Stream omitted message_start.message.model entirely — "
                "relay may be stripping model identity to hide a downgrade"
            )

    anomaly = bool(
        unknown_events
        or not usage_monotonic
        or not usage_consistent
        or not signature_valid
        or not stream_model_is_claude
    )

    shape_flags_seen = sum([
        signals.has_message_start,
        signals.has_content_block_start,
        signals.has_content_block_delta,
        signals.has_message_delta,
        signals.has_message_stop,
    ])
    if shape_flags_seen >= 4 and signals.has_text_delta and not unknown_events:
        event_shape = "pass"
    elif shape_flags_seen >= 2:
        event_shape = "partial"
    else:
        event_shape = "weak"

    return {
        "verdict": "anomaly" if anomaly else "clean",
        "event_shape": event_shape,
        "unknown_events": unknown_events_capped,
        "usage_monotonic": usage_monotonic,
        "usage_consistent": usage_consistent,
        "signature_valid": signature_valid,
        "stream_model_name": signals.message_start_model,
        "stream_model_is_claude": stream_model_is_claude,
        "findings": findings,
    }


# ============================================================
# Step 10 public entry
# ============================================================

def run(client, report, **kwargs) -> tuple[str, bool]:
    """Stream integrity test (AC-1 SSE-level)."""
    report.h2(f"10. {STEP_NAME_CN}")
    report.p(
        "开启一个启用 thinking 的 Anthropic 流式请求，检查每个 SSE 事件的结构完整性。"
        "改写或降级流式响应的中转站通常会违反以下四个不变量之一："
        "(1) 所有事件类型属于 Anthropic 已知集合（ping / message_start / "
        "content_block_start / content_block_delta / content_block_stop / "
        "message_delta / message_stop）；"
        "(2) `input_tokens` 在 `message_start` 和 `message_delta` 之间一致；"
        "(3) `output_tokens` 单调非递减；"
        "(4) `signature_delta` 事件携带非空签名值。"
        "检测概念源自 hvoy.ai 的 claude_detector.py，于 2026-04-11 验证。\n"
    )

    signals = client.stream_call(
        [{"role": "user", "content": "Reply with the single word: ok"}],
        max_tokens=100,
        with_thinking=True,
    )
    analysis = analyze_stream(signals)
    verdict = analysis["verdict"]

    report.p("| 检查项 | 结果 |")
    report.p("|--------|------|")
    report.p(f"| 事件形状 | {_event_shape_cn(analysis['event_shape'])} |")
    report.p(
        "| 未知事件类型 | "
        + (", ".join(analysis["unknown_events"]) if analysis["unknown_events"] else "—")
        + " |"
    )
    report.p(f"| 用量单调性 | {'✅ 是' if analysis['usage_monotonic'] else '❌ 否'} |")
    report.p(f"| 用量一致性 | {'✅ 是' if analysis['usage_consistent'] else '❌ 否'} |")
    report.p(f"| 签名有效性 | {'✅ 是' if analysis['signature_valid'] else '❌ 否'} |")
    report.p(
        f"| 流模型标识 | {analysis['stream_model_name'] or '—'} "
        f"({'✅ Claude' if analysis['stream_model_is_claude'] else '❌ 非 Claude'}) |"
    )
    report.p(f"| 事件总数 | {signals.raw_event_count} |")
    if signals.total_duration_seconds is not None:
        report.p(f"| 耗时 | {signals.total_duration_seconds:.2f}s |")

    if analysis["findings"]:
        report.p("\n**检测发现**：")
        for finding in analysis["findings"]:
            report.p(f"- {_translate_finding(finding)}")
    if signals.transport_error:
        report.p("\n**传输层错误诊断**：")
        report.p(format_diagnosis(_diagnosis_for_error(signals.transport_error)))

    if verdict == "anomaly":
        findings_cn = [_translate_finding(f) for f in analysis["findings"]]
        report.flag(
            "red",
            "检测到流完整性异常（AC-1 SSE 层）："
            + "；".join(findings_cn)[:400],
        )
    elif verdict == "inconclusive":
        findings_cn = [_translate_finding(f) for f in analysis["findings"]]
        report.flag(
            "yellow",
            "流完整性测试结果不确定："
            + "；".join(findings_cn)[:400]
            + "。非 Anthropic 中转站或损坏的流无法在 SSE 事件层进行审计。",
        )
    else:
        report.flag(
            "green",
            "流完整性检查通过：SSE 事件白名单 + 用量单调性 + "
            "签名有效性 + 流模型标识 全部正常",
        )

    print(f"  Done: stream integrity ({verdict})")
    return verdict, verdict == "inconclusive"


# ============================================================
# 中文映射辅助函数
# ============================================================

def _event_shape_cn(shape: str) -> str:
    return {"pass": "✅ 完整", "partial": "⚠️ 部分", "weak": "❌ 薄弱"}.get(shape, shape)


def _translate_finding(finding: str) -> str:
    """将 analyze_stream 的英文发现翻译为中文。"""
    translations = [
        ("Stream contained", "流中包含"),
        ("unknown SSE event type(s)", "个未知 SSE 事件类型"),
        ("(+more, capped)", "（更多，已截断）"),
        ("output_tokens samples across message_delta events went backwards at least once — a relay is rewriting usage fields",
         "message_delta 事件中的 output_tokens 样本至少有一次回退——中转站正在改写用量字段"),
        ("input_tokens at message_start", "message_start 的 input_tokens"),
        ("disagrees with message_delta samples", "与 message_delta 样本不一致——用量改写"),
        ("signature_delta event(s) had empty signatures — thinking block downgrade or rewriter",
         "个 signature_delta 事件签名为空——thinking 块被降级或改写"),
        ("Stream's message_start.message.model =", "流的 message_start.message.model ="),
        ("does not contain 'claude' — relay may be routing to a substitute model",
         "不包含 'claude'——中转站可能路由到了替代模型"),
        ("Stream omitted message_start.message.model entirely — relay may be stripping model identity to hide a downgrade",
         "流完全省略了 message_start.message.model——中转站可能剥离了模型标识以隐藏降级"),
        ("Stream opened but produced no non-ping events — the relay is either broken or does not speak Anthropic SSE",
         "流已开启但未产生任何非 ping 事件——中转站可能已损坏或不支持 Anthropic SSE"),
        ("Stream transport error", "流传输错误"),
    ]
    result = finding
    for en, cn in translations:
        result = result.replace(en, cn)
    return result
