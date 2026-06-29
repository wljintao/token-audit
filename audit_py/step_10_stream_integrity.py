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
        "Open an Anthropic streaming request with thinking enabled and "
        "inspect every SSE event for structural anomalies. A relay that "
        "rewrites or downgrades the streamed response often fails one "
        "of four invariants: (1) all event types belong to Anthropic's "
        "known set (ping / message_start / content_block_start / "
        "content_block_delta / content_block_stop / message_delta / "
        "message_stop); (2) ``input_tokens`` is consistent across "
        "``message_start`` and ``message_delta``; (3) ``output_tokens`` "
        "is monotonically non-decreasing; (4) ``signature_delta`` events "
        "carry non-empty signature values. Detection concept sourced from "
        "hvoy.ai's claude_detector.py, verified against source on "
        "2026-04-11. See reference_hvoy_relayapi memory for details.\n"
    )

    signals = client.stream_call(
        [{"role": "user", "content": "Reply with the single word: ok"}],
        max_tokens=100,
        with_thinking=True,
    )
    analysis = analyze_stream(signals)
    verdict = analysis["verdict"]

    report.p("| Check | Result |")
    report.p("|-------|--------|")
    report.p(f"| Event shape | {analysis['event_shape']} |")
    report.p(
        "| Unknown events | "
        + (", ".join(analysis["unknown_events"]) if analysis["unknown_events"] else "—")
        + " |"
    )
    report.p(f"| Usage monotonic | {'yes' if analysis['usage_monotonic'] else 'NO'} |")
    report.p(f"| Usage consistent | {'yes' if analysis['usage_consistent'] else 'NO'} |")
    report.p(f"| Signature valid | {'yes' if analysis['signature_valid'] else 'NO'} |")
    report.p(
        f"| Stream model | {analysis['stream_model_name'] or '—'} "
        f"({'claude' if analysis['stream_model_is_claude'] else 'NOT claude'}) |"
    )
    report.p(f"| Total events seen | {signals.raw_event_count} |")
    if signals.total_duration_seconds is not None:
        report.p(f"| Duration | {signals.total_duration_seconds:.2f}s |")

    if analysis["findings"]:
        report.p("\n**Findings**:")
        for finding in analysis["findings"]:
            report.p(f"- {finding}")
    if signals.transport_error:
        report.p("\n**Transport error diagnosis:**")
        report.p(format_diagnosis(_diagnosis_for_error(signals.transport_error)))

    if verdict == "anomaly":
        report.flag(
            "red",
            "Stream integrity anomaly detected (AC-1 SSE-level): "
            + "; ".join(analysis["findings"])[:400],
        )
    elif verdict == "inconclusive":
        report.flag(
            "yellow",
            "Stream integrity test INCONCLUSIVE: "
            + "; ".join(analysis["findings"])[:400]
            + ". A non-Anthropic relay or broken stream cannot be audited "
              "at the SSE event layer.",
        )
    else:
        report.flag(
            "green",
            "Stream integrity clean: SSE whitelist + usage monotonicity "
            "+ signature validity + stream model identity all passed",
        )

    print(f"  Done: stream integrity ({verdict})")
    return verdict, verdict == "inconclusive"
