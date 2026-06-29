"""Step 3: Token Injection Detection (令牌注入检测).

发送 3 个最小消息，对比 expected vs actual input_tokens。差值 = 隐藏注入。
返回值 `injection` 进入风险矩阵 d1 / d1i。
"""
from __future__ import annotations

import time

from step_helpers import (
    format_diagnosis,
    _diagnosis_for_error,
    _looks_like_claude_code_client_gate,
)


STEP_NAME_CN = "令牌注入检测"


def run(client, report, **kwargs) -> int | None:
    """Send minimal messages, compare expected vs actual input_tokens.

    Returns the largest observed delta (or None if every probe errored).
    """
    report.h2(f"3. {STEP_NAME_CN}")
    report.p("Send minimal messages, compare expected vs actual input_tokens. Delta = hidden injection.\n")

    tests = [
        ("'Say hi' (no system prompt)", None, "Say hi", 10),
        ("'Say hi' + short system prompt", "You are a helpful assistant.", "Say hi", 20),
        ("'Who are you' (no system prompt)", None, "Who are you?", 15),
    ]

    report.p("| Test | Actual input_tokens | Expected | Delta |")
    report.p("|------|---------------------|----------|-------|")

    injection_size = 0
    errors = []
    success_count = 0
    error_diagnostics = []
    for name, sys_prompt, user_msg, expected in tests:
        r = client.call([{"role": "user", "content": user_msg}],
                        system=sys_prompt, max_tokens=100)
        if "error" in r:
            report.p(f"| {name} | ERROR | ~{expected} | - |")
            errors.append(r.get("error", ""))
            error_diagnostics.append((name, r["error"]))
        else:
            success_count += 1
            actual = r["input_tokens"]
            diff = actual - expected
            injection_size = max(injection_size, diff)
            report.p(f"| {name} | **{actual}** | ~{expected} | **~{diff}** |")
        time.sleep(1)

    if error_diagnostics:
        report.p("\n**Error diagnostics:**")
        for name, error in error_diagnostics:
            report.p(f"- {name}: {format_diagnosis(_diagnosis_for_error(error))}")

    if success_count == 0:
        if errors and all(_looks_like_claude_code_client_gate(err) for err in errors):
            report.flag(
                "yellow",
                "Token injection test INCONCLUSIVE: every completion probe "
                "was rejected as Claude Code-client-only. The relay appears "
                "restricted to Claude Code clients, so hidden prompt injection "
                "could not be measured.",
            )
        else:
            report.flag(
                "yellow",
                f"Token injection test INCONCLUSIVE: all {len(errors)} probes "
                "errored, so hidden prompt injection could not be measured.",
            )
        print("  Done: token injection (inconclusive, all probes errored)")
        return None

    if injection_size > 100:
        report.flag("red", f"Hidden system prompt injection detected (~{injection_size} tokens/request)")
    elif injection_size > 20:
        report.flag("yellow", f"Minor injection detected (~{injection_size} tokens)")
    else:
        report.flag("green", "No token injection detected")

    print(f"  Done: token injection (delta: ~{injection_size} tokens)")
    return injection_size
