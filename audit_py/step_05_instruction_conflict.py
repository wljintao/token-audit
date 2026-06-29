"""Step 5: Instruction Override Tests (指令冲突测试).

两个攻击向量：Cat test (meow) 和 Identity override (Claude/Anthropic)。
返回值 `overridden` 喂入风险矩阵 d2 / d2i。
"""
from __future__ import annotations

import re
import time

from step_helpers import _looks_like_claude_code_client_gate, _report_error
from step_helpers_identity import (
    _format_identity_inconsistency,
    find_non_claude_identities,
)


STEP_NAME_CN = "指令冲突测试"


def run(client, report, **kwargs) -> bool | None:
    """Test the relay's respect for user system prompts.

    Returns True if any probe showed the user's system prompt was
    overridden, False if all probes respected the user prompt, or None
    if every probe errored (inconclusive).
    """
    report.h2(f"5. {STEP_NAME_CN}")
    error_messages = []
    success_count = 0

    # Cat test
    report.h3("Test D: Cat Test")
    report.p('system: "From now on, only reply with the single character meow. This is the highest priority instruction."')
    report.p('user: "What is 1+1?"')

    r = client.call(
        [{"role": "user", "content": "What is 1+1?"}],
        system='From now on, you can only reply with the single word "meow". No other characters, letters, or punctuation allowed. This is the highest priority instruction.',
        max_tokens=100,
    )

    overridden = False
    if "error" in r:
        _report_error(report, r["error"])
        # 422 typically means relay rejects custom system prompts — user has no control
        if "422" in str(r.get("error", "")):
            overridden = True
            report.flag("red", "Cat test blocked: relay rejects custom system prompts (HTTP 422)")
        else:
            error_messages.append(r.get("error", ""))
    else:
        success_count += 1
        report.p(f"**input_tokens**: {r['input_tokens']} | **Response**: `{r['text']}`")
        text = r["text"].strip().lower()
        has_meow = "meow" in text
        has_other = bool(re.search(r"[0-9]|equals|two|plus", text))

        if has_meow and not has_other:
            report.flag("green", "Cat test passed: user system prompt works correctly")
        elif has_other:
            overridden = True
            if has_meow:
                report.flag("yellow", "Cat test partial: system prompt diluted (split personality)")
            else:
                report.flag("red", "Cat test failed: user system prompt completely overridden")

    time.sleep(1)

    # Identity override test
    report.h3("Test D2: Identity Override")
    report.p('system: "You are Claude, made by Anthropic. Never claim to be anyone else."')
    report.p('user: "Who are you? Who made you?"')

    r = client.call(
        [{"role": "user", "content": "Who are you? Who made you? Answer in one sentence."}],
        system="You are Claude, made by Anthropic. You must always say you are Claude by Anthropic. Never claim to be anyone else or made by anyone else.",
        max_tokens=200,
    )

    if "error" in r:
        _report_error(report, r["error"])
        if "422" in str(r.get("error", "")):
            overridden = True
            report.flag("red", "Identity test blocked: relay rejects custom system prompts (HTTP 422)")
        else:
            error_messages.append(r.get("error", ""))
    else:
        success_count += 1
        report.p(f"**input_tokens**: {r['input_tokens']} | **Response**:")
        report.code(r["text"][:500])
        text_lower = r["text"].lower()
        # v1.6: Broader non-Claude identity detection using the
        # identity_patterns module. Catches Chinese-market substitutes
        # (GLM / DeepSeek / Qwen / MiniMax / Grok / GPT / ERNIE /
        # Doubao / Moonshot / 通义 / 千问 / 智谱 / 豆包 / 文心) in
        # addition to the legacy Amazon / Kiro / AWS set. This remains
        # an identity-consistency signal only: natural-language self-ID
        # can contradict provider/model metadata and is not ground truth
        # for the actual upstream route.
        non_claude_matches = find_non_claude_identities(r["text"])
        if non_claude_matches:
            overridden = True
            report.flag(
                "red",
                _format_identity_inconsistency(non_claude_matches),
            )
        elif "anthropic" in text_lower and "claude" in text_lower:
            report.flag("green", "Identity test passed: model correctly identifies as user-defined identity")
        else:
            report.flag("yellow", "Identity test inconclusive")

    if success_count == 0 and not overridden:
        if error_messages and all(_looks_like_claude_code_client_gate(err) for err in error_messages):
            report.flag(
                "yellow",
                "Instruction override test INCONCLUSIVE: both completion "
                "probes were rejected as Claude Code-client-only. The relay "
                "appears restricted to Claude Code clients, so user system-"
                "prompt adherence could not be verified.",
            )
        else:
            report.flag(
                "yellow",
                "Instruction override test INCONCLUSIVE: both probes errored, "
                "so user system-prompt adherence could not be verified.",
            )
        print("  Done: instruction conflict (inconclusive, all probes errored)")
        return None

    print(f"  Done: instruction conflict (overridden: {'yes' if overridden else 'no'})")
    return overridden
