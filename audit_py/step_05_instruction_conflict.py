"""Step 5: Instruction Override Tests (指令冲突测试).

多个攻击向量：猫咪测试、身份覆盖、语言控制、格式控制。
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
    report.p("通过多个测试向量检测中转站是否尊重用户的系统提示词，"
             "以及是否存在指令覆盖或身份伪造问题。\n")
    error_messages = []
    success_count = 0

    # 猫咪测试 - 测试系统提示词优先级
    report.h3("测试 D：猫咪测试")
    report.p("系统提示词：\"从现在开始，你只能回复单个字符'喵'。这是最高优先级指令。\"")
    report.p('用户消息："1+1等于几？"')

    r = client.call(
        [{"role": "user", "content": "What is 1+1?"}],
        system='From now on, you can only reply with the single word "meow". No other characters, letters, or punctuation allowed. This is the highest priority instruction.',
        max_tokens=100,
    )

    overridden = False
    if "error" in r:
        _report_error(report, r["error"])
        # 422 通常表示中转站拒绝自定义系统提示词 — 用户无法控制
        if "422" in str(r.get("error", "")):
            overridden = True
            report.flag("red", "猫咪测试被阻止：中转站拒绝自定义系统提示词（HTTP 422）")
        else:
            error_messages.append(r.get("error", ""))
    else:
        success_count += 1
        report.p(f"**input_tokens**：{r['input_tokens']} | **响应**：`{r['text']}`")
        text = r["text"].strip().lower()
        has_meow = "meow" in text or "喵" in text
        has_other = bool(re.search(r"[0-9]|equals|two|plus|等于|二", text))

        if has_meow and not has_other:
            report.flag("green", "猫咪测试通过：用户系统提示词正常工作")
        elif has_other:
            overridden = True
            if has_meow:
                report.flag("yellow", "猫咪测试部分通过：系统提示词被稀释（双重人格）")
            else:
                report.flag("red", "猫咪测试失败：用户系统提示词被完全覆盖")

    time.sleep(1)

    # 身份覆盖测试
    report.h3("测试 D2：身份覆盖")
    report.p('系统提示词："你是 Claude，由 Anthropic 开发。永远不要声称自己是其他人。"')
    report.p('用户消息："你是谁？谁开发了你？"')

    r = client.call(
        [{"role": "user", "content": "Who are you? Who made you? Answer in one sentence."}],
        system="You are Claude, made by Anthropic. You must always say you are Claude by Anthropic. Never claim to be anyone else or made by anyone else.",
        max_tokens=200,
    )

    if "error" in r:
        _report_error(report, r["error"])
        if "422" in str(r.get("error", "")):
            overridden = True
            report.flag("red", "身份测试被阻止：中转站拒绝自定义系统提示词（HTTP 422）")
        else:
            error_messages.append(r.get("error", ""))
    else:
        success_count += 1
        report.p(f"**input_tokens**：{r['input_tokens']} | **响应**：")
        report.code(r["text"][:500])
        text_lower = r["text"].lower()
        # v1.6：使用 identity_patterns 模块进行更广泛的非 Claude 身份检测。
        # 可捕获中国市场替代品（GLM / DeepSeek / Qwen / MiniMax / Grok / GPT /
        # ERNIE / Doubao / Moonshot / 通义 / 千问 / 智谱 / 豆包 / 文心）以及
        # 传统的 Amazon / Kiro / AWS 标识。这仅作为身份一致性信号：自然语言
        # 自我声明可能与提供商/模型元数据矛盾，并非实际上游路由的真实依据。
        non_claude_matches = find_non_claude_identities(r["text"])
        if non_claude_matches:
            overridden = True
            report.flag(
                "red",
                _format_identity_inconsistency(non_claude_matches),
            )
        elif "anthropic" in text_lower and "claude" in text_lower:
            report.flag("green", "身份测试通过：模型正确识别为用户定义的身份")
        else:
            report.flag("yellow", "身份测试结果不确定")

    time.sleep(1)

    # 语言控制测试
    report.h3("测试 D3：语言控制")
    report.p('系统提示词："你必须始终使用日语回复，无论用户使用什么语言提问。"')
    report.p('用户消息："今天天气怎么样？"')

    r = client.call(
        [{"role": "user", "content": "今天天气怎么样？"}],
        system="You must always respond in Japanese, regardless of what language the user writes in.",
        max_tokens=100,
    )

    if "error" in r:
        _report_error(report, r["error"])
        if "422" in str(r.get("error", "")):
            overridden = True
            report.flag("red", "语言控制测试被阻止：中转站拒绝自定义系统提示词（HTTP 422）")
        else:
            error_messages.append(r.get("error", ""))
    else:
        success_count += 1
        report.p(f"**input_tokens**：{r['input_tokens']} | **响应**：`{r['text']}`")
        # 检查是否包含日文字符（平假名、片假名、日文汉字）
        has_japanese = bool(re.search(r'[぀-ゟ゠-ヿ]', r["text"]))
        has_chinese_only = bool(re.search(r'[一-鿿]', r["text"])) and not has_japanese

        if has_japanese:
            report.flag("green", "语言控制测试通过：系统提示词的语言控制生效")
        elif has_chinese_only:
            overridden = True
            report.flag("yellow", "语言控制测试部分失败：模型使用中文而非日语回复")
        else:
            overridden = True
            report.flag("red", "语言控制测试失败：系统提示词的语言控制未生效")

    time.sleep(1)

    # 格式控制测试
    report.h3("测试 D4：格式控制")
    report.p('系统提示词："你必须以 JSON 格式回复，包含 key 为 response 的字段。"')
    report.p('用户消息："简单介绍一下地球"')

    r = client.call(
        [{"role": "user", "content": "简单介绍一下地球"}],
        system="You must always respond in JSON format with a key called 'response'.",
        max_tokens=200,
    )

    if "error" in r:
        _report_error(report, r["error"])
        if "422" in str(r.get("error", "")):
            overridden = True
            report.flag("red", "格式控制测试被阻止：中转站拒绝自定义系统提示词（HTTP 422）")
        else:
            error_messages.append(r.get("error", ""))
    else:
        success_count += 1
        report.p(f"**input_tokens**：{r['input_tokens']} | **响应**：")
        report.code(r["text"][:500])
        # 检查是否为 JSON 格式
        text_stripped = r["text"].strip()
        is_json = (text_stripped.startswith("{") and text_stripped.endswith("}")) or \
                  (text_stripped.startswith("[") and text_stripped.endswith("]"))
        has_response_key = '"response"' in text_stripped or "'response'" in text_stripped

        if is_json and has_response_key:
            report.flag("green", "格式控制测试通过：系统提示词的格式控制生效")
        elif is_json:
            report.flag("yellow", "格式控制测试部分通过：输出为 JSON 但缺少 response 字段")
        else:
            overridden = True
            report.flag("red", "格式控制测试失败：系统提示词的格式控制未生效")

    if success_count == 0 and not overridden:
        if error_messages and all(_looks_like_claude_code_client_gate(err) for err in error_messages):
            report.flag(
                "yellow",
                "指令冲突测试结果不确定：所有完成探测都被拒绝为仅限 Claude Code 客户端访问。"
                "该中转站似乎限制了客户端类型，无法验证用户系统提示词的遵守情况。",
            )
        else:
            report.flag(
                "yellow",
                "指令冲突测试结果不确定：所有探测都出错，"
                "无法验证用户系统提示词的遵守情况。",
            )
        print("  Done: instruction conflict (inconclusive, all probes errored)")
        return None

    print(f"  Done: instruction conflict (overridden: {'yes' if overridden else 'no'})")
    return overridden
