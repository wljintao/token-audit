"""Step 3: Token Injection Detection (token注入检测).

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


STEP_NAME_CN = "token注入检测"


def run(client, report, **kwargs) -> int | None:
    """Send minimal messages, compare expected vs actual input_tokens.

    Returns the largest observed delta (or None if every probe errored).
    """
    report.h2(f"3. {STEP_NAME_CN}")
    report.p("通过发送极短消息并对比「预期 token 数」与「实际 input_tokens」，"
             "差值即为中转站暗中注入的隐藏系统提示词大小。\n")

    tests = [
        # 极简测试（精确测量基线）
        ("极简英文消息", None, "Hi", 5),
        ("极简中文消息", None, "你好", 6),
        # 常见使用场景
        ("短对话（无系统提示词）", None, "请帮我写一个 Python 函数，计算斐波那契数列的第 n 项", 25),
        ("短对话 + 简短系统提示词", "你是一个有帮助的助手。", "解释一下什么是机器学习", 30),
        ("短对话 + 详细系统提示词",
         "你是一个专业的编程助手，擅长 Python、JavaScript 和 Go 语言。请用简洁清晰的中文回答问题，并提供代码示例。",
         "如何用 Python 读取 JSON 文件？", 55),
        # 多轮对话场景
        ("多轮对话（2 轮）", "你是 AI 助手。",
         [{"role": "user", "content": "什么是 API？"},
          {"role": "assistant", "content": "API 是应用程序编程接口。"},
          {"role": "user", "content": "能给个例子吗？"}], 50),
        # 长消息测试
        ("长用户消息", None,
         "请分析以下代码的问题：\n```python\ndef process_data(data):\n    result = []\n    for item in data:\n        if item > 0:\n            result.append(item * 2)\n        else:\n            result.append(item)\n    return result\n```\n这段代码有什么可以优化的地方？", 80),
        # 模型身份验证（检测是否伪造模型）
        ("身份验证 - 直接询问", None,
         "请详细介绍你自己：你是什么模型？具体版本号是什么？你的训练数据截止到什么时候？你有哪些独特的能力？", 35),
        ("身份验证 - 技术细节", None,
         "请告诉我你的技术规格：上下文窗口大小是多少？你支持的最大输出 tokens 是多少？你的知识截止日期是哪一天？", 40),
    ]

    report.p("| 测试用例 | 实际 input_tokens | 预期 | 差值 |")
    report.p("|----------|-------------------|------|------|")

    injection_size = 0
    errors = []
    success_count = 0
    error_diagnostics = []
    for test_case in tests:
        name = test_case[0]
        sys_prompt = test_case[1]
        messages = test_case[2]
        expected = test_case[3]

        # 支持单条消息或多轮对话
        if isinstance(messages, str):
            messages = [{"role": "user", "content": messages}]

        r = client.call(messages, system=sys_prompt, max_tokens=100)
        if "error" in r:
            report.p(f"| {name} | 错误 | ~{expected} | - |")
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
        report.p("\n**错误诊断：**")
        for name, error in error_diagnostics:
            report.p(f"- {name}：{format_diagnosis(_diagnosis_for_error(error))}")

    if success_count == 0:
        if errors and all(_looks_like_claude_code_client_gate(err) for err in errors):
            report.flag(
                "yellow",
                "token注入检测无法完成：所有探测请求均被拒绝"
                "（仅限 Claude Code 客户端访问）。"
                "该中转站似乎限制了客户端类型，无法测量隐藏注入。",
            )
        else:
            report.flag(
                "yellow",
                f"token注入检测无法完成：全部 {len(errors)} 个探测请求均失败，"
                "无法测量隐藏提示词注入。",
            )
        print("  Done: token injection (inconclusive, all probes errored)")
        return None

    if injection_size > 100:
        report.flag("red",
                     f"检测到隐藏系统提示词注入（每次请求约 {injection_size} tokens）")
    elif injection_size > 20:
        report.flag("yellow",
                     f"检测到少量注入（约 {injection_size} tokens）")
    else:
        report.flag("green", "未检测到token注入")

    print(f"  Done: token injection (delta: ~{injection_size} tokens)")
    return injection_size
