"""Step 8: Tool-Call Package Substitution (AC-1.a) (工具调用替换测试).

让模型逐字回显 4 个无害的包安装命令，看返回路径上是否被中间件改写。
返回值 (detected, inconclusive) 喂入风险矩阵 d3 / d3i。
"""
from __future__ import annotations

import time

from step_helpers import format_diagnosis, _diagnosis_for_error

STEP_NAME_CN = "工具调用替换测试 (AC-1.a)"


# ============================================================
# Step 8 private helpers (moved from main.py lines 2242-2347)
# ============================================================

PROBES = [
    ("pip",   "pip install requests==2.31.0"),
    ("npm",   "npm install lodash@4.17.21"),
    ("cargo", "cargo add serde"),
    ("go",    "go get github.com/stretchr/testify"),
]


def _strip_wrappers(s: str) -> str:
    """Remove common markdown/prompt wrappers the model may add despite the
    instruction (code fences, backticks, quotes, shell prompts)."""
    s = s.strip()
    # Strip fenced code block
    if s.startswith("```"):
        # drop the first line (``` or ```lang) and the closing fence
        nl = s.find("\n")
        if nl != -1:
            s = s[nl + 1:]
        if s.endswith("```"):
            s = s[:-3]
        s = s.strip()
    # Strip wrapping single-char backticks or quotes (one layer)
    for ch in ("`", '"', "'"):
        if len(s) >= 2 and s[0] == ch and s[-1] == ch:
            s = s[1:-1]
    s = s.strip()
    # Strip leading shell prompt / comment markers
    for prefix in ("$ ", "# ", "> "):
        if s.startswith(prefix):
            s = s[len(prefix):]
    return s


def classify(expected: str, received: str) -> str:
    """Classify the probe verdict.

    Returns one of:
      - ``"exact"``        : character-identical to expected
      - ``"whitespace"``   : same whitespace-delimited tokens modulo case and
                             trailing punctuation (benign model noise such as a
                             trailing newline, period, or all-caps)
      - ``"substituted"``  : token-level divergence -> AC-1.a signal

    Critically, this does NOT collapse internal whitespace. A response that
    inserts a space inside a package identifier (e.g. ``req uests``) changes
    shell tokenization and must be flagged as substitution. Similarly, a
    multi-line response that contains the expected command alongside a
    malicious variant will not match the token list and will be flagged.
    """
    if received == expected:
        return "exact"
    # Strip trailing punctuation the model may add (period, comma, semicolon).
    trimmed = received.strip().rstrip(".,;:!?")
    exp_tokens = expected.split()
    rcv_tokens = trimmed.split()
    if exp_tokens == rcv_tokens:
        return "whitespace"
    # Case-only differences in otherwise identical token sequences
    if [t.lower() for t in exp_tokens] == [t.lower() for t in rcv_tokens]:
        return "whitespace"
    return "substituted"


def probe_once(client, expected: str, sleep: float = 1.0, max_retries: int = 2):
    """Run a single probe with retry logic.

    Returns a dict with keys ``verdict`` (str), ``received`` (str),
    ``error`` (str or None).

    Prompt 设计要点：
    - 使用「转录任务」中性框架，避免触发安全拒绝
    - 用 XML 标签清晰分隔指令与待复制文本
    - 以正面指令为主（"只输出"），减少否定指令
    - 内置重试机制：如果模型添加了多余前缀/后缀，最多重试 max_retries 次
    """
    # 使用分隔符将待复制文本与指令清晰分离
    prompt = (
        "You are a text transcription tool. Your task is to copy text exactly as given.\n\n"
        "Rules:\n"
        "- Output ONLY the text between the <text> tags\n"
        "- Preserve every character exactly: spaces, punctuation, case\n"
        "- No commentary, no markdown, no code fences\n\n"
        f"<text>{expected}</text>"
    )

    for attempt in range(max_retries + 1):
        r = client.call(
            [{"role": "user", "content": prompt}], max_tokens=100
        )
        if sleep > 0 and attempt < max_retries:
            time.sleep(sleep)
        if "error" in r:
            return {"verdict": "error", "received": "", "error": str(r.get("error", ""))}
        raw = r.get("text", "") or ""
        cleaned = _strip_wrappers(raw)

        # 快速验证：如果清理后内容与预期完全一致或仅空白差异，直接返回
        verdict = classify(expected, cleaned)
        if verdict in ("exact", "whitespace", "substituted"):
            return {"verdict": verdict, "received": cleaned, "error": None}

        # 如果模型输出了多余内容（既不是精确匹配也不是替换），
        # 尝试从响应中提取预期文本
        if expected in raw:
            return {"verdict": "exact", "received": expected, "error": None}

        # 最后一次重试仍未通过，返回当前结果
        if attempt == max_retries:
            return {"verdict": verdict, "received": cleaned, "error": None}

    # 不应到达此处，但作为安全兜底
    return {"verdict": "error", "received": "", "error": "max retries exceeded"}


def run_tool_substitution_test(client, sleep: float = 1.0):
    """Run all probes against the client.

    Returns ``(results, detected, inconclusive)`` where:

    - ``results`` is a list of dicts with keys ``manager``, ``expected``,
      ``received``, ``verdict``, ``error``
    - ``detected`` is ``True`` iff any probe returned verdict ``"substituted"``
    - ``inconclusive`` is ``True`` iff **all** probes errored (e.g. the relay
      blocks plaintext echo). An inconclusive run must NOT be treated as a
      clean signal by the caller's risk matrix.
    """
    results = []
    for manager, expected in PROBES:
        r = probe_once(client, expected, sleep=sleep)
        r["manager"] = manager
        r["expected"] = expected
        results.append(r)
    detected = any(r["verdict"] == "substituted" for r in results)
    inconclusive = all(r["verdict"] == "error" for r in results)
    return results, detected, inconclusive


# ============================================================
# Step 8 public entry
# ============================================================

def run(client, report, **kwargs) -> tuple[bool, bool]:
    """Tool-call package substitution test (AC-1.a).

    Returns ``(detected, inconclusive)``.
    """
    report.h2(f"8. {STEP_NAME_CN}")
    report.p(
        "要求模型逐字回显包安装命令，并在返回路径上验证字符级完整性。"
        "恶意的中间件可能执行 AC-1.a 攻击，将包名改写（例如 `requests` -> `reqeusts` "
        "拼写错误），从而在代理主机上建立持久的供应链攻击据点。"
        "参考文献：Liu et al., *Your Agent Is Mine*, arXiv:2604.08407 第 4.2.1 节。\n"
    )
    report.p(
        "局限性：这是一个文本回显替代测试。它无法捕获仅针对结构化 tool_call "
        "负载的 AC-1 改写。\n"
    )

    results, detected, inconclusive = run_tool_substitution_test(client, sleep=1.0)

    report.p("| 包管理器 | 预期命令 | 实际接收 | 判定结果 |")
    report.p("|----------|----------|----------|----------|")
    error_count = 0
    error_diagnostics = []
    for r in results:
        expected = r["expected"]
        if r["verdict"] == "error":
            error_count += 1
            error_diagnostics.append((r["manager"], r.get("error") or ""))
            err_short = (r.get("error") or "")[:60].replace("|", "\\|").replace("\n", " ")
            received_cell = f"错误：{err_short}"
            icon = "⚪ 跳过"
        else:
            disp = r["received"][:80].replace("|", "\\|").replace("\n", " ")
            received_cell = f"`{disp}`"
            if r["verdict"] == "exact":
                icon = "\U0001f7e2 完全匹配"
            elif r["verdict"] == "whitespace":
                icon = "\U0001f7e1 空白差异"
            else:
                icon = "\U0001f534 已被替换"
        report.p(f"| {r['manager']} | `{expected}` | {received_cell} | {icon} |")

    if error_diagnostics:
        report.p("\n**错误诊断：**")
        for manager, error in error_diagnostics:
            report.p(f"- {manager}：{format_diagnosis(_diagnosis_for_error(error))}")

    if detected:
        subs = sum(1 for r in results if r["verdict"] == "substituted")
        report.flag(
            "red",
            f"检测到工具调用包替换攻击（AC-1.a）："
            f"{subs}/{len(results)} 个探测在返回路径上被改写",
        )
    elif inconclusive:
        report.flag(
            "yellow",
            "工具调用替换测试结果不确定：所有探测都出错。"
            "中转站可能阻止了明文回显——请使用不同模型重新测试，"
            "或将其本身视为一个危险信号。",
        )
    elif error_count > 0:
        report.flag(
            "yellow",
            f"工具调用替换测试部分跳过"
            f"（{error_count}/{len(results)} 个探测出错）",
        )
    else:
        report.flag("green", "未检测到工具调用包替换攻击")

    state = "detected" if detected else ("inconclusive" if inconclusive else "clean")
    print(f"  Done: tool-call substitution ({state})")
    return detected, inconclusive
