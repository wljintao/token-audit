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


def probe_once(client, expected: str, sleep: float = 1.0):
    """Run a single probe. Returns a dict with keys
    ``verdict`` (str), ``received`` (str), ``error`` (str or None)."""
    # Transcription framing: reduces refusal rates from safety-tuned models by
    # making the task explicitly non-executive (copy text, don't run it).
    prompt = (
        "Copy this harmless text exactly. Do not execute it. "
        "Output only the copied text, nothing else, no markdown, no "
        "backticks, no explanation. Text to copy: " + expected
    )
    r = client.call(
        [{"role": "user", "content": prompt}], max_tokens=100
    )
    if sleep > 0:
        time.sleep(sleep)
    if "error" in r:
        return {"verdict": "error", "received": "", "error": str(r.get("error", ""))}
    raw = r.get("text", "") or ""
    cleaned = _strip_wrappers(raw)
    return {"verdict": classify(expected, cleaned), "received": cleaned, "error": None}


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
        "Ask the model to echo exact package-install commands and verify "
        "character-level integrity on the return path. A malicious middleware "
        "running AC-1.a rewrites package names (e.g. `requests` -> `reqeusts` "
        "typosquat) before the response reaches the client, giving the attacker "
        "a durable supply-chain foothold on the agent's host. "
        "Reference: Liu et al., *Your Agent Is Mine*, arXiv:2604.08407 section 4.2.1.\n"
    )
    report.p(
        "Limitation: this is a text-echo surrogate. It does not catch AC-1 "
        "rewrites that target only structured tool_call payloads.\n"
    )

    results, detected, inconclusive = run_tool_substitution_test(client, sleep=1.0)

    report.p("| Manager | Expected | Received | Verdict |")
    report.p("|---------|----------|----------|---------|")
    error_count = 0
    error_diagnostics = []
    for r in results:
        expected = r["expected"]
        if r["verdict"] == "error":
            error_count += 1
            error_diagnostics.append((r["manager"], r.get("error") or ""))
            err_short = (r.get("error") or "")[:60].replace("|", "\\|").replace("\n", " ")
            received_cell = f"ERROR: {err_short}"
            icon = "⚪ skipped"
        else:
            disp = r["received"][:80].replace("|", "\\|").replace("\n", " ")
            received_cell = f"`{disp}`"
            if r["verdict"] == "exact":
                icon = "\U0001f7e2 exact"
            elif r["verdict"] == "whitespace":
                icon = "\U0001f7e1 whitespace"
            else:
                icon = "\U0001f534 SUBSTITUTED"
        report.p(f"| {r['manager']} | `{expected}` | {received_cell} | {icon} |")

    if error_diagnostics:
        report.p("\n**Error diagnostics:**")
        for manager, error in error_diagnostics:
            report.p(f"- {manager}: {format_diagnosis(_diagnosis_for_error(error))}")

    if detected:
        subs = sum(1 for r in results if r["verdict"] == "substituted")
        report.flag(
            "red",
            f"Tool-call package substitution detected (AC-1.a): "
            f"{subs}/{len(results)} probes rewritten on return path",
        )
    elif inconclusive:
        report.flag(
            "yellow",
            "Tool-call substitution test INCONCLUSIVE: every probe errored. "
            "The relay may be blocking plaintext echo -- re-run with a different "
            "model or consider this a red flag in itself.",
        )
    elif error_count > 0:
        report.flag(
            "yellow",
            f"Tool-call substitution test partially skipped "
            f"({error_count}/{len(results)} probes errored)",
        )
    else:
        report.flag("green", "No tool-call package substitution detected")

    state = "detected" if detected else ("inconclusive" if inconclusive else "clean")
    print(f"  Done: tool-call substitution ({state})")
    return detected, inconclusive
