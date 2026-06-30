#!/usr/bin/env python3
"""
audit_long_task.py --- Long-task / multi-request audit dimension (P0).

Fills the structural gap in audit.py where every probe is a single
request/response. Adds four checks that only make sense across a
multi-turn agentic session:

  (a) Structured tool_call tampering (the real AC-1.a surface that the
      text-echo surrogate in Step 8 admits it cannot catch).
  (b) Multi-turn conditional injection (AC-1.b depth): a relay may inject
      only on/after the Nth turn. We measure input_tokens per turn and
      look for a step-discontinuity in the additive offset.
  (c) History / tool_result tampering: poison a tool_result with a canary
      value and verify the model can recall it on the next turn.
  (d) Prompt-cache fidelity: send cache_control twice and verify the relay
      honours it (reports cache_read tokens) rather than silently stripping
      the beta feature.

Design constraints (no official Anthropic baseline available):
  - All verdicts are absolute / internal-consistency heuristics.
  - Mockable transport so selftest() is deterministic and offline.

Integration: each ``test_*`` follows the audit.py convention
``test_*(client, report, ...)`` and can be wrapped by ``_run_step``.
"""
import hashlib
import json
import time
from typing import List, Optional, Tuple


# ============================================================
# (a) Structured tool_call integrity (AC-1.a)
# ============================================================

# A set of quirky, low-entropy-canonical tokens the model is told to emit
# verbatim inside a tool_use input. A relay running AC-1.a rewrites the
# structured tool_use payload (package name / url / path) before it reaches
# the client. We detect any character-level deviation.
_TOOL_ECHO_SCHEMA = {
    "name": "report_payload",
    "description": "Echo a verbatim payload string back to the caller.",
    "input_schema": {
        "type": "object",
        "properties": {
            "payload": {"type": "string", "description": "The exact string to echo."},
        },
        "required": ["payload"],
    },
}

# Diverse token shapes: mixed-case, digits, symbols, a typosquat-adjacent name.
_ECHO_TOKENS = [
    "requests-pip-install-7Q2",
    "zkSync-era-bridge-v2",
    "node_modules/.cache/pkg_42",
    "apt-get install redis-server-9",
]


def _extract_tool_use_inputs(raw: dict) -> List[dict]:
    """Pull every tool_use block's ``input`` dict from an Anthropic response.

    Returns the list of input dicts (possibly empty). Never raises.
    """
    if not isinstance(raw, dict):
        return []
    content = raw.get("content")
    if not isinstance(content, list):
        return []
    out = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "tool_use":
            inp = block.get("input")
            if isinstance(inp, dict):
                out.append(inp)
    return out


def _build_tool_echo_messages(token: str) -> Tuple[list, str]:
    """Construct a request that asks the model to emit ``token`` via tool_use.

    Returns (messages, system_prompt).
    """
    system = (
        "You are a payload-echo assistant. When the user asks you to report a "
        "payload, you MUST call the `report_payload` tool exactly once with the "
        "payload argument set to the exact string the user provides, including "
        "all punctuation, case and digits. Do not modify, paraphrase, trim or "
        "reformat the string. Do not output any text, only the tool call."
    )
    messages = [
        {
            "role": "user",
            "content": (
                f"Report this payload exactly: {token}\n"
                f"Call report_payload with payload=\"{token}\"."
            ),
        }
    ]
    return messages, system


def run_tool_use_integrity(client, tokens: Optional[List[str]] = None,
                           sleep: float = 1.0) -> dict:
    """Probe structured tool_use payload integrity.

    For each token, asks the model to emit it via a tool_use block and checks
    the returned ``input.payload`` for an exact character match. Any mismatch
    is evidence of an AC-1.a relay rewrite on the structured return path.

    Returns a dict:
      - ``results``: per-token {token, expected, received, verdict}
        verdict in {"exact","substituted","no_tool_use","error"}
      - ``detected``: True if any verdict == "substituted"
      - ``inconclusive``: True if every probe failed (error/no_tool_use)
    """
    tokens = list(tokens) if tokens else list(_ECHO_TOKENS)
    results = []
    detected = False
    usable = 0
    for tok in tokens:
        messages, system = _build_tool_echo_messages(tok)
        # Use a large max_tokens so the tool call is not truncated.
        r = client.call(messages, system=system, max_tokens=256)
        if "error" in r:
            results.append({"token": tok, "expected": tok, "received": "",
                            "verdict": "error", "error": r.get("error", "")})
        else:
            inputs = _extract_tool_use_inputs(r.get("raw", {}))
            if not inputs:
                results.append({"token": tok, "expected": tok, "received": "",
                                "verdict": "no_tool_use"})
            else:
                usable += 1
                received = str(inputs[0].get("payload", ""))
                verdict = "exact" if received == tok else "substituted"
                if verdict == "substituted":
                    detected = True
                results.append({"token": tok, "expected": tok,
                                "received": received, "verdict": verdict})
        time.sleep(sleep)
    inconclusive = usable == 0
    return {"results": results, "detected": detected, "inconclusive": inconclusive}


# ============================================================
# (b) Multi-turn conditional injection (AC-1.b depth)
# ============================================================

def _expected_turn_tokens(messages_sent: list) -> int:
    """Rough lower-bound estimate of the tokens in ``messages_sent``.

    A relay with NO hidden injection should report input_tokens >= this
    estimate (the estimate is a floor, not exact). We use it only to
    compute the per-turn additive offset delta = reported - floor.
    """
    total = 0
    for m in messages_sent:
        content = m.get("content", "")
        if isinstance(content, list):
            for b in content:
                if isinstance(b, dict):
                    content = str(b.get("text", ""))
                    total += max(1, len(content) // 4)
        elif isinstance(content, str):
            total += max(1, len(content) // 4)
    return total


def run_multiturn_injection(client, turns: int = 5,
                            sleep: float = 1.0) -> dict:
    """Measure per-turn input_tokens offset to detect conditional injection.

    Holds a fixed minimal system prompt and grows the conversation one turn
    at a time. A healthy relay shows a *stable* additive offset (the hidden
    system prompt size) across turns. A conditional AC-1.b relay shows a
    *step discontinuity* --- the offset jumps at some turn N.

    Returns:
      - ``offsets``: list of (turn, reported_input_tokens, floor, offset)
      - ``discontinuity_turn``: turn index where offset jumped, or None
      - ``stable_offset``: the most common offset (hidden prompt size guess)
      - ``detected``: True if a discontinuity of > THRESHOLD tokens appears
      - ``inconclusive``: True if not enough turns succeeded
    """
    THRESHOLD = 25  # tokens; below this is measurement noise
    system = "You are a concise assistant. Reply in one short sentence."
    convo = []
    offsets = []
    per_turn_user = [
        "Explain why the sky appears blue using Rayleigh scattering.",
        "Calculate the time complexity of binary search and justify your answer.",
        "Describe the difference between TCP and UDP protocols.",
        "Explain how a hash table handles collisions.",
        "What is the CAP theorem and why does it matter in distributed systems?",
        "Describe the difference between stack and heap memory allocation.",
        "Explain the purpose of database indexing and its trade-offs.",
        "What is the difference between concurrency and parallelism?",
    ]
    successes = 0
    for i in range(turns):
        user = per_turn_user[i % len(per_turn_user)]
        convo.append({"role": "user", "content": user})
        r = client.call(list(convo), system=system, max_tokens=40)
        if "error" in r:
            offsets.append({"turn": i + 1, "reported": None,
                            "floor": None, "offset": None, "error": True})
        else:
            successes += 1
            reported = r.get("input_tokens", 0)
            floor = _expected_turn_tokens(convo) + len(system) // 4
            offset = reported - floor
            offsets.append({"turn": i + 1, "reported": reported,
                            "floor": floor, "offset": offset, "error": False})
            convo.append({"role": "assistant", "content": r.get("text", "")})
        time.sleep(sleep)

    # Detect discontinuity: a single step jump > THRESHOLD between adjacent
    # successful turns, where the new offset then *persists* (stays elevated).
    valid = [o for o in offsets if not o.get("error") and o["offset"] is not None]
    discontinuity_turn = None
    detected = False
    if len(valid) >= 3:
        for j in range(1, len(valid)):
            prev = valid[j - 1]["offset"]
            cur = valid[j]["offset"]
            if cur - prev > THRESHOLD:
                # Confirm persistence: subsequent offsets stay near `cur`.
                later = [o["offset"] for o in valid[j + 1:]]
                if not later or all(abs(o - cur) <= THRESHOLD for o in later):
                    discontinuity_turn = valid[j]["turn"]
                    detected = True
                    break
    # Most common offset = guess of hidden prompt size
    stable_offset = None
    if valid:
        from collections import Counter
        # Bucket offsets to nearest 5 to absorb noise
        buckets = Counter((o["offset"] // 5) * 5 for o in valid)
        stable_offset = buckets.most_common(1)[0][0]
    inconclusive = successes < 3
    return {
        "offsets": offsets,
        "discontinuity_turn": discontinuity_turn,
        "stable_offset": stable_offset,
        "detected": detected,
        "inconclusive": inconclusive,
    }


# ============================================================
# (c) History / tool_result tampering
# ============================================================

def run_history_tamper(client, sleep: float = 1.0) -> dict:
    """Detect tampering with a prior tool_result across turns.

    Turn 1: the model calls a tool whose result we control; we inject a
    canary value V as the tool_result. Turn 2: we ask the model what value
    the tool returned. If the relay rewrote the tool_result between turns,
    the model recalls != V.

    Returns:
      - ``canary``: the value we planted
      - ``recalled``: what the model reported on turn 2
      - ``detected``: True if canary not present in the recall text
      - ``inconclusive``: True if either turn errored
    """
    canary = "ZEBRA-9472-MANGO"
    system = (
        "You are an assistant that records tool results precisely. When asked "
        "what a tool returned, report the exact value with no changes."
    )
    # Turn 1: assistant claims it ran a tool and got the canary.
    convo = [
        {"role": "user", "content": "Fetch the daily access code."},
        {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "I'll fetch the access code."},
                {"type": "tool_use", "id": "toolu_1", "name": "get_access_code",
                 "input": {}},
            ],
        },
        {
            "role": "user",
            "content": [
                {"type": "tool_result", "tool_use_id": "toolu_1",
                 "content": f"access_code={canary}"},
            ],
        },
    ]
    r1 = client.call(list(convo), system=system, max_tokens=60)
    if "error" in r1:
        return {"canary": canary, "recalled": None, "detected": False,
                "inconclusive": True, "error": r1.get("error")}
    # Record the assistant's acknowledgement, then ask for recall.
    convo.append({"role": "assistant", "content": r1.get("text", "")})
    convo.append({"role": "user",
                  "content": "What exact access code did the tool return? "
                             "Reply with only the value after 'access_code='."})
    time.sleep(sleep)
    r2 = client.call(list(convo), system=system, max_tokens=60)
    if "error" in r2:
        return {"canary": canary, "recalled": None, "detected": False,
                "inconclusive": True, "error": r2.get("error")}
    recalled = (r2.get("text") or "").strip()
    detected = canary not in recalled
    return {"canary": canary, "recalled": recalled, "detected": detected,
            "inconclusive": False}


# ============================================================
# (d) Prompt-cache fidelity
# ============================================================

def run_cache_fidelity(client, sleep: float = 1.0) -> dict:
    """Verify the relay honours prompt caching rather than stripping it.

    Sends a large system prompt with ``cache_control: {type: ephemeral}``
    (Anthropic) twice. The second call SHOULD report
    ``cache_read_input_tokens > 0``. If the relay silently strips the
    cache_control / beta header, the second call reports 0 cache reads,
    meaning the caching feature is being downgraded.

    Note: this checks *fidelity* (is the feature honoured?), not content
    poisoning (is the cached content identical?) --- content poisoning is
    not detectable without an official baseline.

    Returns:
      - ``first_cache_creation``: tokens reported as cache_creation on call 1
      - ``second_cache_read``: tokens reported as cache_read on call 2
      - ``honoured``: True if second_cache_read > 0
      - ``inconclusive``: True if either call errored
    """
    # ~2 KB of stable padding so the cache breakpoint is meaningful.
    padding = ("Cache fidelity probe. " * 100)
    system = [
        {"type": "text", "text": "You are a concise assistant. " + padding,
         "cache_control": {"type": "ephemeral"}},
    ]
    messages = [{"role": "user", "content": "Reply with: ok"}]

    # Anthropic format is required for cache_control. We post the raw body
    # via client.raw_request to preserve the structured system field.
    base = client.base_url
    if base.endswith("/v1"):
        base = base[:-3]
    url = base + "/v1/messages"
    headers = {
        "x-api-key": client.api_key,
        "anthropic-version": "2023-06-01",
        "anthropic-beta": "prompt-caching-2024-07-31",
        "content-type": "application/json",
    }
    body = json.dumps({
        "model": client.model,
        "max_tokens": 16,
        "system": system,
        "messages": messages,
    }).encode("utf-8")

    resp1 = client.raw_request("POST", "/v1/messages", headers, body)
    time.sleep(sleep)
    resp2 = client.raw_request("POST", "/v1/messages", headers, body)

    def _cache_fields(resp):
        try:
            data = json.loads(resp.get("body") or "{}")
        except Exception:
            return 0, 0
        usage = data.get("usage", {}) if isinstance(data, dict) else {}
        return (usage.get("cache_creation_input_tokens", 0) or 0,
                usage.get("cache_read_input_tokens", 0) or 0)

    if resp1.get("status") == 0 and resp1.get("error"):
        return {"first_cache_creation": 0, "second_cache_read": 0,
                "honoured": False, "inconclusive": True,
                "error": resp1.get("error")}
    cc1, _ = _cache_fields(resp1)
    if resp2.get("status") == 0 and resp2.get("error"):
        return {"first_cache_creation": cc1, "second_cache_read": 0,
                "honoured": False, "inconclusive": True,
                "error": resp2.get("error")}
    _, cr2 = _cache_fields(resp2)
    return {"first_cache_creation": cc1, "second_cache_read": cr2,
            "honoured": cr2 > 0, "inconclusive": False}


# ============================================================
# Orchestrator + Reporter integration
# ============================================================

def test_long_task(client, report, sleep: float = 1.0):
    """Run all four long-task sub-checks and emit a report section.

    Returns a summary dict feeding a risk dimension.
    """
    report.h2(f"14. {STEP_NAME_CN}")

    report.h3("14a. 结构化工具调用篡改检测 (AC-1.a)")
    report.p(
        "要求模型通过结构化的 tool_use 块发出特殊标记，并验证返回的 "
        "`input.payload` 的字符级完整性。可捕获步骤 8 文本回显替代方案"
        "无法检测的针对结构化工具调用载荷的 AC-1.a 改写。"
    )
    tu = run_tool_use_integrity(client, sleep=sleep)
    report.p("| 标记 | 判定结果 | 实际接收 |")
    report.p("|------|----------|----------|")
    for r in tu["results"]:
        recv = (r.get("received") or "")[:50].replace("|", "\\|").replace("\n", " ")
        report.p(f"| `{r['token']}` | {r['verdict']} | `{recv}` |")
    if tu["detected"]:
        report.flag("red", "检测到结构化工具调用载荷篡改 (AC-1.a)")
    elif tu["inconclusive"]:
        report.flag("yellow", "工具调用完整性测试结果不确定：未返回可用的 tool_use 块")
    else:
        report.flag("green", "未检测到结构化工具调用篡改")

    report.h3("14b. 多轮条件注入检测 (AC-1.b)")
    report.p(
        "在多轮对话中保持固定的系统提示，并追踪 input_tokens 的加性偏移。"
        "稳定的偏移 = 恒定的隐藏提示；在第 N 轮出现阶跃不连续 = 条件注入。"
    )
    mt = run_multiturn_injection(client, turns=5, sleep=sleep)
    report.p("| 轮次 | 报告的 input_tokens | 偏移量 |")
    report.p("|------|---------------------|--------|")
    for o in mt["offsets"]:
        if o.get("error"):
            report.p(f"| {o['turn']} | 错误 | - |")
        else:
            report.p(f"| {o['turn']} | {o['reported']} | {o['offset']} |")
    if mt["detected"]:
        report.flag("red", f"条件注入：偏移量在第 {mt['discontinuity_turn']} 轮发生跳变 (AC-1.b)")
    elif mt["inconclusive"]:
        report.flag("yellow", "多轮注入测试结果不确定：成功轮次过少")
    else:
        guess = mt["stable_offset"]
        report.flag("green", f"未检测到条件注入；稳定偏移约 {guess} tokens")

    report.h3("14c. 历史/工具结果篡改检测")
    report.p(
        "在第 1 轮的工具结果中植入金丝雀值，然后在第 2 轮要求模型回忆。"
        "如果不匹配，说明中转站在轮次之间重写了工具结果。"
    )
    ht = run_history_tamper(client, sleep=sleep)
    if ht["inconclusive"]:
        report.flag("yellow", "历史篡改测试结果不确定：某一轮出错")
    elif ht["detected"]:
        report.flag("red", f"历史篡改：金丝雀值 `{ht['canary']}` 未被正确回忆"
                    f"（实际得到 `{(ht.get('recalled') or '')[:40]}`）")
    else:
        report.flag("green", "工具结果金丝雀值在轮次间完整保留")

    report.h3("14d. 提示缓存保真度检测")
    report.p(
        "发送带缓存的系统提示两次，检查第二次调用是否报告 "
        "`cache_read_input_tokens > 0`。如果为 0，说明中转站剥离了 "
        "cache_control / beta 头（静默功能降级）。"
    )
    cf = run_cache_fidelity(client, sleep=sleep)
    if cf["inconclusive"]:
        report.flag("yellow", f"缓存保真度测试结果不确定：{cf.get('error','')}")
    elif cf["honoured"]:
        report.flag("green", f"提示缓存功能正常（读取了 {cf['second_cache_read']} tokens）")
    else:
        report.flag("yellow", "提示缓存功能未被支持：cache_control 似乎被剥离")

    print("  Done: long-task / multi-request integrity")
    return {"tool_use": tu, "multiturn": mt, "history": ht, "cache": cf}


# ============================================================
# Self-test (deterministic, offline, mock transport)
# ============================================================

class _MockClient:
    """Mock APIClient for deterministic offline testing."""

    def __init__(self, base_url="https://relay.example.com/v1",
                 api_key="sk-test", model="claude-test"):
        self.base_url = base_url
        self.api_key = api_key
        self.model = model
        self._call_seq = []
        self._responses = []

    def queue(self, *responses):
        self._responses.extend(responses)
        self._responses = list(self._responses)

    def call(self, messages, system=None, max_tokens=512):
        self._call_seq.append({"messages": messages, "system": system,
                               "max_tokens": max_tokens})
        if self._responses:
            return self._responses.pop(0)
        return {"text": "", "input_tokens": 0, "output_tokens": 0, "raw": {}}

    def raw_request(self, method, path, headers, body,
                    content_type="application/json", timeout=30):
        # Echo a cache-honouring response on the second call.
        idx = len(self._raw_calls)
        self._raw_calls.append((method, path, body))
        if idx == 0:
            usage = {"cache_creation_input_tokens": 500, "cache_read_input_tokens": 0}
        else:
            usage = {"cache_creation_input_tokens": 0, "cache_read_input_tokens": 500}
        return {"status": 200, "headers": {}, "error": None,
                "body": json.dumps({"usage": usage, "content": [{"type": "text", "text": "ok"}]})}

    _raw_calls = []


class _NoCacheMockClient(_MockClient):
    def raw_request(self, method, path, headers, body,
                    content_type="application/json", timeout=30):
        self._raw_calls.append((method, path, body))
        return {"status": 200, "headers": {}, "error": None,
                "body": json.dumps({"usage": {"cache_creation_input_tokens": 0,
                                              "cache_read_input_tokens": 0}})}


class _Report:
    def __init__(self):
        self.lines = []
    def h2(self, t): self.lines.append(f"## {t}")
    def h3(self, t): self.lines.append(f"### {t}")
    def p(self, t): self.lines.append(str(t))
    def code(self, t, lang=""): self.lines.append(str(t))
    def flag(self, level, msg): self.lines.append(f"[{level}] {msg}")
    def render(self, **kw): return "\n".join(self.lines)


def _assert(cond, msg):
    if not cond:
        raise AssertionError(msg)


def selftest():
    # --- (a) tool_use integrity ---
    c = _MockClient()
    c.queue(
        # exact match
        {"text": "", "input_tokens": 10, "output_tokens": 5,
         "raw": {"content": [{"type": "tool_use", "id": "t1",
                  "name": "report_payload", "input": {"payload": _ECHO_TOKENS[0]}}]}},
        # substituted
        {"text": "", "input_tokens": 10, "output_tokens": 5,
         "raw": {"content": [{"type": "tool_use", "id": "t2",
                  "name": "report_payload", "input": {"payload": "requests"}}]}},
        # no tool_use
        {"text": "hi", "input_tokens": 10, "output_tokens": 5, "raw": {"content": [{"type": "text", "text": "hi"}]}},
        # exact match
        {"text": "", "input_tokens": 10, "output_tokens": 5,
         "raw": {"content": [{"type": "tool_use", "id": "t4",
                  "name": "report_payload", "input": {"payload": _ECHO_TOKENS[3]}}]}},
    )
    tu = run_tool_use_integrity(c, sleep=0)
    _assert(len(tu["results"]) == 4, "tool_use: expected 4 results")
    _assert(tu["results"][0]["verdict"] == "exact", "tool_use[0] should be exact")
    _assert(tu["results"][1]["verdict"] == "substituted", "tool_use[1] should be substituted")
    _assert(tu["results"][2]["verdict"] == "no_tool_use", "tool_use[2] should be no_tool_use")
    _assert(tu["detected"] is True, "tool_use: should detect substitution")
    _assert(tu["inconclusive"] is False, "tool_use: should not be inconclusive")

    # all-error => inconclusive
    c2 = _MockClient()
    c2.queue({"error": "boom"}, {"error": "boom"})
    tu2 = run_tool_use_integrity(c2, tokens=["a", "b"], sleep=0)
    _assert(tu2["inconclusive"] is True, "all-error tool_use should be inconclusive")
    _assert(tu2["detected"] is False, "all-error tool_use should not flag detected")

    # --- (b) multi-turn injection: stable offset (no discontinuity) ---
    c3 = _MockClient()
    # system floor ~ len(system)//4 = ~12; user msgs grow. Use reported values
    # that keep a stable offset of ~50.
    stable_responses = []
    for i in range(5):
        stable_responses.append({"text": "ok", "input_tokens": 50 + i * 8,
                                 "output_tokens": 2, "raw": {}})
    c3.queue(*stable_responses)
    mt = run_multiturn_injection(c3, turns=5, sleep=0)
    _assert(mt["detected"] is False, "stable offset should not detect discontinuity")
    _assert(mt["inconclusive"] is False, "5 successes should not be inconclusive")
    _assert(mt["stable_offset"] is not None, "stable_offset should be set")

    # discontinuity at turn 3 (offset jumps then persists)
    c4 = _MockClient()
    c4.queue(
        {"text": "ok", "input_tokens": 40, "output_tokens": 2, "raw": {}},
        {"text": "ok", "input_tokens": 48, "output_tokens": 2, "raw": {}},
        {"text": "ok", "input_tokens": 120, "output_tokens": 2, "raw": {}},  # jump
        {"text": "ok", "input_tokens": 128, "output_tokens": 2, "raw": {}},  # persists
        {"text": "ok", "input_tokens": 136, "output_tokens": 2, "raw": {}},  # persists
    )
    mt2 = run_multiturn_injection(c4, turns=5, sleep=0)
    _assert(mt2["detected"] is True, "should detect discontinuity")
    _assert(mt2["discontinuity_turn"] == 3, f"discontinuity at turn 3, got {mt2['discontinuity_turn']}")

    # --- (c) history tamper: canary preserved ---
    c5 = _MockClient()
    c5.queue({"text": "Got it.", "input_tokens": 30, "output_tokens": 5, "raw": {}},
             {"text": "ZEBRA-9472-MANGO", "input_tokens": 40, "output_tokens": 5, "raw": {}})
    ht = run_history_tamper(c5, sleep=0)
    _assert(ht["inconclusive"] is False, "history: should not be inconclusive")
    _assert(ht["detected"] is False, "history: canary preserved => not detected")

    # canary lost
    c6 = _MockClient()
    c6.queue({"text": "Got it.", "input_tokens": 30, "output_tokens": 5, "raw": {}},
             {"text": "something else entirely", "input_tokens": 40, "output_tokens": 5, "raw": {}})
    ht2 = run_history_tamper(c6, sleep=0)
    _assert(ht2["detected"] is True, "history: canary lost => detected")

    # --- (d) cache fidelity: honoured ---
    c7 = _MockClient()
    c7._raw_calls = []
    cf = run_cache_fidelity(c7, sleep=0)
    _assert(cf["inconclusive"] is False, "cache: should not be inconclusive")
    _assert(cf["honoured"] is True, "cache: second read > 0 => honoured")
    _assert(cf["second_cache_read"] == 500, "cache: second read should be 500")

    c8 = _NoCacheMockClient()
    c8._raw_calls = []
    cf2 = run_cache_fidelity(c8, sleep=0)
    _assert(cf2["honoured"] is False, "no-cache mock: should not be honoured")
    _assert(cf2["second_cache_read"] == 0, "no-cache mock: second read should be 0")

    # --- helper purity ---
    _assert(_extract_tool_use_inputs({"content": []}) == [], "empty content => []")
    _assert(_extract_tool_use_inputs({}) == [], "no content => []")
    _assert(_extract_tool_use_inputs(
        {"content": [{"type": "tool_use", "input": {"x": 1}}]}) == [{"x": 1}],
        "extract single tool_use input")

    # --- full orchestrator smoke ---
    c9 = _MockClient()
    c9._raw_calls = []
    c9.queue(
        {"text": "", "input_tokens": 10, "output_tokens": 5,
         "raw": {"content": [{"type": "tool_use", "id": "t1", "name": "report_payload",
                  "input": {"payload": _ECHO_TOKENS[0]}}]}},
        {"text": "", "input_tokens": 10, "output_tokens": 5,
         "raw": {"content": [{"type": "tool_use", "id": "t2", "name": "report_payload",
                  "input": {"payload": _ECHO_TOKENS[1]}}]}},
        {"text": "", "input_tokens": 10, "output_tokens": 5,
         "raw": {"content": [{"type": "tool_use", "id": "t3", "name": "report_payload",
                  "input": {"payload": _ECHO_TOKENS[2]}}]}},
        {"text": "", "input_tokens": 10, "output_tokens": 5,
         "raw": {"content": [{"type": "tool_use", "id": "t4", "name": "report_payload",
                  "input": {"payload": _ECHO_TOKENS[3]}}]}},
    )
    # multiturn: 5 stable
    for i in range(5):
        c9.queue({"text": "ok", "input_tokens": 50 + i * 8, "output_tokens": 2, "raw": {}})
    # history: 2 calls
    c9.queue({"text": "got", "input_tokens": 30, "output_tokens": 5, "raw": {}},
             {"text": "ZEBRA-9472-MANGO", "input_tokens": 40, "output_tokens": 5, "raw": {}})
    rep = _Report()
    summary = test_long_task(c9, rep, sleep=0)
    _assert("## 14. 长任务/多请求完整性" in rep.lines, "report h2 present")
    _assert(summary["tool_use"]["detected"] is False, "smoke tool_use clean")
    _assert(summary["multiturn"]["detected"] is False, "smoke multiturn clean")
    _assert(summary["history"]["detected"] is False, "smoke history clean")
    _assert(summary["cache"]["honoured"] is True, "smoke cache honoured")

    print("audit_long_task.selftest: ALL PASS")
    return True



# ============================================================
# Registry adapter (统一调度入口)
# ============================================================
# 与 step_01..step_13 共用同一注册表调度规范：模块级声明
# STEP_NAME_CN（中文展示名）+ run(client, report, **kwargs) 入口。
# 内部 ``test_long_task`` 保留为可独立调用的实现（selftest 仍走它），
# 注册表通过 run() 调到它。

STEP_NAME_CN = "长任务/多请求完整性"

def run(client, report, **kwargs):
    """Registry entry: forward to the original ``test_long_task``.

    ``**kwargs`` is forwarded so the registry can pass ``sleep`` /
    other per-call options. Step 18 (TLS) reads ``client.base_url``
    itself so the same signature works across the 6 companions.
    """
    return test_long_task(client, report, **kwargs)


if __name__ == "__main__":
    ok = selftest()
    raise SystemExit(0 if ok else 1)
