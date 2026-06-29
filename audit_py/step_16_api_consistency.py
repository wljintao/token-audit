#!/usr/bin/env python3
"""
audit_api_consistency.py --- API conformance / silent-downgrade audit (P1).

A relay can silently degrade the API surface in ways that break agent
workflows without raising errors: stripping the anthropic-beta header
(thinking / caching vanish), mangling a tool schema, ignoring max_tokens /
stop_reason, or splicing extra text into a stream. None of these are
caught by audit.py today.

Adds four checks:

  (a) Beta-feature honoring: request extended thinking; verify the
      response carries a ``thinking`` content block. Absent => beta header
      was stripped (silent downgrade).
  (b) Tool-schema fidelity: send a tool with a distinctive field; ask the
      model to describe it. If the relay mangled the schema the model cannot
      reproduce the distinctive field name.
  (c) max_tokens / stop_reason honoring: send max_tokens=5; verify
      output_tokens <= ~5 and stop_reason == "max_tokens". A relay that
      ignores max_tokens is a correctness/billing hazard.
  (d) Mid-stream text injection: open a stream, reassemble the deltas, and
      detect inserted canary markers that were never requested.

All checks are absolute heuristics (no official baseline).
"""
import json
import time
from typing import List


# ============================================================
# (a) Beta-feature (extended thinking) honoring
# ============================================================

def _anthropic_post_raw(client, body: dict, beta_header: str = None) -> dict:
    """POST an Anthropic-format request via raw_request, preserving the body.

    Returns the parsed JSON dict, or {"_error": ...}.
    """
    base = client.base_url
    if base.endswith("/v1"):
        base = base[:-3]
    headers = {
        "x-api-key": client.api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    if beta_header:
        headers["anthropic-beta"] = beta_header
    raw = json.dumps(body).encode("utf-8")
    resp = client.raw_request("POST", "/v1/messages", headers, raw)
    if resp.get("status") == 0 and resp.get("error"):
        return {"_error": resp.get("error")}
    try:
        return json.loads(resp.get("body") or "{}")
    except Exception as e:
        return {"_error": f"bad json: {e}"}


def has_thinking_block(data: dict) -> bool:
    """True if the Anthropic response content contains a thinking block."""
    content = data.get("content") if isinstance(data, dict) else None
    if not isinstance(content, list):
        return False
    for blk in content:
        if isinstance(blk, dict) and blk.get("type") == "thinking":
            return True
    return False


def run_beta_thinking(client, sleep: float = 1.0) -> dict:
    """Request extended thinking and verify a thinking block is returned.

    We use the OpenAI-style interleaved-thinking beta plus the native
    ``thinking`` field. If the relay strips the anthropic-beta header,
    the response will have no thinking block (and likely no error either).

    Returns:
      - ``thinking_present``: bool
      - ``detected_downgrade``: True if no thinking block AND no error
      - ``inconclusive``: True if the request errored
    """
    body = {
        "model": client.model,
        "max_tokens": 1024,
        "thinking": {"type": "enabled", "budget_tokens": 512},
        "messages": [{"role": "user", "content": "What is 17 * 23? Think carefully."}],
    }
    data = _anthropic_post_raw(
        client, body, beta_header="interleaved-thinking-2025-05-14")
    if "_error" in data:
        return {"thinking_present": False, "detected_downgrade": False,
                "inconclusive": True, "error": data["_error"]}
    present = has_thinking_block(data)
    # Also accept the OpenAI-style reasoning field as a thinking proxy.
    if not present and isinstance(data, dict):
        # some relays expose reasoning in choices[0].message.reasoning
        choices = data.get("choices")
        if isinstance(choices, list) and choices:
            msg = choices[0].get("message", {})
            if isinstance(msg, dict) and msg.get("reasoning"):
                present = True
    return {"thinking_present": present,
            "detected_downgrade": not present,
            "inconclusive": False}


# ============================================================
# (b) Tool-schema fidelity
# ============================================================

# A distinctive, unlikely-to-guess field name + value the model must echo
# back when asked to describe the tool.
_DISTINCTIVE_FIELD = "qzx_graviton_calibration"
_DISTINCTIVE_DESC = "calibrates the graviton array"

_TOOL_SCHEMA = {
    "name": "operate_instrument",
    "description": "Operate a laboratory instrument.",
    "input_schema": {
        "type": "object",
        "properties": {
            _DISTINCTIVE_FIELD: {
                "type": "string",
                "description": _DISTINCTIVE_DESC,
            },
        },
        "required": [_DISTINCTIVE_FIELD],
    },
}


def run_tool_schema_fidelity(client, sleep: float = 1.0) -> dict:
    """Verify the relay passes the tool schema through unchanged.

    Sends the tool definition and asks the model to name the required
    parameter and its description. If the relay mangled the schema (renamed
    / dropped fields), the model cannot reproduce the distinctive field name.

    Returns:
      - ``field_reproduced``: True if the distinctive field name appears
      - ``detected``: True if the field was NOT reproduced (schema mangled)
      - ``inconclusive``: True if the call errored
    """
    system = (
        "You have access to the `operate_instrument` tool. When asked, "
        "report the exact name of its required parameter and the parameter's "
        "description verbatim."
    )
    body = {
        "model": client.model,
        "max_tokens": 200,
        "system": system,
        "tools": [_TOOL_SCHEMA],
        "messages": [{"role": "user",
                      "content": f"Name the required parameter of operate_instrument "
                                 f"and quote its description exactly."}],
    }
    data = _anthropic_post_raw(client, body)
    if "_error" in data:
        return {"field_reproduced": False, "detected": False,
                "inconclusive": True, "error": data["_error"]}
    # Concatenate all text blocks
    text = ""
    content = data.get("content")
    if isinstance(content, list):
        for blk in content:
            if isinstance(blk, dict) and isinstance(blk.get("text"), str):
                text += blk["text"]
    # OpenAI-style
    if not text:
        choices = data.get("choices")
        if isinstance(choices, list) and choices:
            text = choices[0].get("message", {}).get("content", "") or ""
    reproduced = _DISTINCTIVE_FIELD in text
    return {"field_reproduced": reproduced,
            "detected": not reproduced,
            "inconclusive": False,
            "text_preview": text[:80]}


# ============================================================
# (c) max_tokens / stop_reason honoring
# ============================================================

def parse_stop_reason(data: dict) -> str:
    """Extract stop_reason from an Anthropic or OpenAI response."""
    if not isinstance(data, dict):
        return ""
    sr = data.get("stop_reason")
    if sr:
        return str(sr)
    choices = data.get("choices")
    if isinstance(choices, list) and choices:
        return str(choices[0].get("finish_reason", ""))
    return ""


def run_max_tokens_honoring(client, sleep: float = 1.0) -> dict:
    """Send max_tokens=5 and verify the relay honors it.

    Honored means: output_tokens <= ~6 (small slack) AND stop_reason ==
    "max_tokens" (Anthropic) or "length" (OpenAI). A relay that returns a
    long completion with stop_reason="end_turn" is ignoring max_tokens.

    Returns:
      - ``output_tokens``: reported
      - ``text_len``: actual returned text length
      - ``stop_reason``: reported
      - ``honored``: bool
      - ``inconclusive``: True if errored
    """
    r = client.call([{"role": "user",
                      "content": "List ten colors, one per line."}],
                    max_tokens=5)
    if "error" in r:
        return {"output_tokens": None, "text_len": None,
                "stop_reason": None, "honored": False,
                "inconclusive": True, "error": r.get("error")}
    out_tok = r.get("output_tokens", 0) or 0
    text = r.get("text", "") or ""
    sr = parse_stop_reason(r.get("raw", {}))
    max_tok_ok = out_tok <= 6
    sr_ok = sr in ("max_tokens", "length", "max_output_tokens")
    honored = max_tok_ok and sr_ok
    return {"output_tokens": out_tok, "text_len": len(text),
            "stop_reason": sr, "honored": honored,
            "inconclusive": False}


# ============================================================
# (d) Mid-stream text injection
# ============================================================

# Markers a malicious relay might splice in. We send a benign prompt and
# scan the reassembled stream for these.
_INJECTION_MARKERS = [
    "<relaying via", "powered by", "<|relay|>", "via-relay",
    "checkout my", "follow me", "discount code", "promo code",
]


def analyze_stream_text(reassembled: str) -> dict:
    """Scan reassembled stream text for injection markers.

    Returns:
      - ``markers_found``: list of markers present (lowercased match)
      - ``detected``: True if any marker found
    """
    low = (reassembled or "").lower()
    found = [m for m in _INJECTION_MARKERS if m in low]
    return {"markers_found": found, "detected": bool(found),
            "reassembled_len": len(reassembled or "")}


def _concat_text(data) -> str:
    """Concatenate text from a non-stream Anthropic/OpenAI response body.

    Fallback for relays that ignore ``stream: true`` and return JSON.
    Mirrors audit.py's ``_extract_anthropic_text`` shape.
    """
    if not isinstance(data, dict):
        return ""
    parts = []
    content = data.get("content")
    if isinstance(content, list):
        for blk in content:
            if isinstance(blk, dict) and blk.get("text"):
                parts.append(str(blk["text"]))
    if not parts:
        choices = data.get("choices")
        if isinstance(choices, list) and choices:
            msg = choices[0].get("message", {})
            if isinstance(msg, dict) and msg.get("content"):
                parts.append(str(msg["content"]))
    return "".join(parts)


def reassemble_stream_text(raw_sse: str) -> str:
    """Concatenate every ``text_delta`` payload from a raw SSE stream.

    Mirrors audit.py's SSE parsing but captures the actual ``delta.text``
    content that StreamSignals discards (it only keeps boolean flags like
    ``has_text_delta``). This is what lets us scan for spliced injection
    text on the delta path, not just the final non-stream body.

    Pure function; safe to unit-test against sample SSE strings.
    """
    if not raw_sse:
        return ""
    out = []
    for line in raw_sse.splitlines():
        line = line.strip()
        if not line.startswith("data: "):
            continue
        data = line[6:]
        if data == "[DONE]":
            continue
        try:
            ev = json.loads(data)
        except Exception:
            continue
        if not isinstance(ev, dict):
            continue
        if ev.get("type") == "content_block_delta":
            delta = ev.get("delta")
            if isinstance(delta, dict) and delta.get("type") == "text_delta":
                t = delta.get("text")
                if isinstance(t, str):
                    out.append(t)
    return "".join(out)


def run_midstream_injection(client, sleep: float = 1.0) -> dict:
    """Open a streaming request, reassemble text deltas, scan for injection.

    Captures the RAW SSE via ``client.raw_request`` (which buffers the full
    body to EOF, just like ``curl -i``) with ``stream: true``, then
    reassembles the ``text_delta`` payloads ourselves. This works against
    the real audit.py APIClient, whose ``StreamSignals`` does NOT retain
    reassembled text (only boolean flags).

    Returns:
      - ``analysis``: output of analyze_stream_text
      - ``detected``: bool
      - ``inconclusive``: True if streaming/capture failed or no text
    """
    body = {
        "model": client.model,
        "max_tokens": 200,
        "stream": True,
        "messages": [{"role": "user",
                      "content": "Say hello and describe the weather briefly."}],
    }
    headers = {
        "x-api-key": client.api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
        "accept": "text/event-stream",
    }
    raw = json.dumps(body).encode("utf-8")
    try:
        resp = client.raw_request("POST", "/v1/messages", headers, raw)
    except Exception as e:
        return {"analysis": None, "detected": False,
                "inconclusive": True, "error": f"raw_request failed: {e}"}
    if resp.get("status") == 0 and resp.get("error"):
        return {"analysis": None, "detected": False,
                "inconclusive": True, "error": resp.get("error")}
    sse = resp.get("body") or ""
    reassembled = reassemble_stream_text(sse)
    if not reassembled:
        # Fallback: some relays return a non-stream JSON body; scan it too.
        reassembled = ""
        try:
            data = json.loads(sse)
            reassembled = _concat_text(data)
        except Exception:
            pass
    if not reassembled:
        return {"analysis": None, "detected": False,
                "inconclusive": True, "error": "no stream text reassembled"}
    analysis = analyze_stream_text(reassembled)
    return {"analysis": analysis, "detected": analysis["detected"],
            "inconclusive": False, "reassembled_preview": reassembled[:60]}


# ============================================================
# Orchestrator + Reporter integration
# ============================================================

def test_api_consistency(client, report, sleep: float = 1.0):
    """Run all four conformance sub-checks and emit a report section."""
    report.h2(f"16. {STEP_NAME_CN}")

    report.h3("16a. Beta-feature honoring (extended thinking)")
    report.p(
        "Request extended thinking with the anthropic-beta header and verify "
        "a thinking block is returned. Absent => the beta header was stripped."
    )
    bt = run_beta_thinking(client, sleep=sleep)
    if bt["inconclusive"]:
        report.flag("yellow", f"beta-thinking INCONCLUSIVE: {bt.get('error','')}")
    elif bt["detected_downgrade"]:
        report.flag("yellow", "Extended thinking NOT returned: anthropic-beta header may be stripped (silent downgrade)")
    else:
        report.flag("green", "Extended thinking honored (thinking block present)")

    report.h3("16b. Tool-schema fidelity")
    report.p(
        "Send a tool with a distinctive parameter name and verify the model "
        "can reproduce it. Failure implies the relay mangled the tool schema."
    )
    ts = run_tool_schema_fidelity(client, sleep=sleep)
    if ts["inconclusive"]:
        report.flag("yellow", f"tool-schema INCONCLUSIVE: {ts.get('error','')}")
    elif ts["detected"]:
        report.flag("red", "Tool schema NOT faithfully passed through: distinctive field missing (schema mangled)")
    else:
        report.flag("green", "Tool schema passed through faithfully")

    report.h3("16c. max_tokens / stop_reason honoring")
    report.p(
        "Send max_tokens=5; verify output_tokens <= ~6 and stop_reason is "
        "max_tokens/length. A long completion with end_turn means max_tokens "
        "was ignored."
    )
    mt = run_max_tokens_honoring(client, sleep=sleep)
    if mt["inconclusive"]:
        report.flag("yellow", f"max_tokens INCONCLUSIVE: {mt.get('error','')}")
    elif mt["honored"]:
        report.flag("green", f"max_tokens honored (output={mt['output_tokens']}, stop={mt['stop_reason']})")
    else:
        report.flag("red", f"max_tokens NOT honored: output={mt['output_tokens']}, stop={mt['stop_reason']}")

    report.h3("16d. Mid-stream text injection")
    report.p(
        "Reassemble streaming deltas and scan for spliced promotional / "
        "relay-branding markers that the user never requested."
    )
    ms = run_midstream_injection(client, sleep=sleep)
    if ms["inconclusive"]:
        report.flag("yellow", f"mid-stream INCONCLUSIVE: {ms.get('error','')}")
    elif ms["detected"]:
        report.flag("red", f"Mid-stream injection markers found: {ms['analysis']['markers_found']}")
    else:
        report.flag("green", "No mid-stream injection markers detected")

    print("  Done: API conformance / silent downgrade")
    return {"beta_thinking": bt, "tool_schema": ts,
            "max_tokens": mt, "midstream": ms}


# ============================================================
# Self-test
# ============================================================

class _MockClient:
    def __init__(self, base_url="https://relay.example.com/v1",
                 api_key="sk-test", model="claude-test"):
        self.base_url = base_url
        self.api_key = api_key
        self.model = model
        self._responses = []
        self._raw_responses = []

    def queue(self, *responses):
        self._responses.extend(responses)

    def queue_raw(self, *responses):
        self._raw_responses.extend(responses)

    def call(self, messages, system=None, max_tokens=512):
        if self._responses:
            return self._responses.pop(0)
        return {"text": "", "input_tokens": 0, "output_tokens": 0, "raw": {}}

    def raw_request(self, method, path, headers, body,
                    content_type="application/json", timeout=30):
        if self._raw_responses:
            r = self._raw_responses.pop(0)
            return {"status": 200, "headers": {}, "error": None, "body": r}
        return {"status": 0, "headers": {}, "error": "no raw queued", "body": ""}


class _Report:
    def __init__(self):
        self.lines = []
    def h2(self, t): self.lines.append(f"## {t}")
    def h3(self, t): self.lines.append(f"### {t}")
    def p(self, t): self.lines.append(str(t))
    def code(self, t, lang=""): self.lines.append(str(t))
    def flag(self, level, msg): self.lines.append(f"[{level}] {msg}")
    def render(self, **kw): return "\n".join(self.lines)


def _sse(text_deltas):
    """Build a minimal raw SSE body from a list of text_delta strings."""
    import json as _json
    lines = []
    for t in text_deltas:
        ev = {"type": "content_block_delta",
              "delta": {"type": "text_delta", "text": t}}
        lines.append("data: " + _json.dumps(ev))
    lines.append("data: [DONE]")
    return "\n".join(lines)


def _assert(cond, msg):
    if not cond:
        raise AssertionError(msg)


def selftest():
    # --- has_thinking_block ---
    _assert(has_thinking_block({"content": [{"type": "thinking", "thinking": "x"}]}) is True, "thinking block present")
    _assert(has_thinking_block({"content": [{"type": "text", "text": "x"}]}) is False, "no thinking => false")
    _assert(has_thinking_block({}) is False, "empty => false")
    _assert(has_thinking_block(None) is False, "None => false")

    # --- parse_stop_reason ---
    _assert(parse_stop_reason({"stop_reason": "max_tokens"}) == "max_tokens", "anthropic stop_reason")
    _assert(parse_stop_reason({"choices": [{"finish_reason": "length"}]}) == "length", "openai finish_reason")
    _assert(parse_stop_reason({}) == "", "no stop_reason => empty")

    # --- analyze_stream_text ---
    clean = analyze_stream_text("The weather is sunny and warm today.")
    _assert(clean["detected"] is False, "clean text => not detected")
    bad = analyze_stream_text("Hello! powered by cheap-relay checkout my site")
    _assert(bad["detected"] is True, "markers => detected")
    _assert("powered by" in bad["markers_found"], "found 'powered by'")
    _assert(analyze_stream_text("")["detected"] is False, "empty => not detected")

    # --- run_beta_thinking: honored ---
    c = _MockClient()
    c.queue_raw(json.dumps({"content": [{"type": "thinking", "thinking": "hmm"},
                                        {"type": "text", "text": "391"}]}))
    bt = run_beta_thinking(c, sleep=0)
    _assert(bt["thinking_present"] is True, "thinking block => present")
    _assert(bt["detected_downgrade"] is False, "present => no downgrade")

    # stripped: no thinking block
    c2 = _MockClient()
    c2.queue_raw(json.dumps({"content": [{"type": "text", "text": "391"}]}))
    bt2 = run_beta_thinking(c2, sleep=0)
    _assert(bt2["detected_downgrade"] is True, "no thinking => downgrade detected")

    # error => inconclusive
    c3 = _MockClient()  # no raw queued => error
    bt3 = run_beta_thinking(c3, sleep=0)
    _assert(bt3["inconclusive"] is True, "raw error => inconclusive")

    # --- run_tool_schema_fidelity: reproduced ---
    c4 = _MockClient()
    c4.queue_raw(json.dumps({"content": [{"type": "text",
        "text": f"The required parameter is `{_DISTINCTIVE_FIELD}` which {_DISTINCTIVE_DESC}."}]}))
    ts = run_tool_schema_fidelity(c4, sleep=0)
    _assert(ts["field_reproduced"] is True, "distinctive field reproduced")
    _assert(ts["detected"] is False, "reproduced => not detected")

    # mangled
    c5 = _MockClient()
    c5.queue_raw(json.dumps({"content": [{"type": "text", "text": "The parameter is name."}]}))
    ts2 = run_tool_schema_fidelity(c5, sleep=0)
    _assert(ts2["detected"] is True, "field missing => detected")

    # --- run_max_tokens_honoring: honored ---
    c6 = _MockClient()
    c6.queue({"text": "re", "input_tokens": 10, "output_tokens": 2,
              "raw": {"stop_reason": "max_tokens"}})
    mt = run_max_tokens_honoring(c6, sleep=0)
    _assert(mt["honored"] is True, "output<=6 + max_tokens => honored")

    # not honored: long output, end_turn
    c7 = _MockClient()
    c7.queue({"text": "red orange yellow green blue indigo violet pink black white",
              "input_tokens": 10, "output_tokens": 40,
              "raw": {"stop_reason": "end_turn"}})
    mt2 = run_max_tokens_honoring(c7, sleep=0)
    _assert(mt2["honored"] is False, "output 40 + end_turn => not honored")

    # error => inconclusive
    c8 = _MockClient()
    c8.queue({"error": "boom"})
    mt3 = run_max_tokens_honoring(c8, sleep=0)
    _assert(mt3["inconclusive"] is True, "error => inconclusive")

    # --- reassemble_stream_text (pure) ---
    sse_clean = _sse(["Hello! ", "The weather is ", "sunny today."])
    _assert(reassemble_stream_text(sse_clean) == "Hello! The weather is sunny today.", "reassemble clean")
    sse_inj = _sse(["Hello! ", "powered by super-relay. ", "The weather is nice."])
    _assert("powered by" in reassemble_stream_text(sse_inj), "reassemble captures injection")
    _assert(reassemble_stream_text("") == "", "empty sse => empty text")
    _assert(reassemble_stream_text("data: [DONE]") == "", "only done => empty")
    _assert(reassemble_stream_text("not an sse line") == "", "non-sse => empty")

    # --- _concat_text (pure fallback) ---
    _assert(_concat_text({"content": [{"type": "text", "text": "hi "}, {"text": "there"}]}) == "hi there", "anthropic concat")
    _assert(_concat_text({"choices": [{"message": {"content": "ok"}}]}) == "ok", "openai concat")
    _assert(_concat_text({}) == "", "empty concat")
    _assert(_concat_text(None) == "", "None concat")

    # --- run_midstream_injection: clean (raw SSE via raw_request) ---
    c9 = _MockClient()
    c9.queue_raw(_sse(["Hello! ", "The weather is ", "sunny today."]))
    ms = run_midstream_injection(c9, sleep=0)
    _assert(ms["inconclusive"] is False, "stream available => not inconclusive")
    _assert(ms["detected"] is False, "clean stream => not detected")

    # injected
    c10 = _MockClient()
    c10.queue_raw(_sse(["Hello! ", "powered by super-relay. ", "The weather is nice."]))
    ms2 = run_midstream_injection(c10, sleep=0)
    _assert(ms2["detected"] is True, "marker in stream => detected")

    # empty stream (no text deltas) => inconclusive
    c12 = _MockClient()
    c12.queue_raw(_sse([]))
    ms4 = run_midstream_injection(c12, sleep=0)
    _assert(ms4["inconclusive"] is True, "empty stream => inconclusive")

    # raw_request error => inconclusive
    c13 = _MockClient()  # nothing queued => returns status 0
    ms5 = run_midstream_injection(c13, sleep=0)
    _assert(ms5["inconclusive"] is True, "raw error => inconclusive")

    # --- orchestrator smoke (all honored) ---
    cs = _MockClient()
    cs.queue_raw(json.dumps({"content": [{"type": "thinking", "thinking": "h"},
                                        {"type": "text", "text": "391"}]}))
    cs.queue_raw(json.dumps({"content": [{"type": "text",
        "text": f"param is {_DISTINCTIVE_FIELD}"}]}))
    cs.queue({"text": "re", "input_tokens": 10, "output_tokens": 2,
              "raw": {"stop_reason": "max_tokens"}})
    cs.queue_raw(_sse(["Hello! ", "Sunny weather today."]))
    rep = _Report()
    summ = test_api_consistency(cs, rep, sleep=0)
    _assert(summ["beta_thinking"]["detected_downgrade"] is False, "smoke beta clean")
    _assert(summ["tool_schema"]["detected"] is False, "smoke tool clean")
    _assert(summ["max_tokens"]["honored"] is True, "smoke max_tokens honored")
    _assert(summ["midstream"]["detected"] is False, "smoke midstream clean")

    print("audit_api_consistency.selftest: ALL PASS")
    return True



# ============================================================
# Registry adapter (统一调度入口)
# ============================================================
# 与 step_01..step_13 共用同一注册表调度规范：模块级声明
# STEP_NAME_CN（中文展示名）+ run(client, report, **kwargs) 入口。
# 内部 ``test_api_consistency`` 保留为可独立调用的实现（selftest 仍走它），
# 注册表通过 run() 调到它。

STEP_NAME_CN = "API 一致性/静默降级"

def run(client, report, **kwargs):
    """Registry entry: forward to the original ``test_api_consistency``.

    ``**kwargs`` is forwarded so the registry can pass ``sleep`` /
    other per-call options. Step 18 (TLS) reads ``client.base_url``
    itself so the same signature works across the 6 companions.
    """
    return test_api_consistency(client, report, **kwargs)


if __name__ == "__main__":
    ok = selftest()
    raise SystemExit(0 if ok else 1)
