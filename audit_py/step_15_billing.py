#!/usr/bin/env python3
"""
audit_billing.py --- Billing / usage-integrity audit dimension (P1).

audit.py Step 3 only validates the INPUT side (hidden injection via
input_tokens delta). The OUTPUT side --- the relay inflating output_tokens
or double-counting cached tokens --- is never checked, yet it is the most
direct fraud surface of a relay (you pay for tokens you never received).

This module adds:

  (a) output_tokens inflation: cross-check the reported output_tokens
      against a length-based floor derived from the actual returned text.
      A relay claiming 500 output tokens for a 12-character reply is
      inflating the bill.
  (b) double-counting of cached input: Anthropic bills cache reads at a
      discount and reports cache_read_input_tokens SEPARATELY from
      input_tokens. A relay that reports BOTH a full input_tokens AND a
      non-zero cache_read_input_tokens for the same content is double
      billing.
  (c) input_tokens vs sent-payload floor: flag when reported input_tokens
      is implausibly small relative to the bytes we actually sent (a relay
      may under-report to look cheap while charging the real figure, or
      the meter is simply broken).

No official baseline: all checks are absolute, internal-consistency
heuristics with conservative thresholds to limit false positives.
"""
import json
import time
from typing import Optional


# ============================================================
# Token estimation helpers (pure functions, easily unit-tested)
# ============================================================

def estimate_output_tokens_floor(text: str) -> int:
    """Lower-bound estimate of output tokens for ``text``.

    Empirical floors (deliberately conservative so a false-positive on
    inflation is unlikely):
      - ASCII / Latin: ~4 chars/token  =>  floor = len/5
      - CJK: ~1.5 chars/token          =>  floor = cjk_count*1
    The floor is the MAX of the per-script estimates so multilingual text
    is never under-counted.

    Returns 0 only for empty text.
    """
    if not text:
        return 0
    total = len(text)
    cjk = sum(1 for ch in text if '\u4e00' <= ch <= '\u9fff' or
              '\u3040' <= ch <= '\u30ff' or '\uac00' <= ch <= '\ud7af')
    latin_floor = max(0, total // 5)
    cjk_floor = cjk  # ~1 token per CJK char is a safe floor
    return max(1, latin_floor, cjk_floor)


def estimate_input_tokens_floor(messages, system=None) -> int:
    """Lower-bound estimate of input tokens for the request payload.

    Counts every character of every message content + system prompt with
    a conservative ~5 chars/token floor. Used only to flag implausibly
    small reported input_tokens.
    """
    total = 0
    if system:
        if isinstance(system, str):
            total += len(system)
        elif isinstance(system, list):
            for blk in system:
                if isinstance(blk, dict):
                    total += len(str(blk.get("text", "")))
    if isinstance(messages, list):
        for m in messages:
            if not isinstance(m, dict):
                continue
            content = m.get("content", "")
            if isinstance(content, str):
                total += len(content)
            elif isinstance(content, list):
                for blk in content:
                    if isinstance(blk, dict):
                        total += len(str(blk.get("text", blk.get("content", ""))))
                    else:
                        total += len(str(blk))
    return max(1, total // 5)


# ============================================================
# (a) output_tokens inflation
# ============================================================

_INFLATION_RATIO = 3.0  # reported must be > 3x the floor to flag inflation
_MIN_REPORTED_TO_FLAG = 50  # ignore tiny absolute differences


def run_output_inflation(client, sleep: float = 1.0) -> dict:
    """Probe for output_tokens inflation.

    Sends prompts designed to produce a known, short, ASCII-only reply and
    compares the relay's reported output_tokens against a conservative
    floor. Flags when reported > INFLATION_RATIO * floor AND the absolute
    gap exceeds _MIN_REPORTED_TO_FLAG (to avoid noise on tiny replies).

    Returns:
      - ``results``: per-probe {reported, floor, ratio, inflated}
      - ``detected``: True if any probe flagged inflation
      - ``inconclusive``: True if every probe errored
    """
    probes = [
        ("Reply with exactly: ok", "ok"),
        ("Reply with exactly: hello world", "hello world"),
        ("Reply with exactly: 42", "42"),
    ]
    results = []
    detected = False
    usable = 0
    for prompt, _expected in probes:
        r = client.call([{"role": "user", "content": prompt}],
                        max_tokens=50)
        if "error" in r:
            results.append({"reported": None, "floor": None,
                            "ratio": None, "inflated": False, "error": True})
        else:
            usable += 1
            reported = r.get("output_tokens", 0) or 0
            text = r.get("text", "") or ""
            floor = estimate_output_tokens_floor(text)
            ratio = reported / floor if floor > 0 else 0
            inflated = (ratio > _INFLATION_RATIO and
                        (reported - floor) > _MIN_REPORTED_TO_FLAG)
            if inflated:
                detected = True
            results.append({"reported": reported, "floor": floor,
                            "ratio": round(ratio, 2), "inflated": inflated,
                            "error": False, "text_preview": text[:30]})
        time.sleep(sleep)
    inconclusive = usable == 0
    return {"results": results, "detected": detected, "inconclusive": inconclusive}


# ============================================================
# (b) cached-input double counting
# ============================================================

def classify_cache_billing(usage: dict) -> dict:
    """Classify a usage dict for cache double-counting.

    Anthropic's honest model: ``input_tokens`` counts the NON-cached input;
    ``cache_read_input_tokens`` counts cached input at a discount. They are
    additive parts of the same prompt, NOT overlapping.

    A relay double-bills when it reports ``input_tokens`` that already
    includes the full prompt AND a separate ``cache_read_input_tokens`` for
    the same content. We cannot see the raw bytes, so we use a heuristic:
    if cache_read_input_tokens > 0 AND input_tokens >= cache_read_input_tokens,
    the input_tokens is suspiciously large for a cache-hit request (the
    non-cached portion should typically be far smaller than the cached
    portion on a repeat). This is a YELLOW (suspicious) signal, not red.

    Returns:
      - ``cache_read``: reported cache_read_input_tokens
      - ``cache_creation``: reported cache_creation_input_tokens
      - ``input_tokens``: reported input_tokens
      - ``double_count_suspect``: bool
      - ``reason``: human-readable
    """
    if not isinstance(usage, dict):
        return {"cache_read": 0, "cache_creation": 0, "input_tokens": 0,
                "double_count_suspect": False, "reason": "no usage"}
    cr = usage.get("cache_read_input_tokens", 0) or 0
    cc = usage.get("cache_creation_input_tokens", 0) or 0
    it = usage.get("input_tokens", 0) or 0
    suspect = False
    reason = "no cache read"
    if cr > 0:
        if it >= cr:
            suspect = True
            reason = (f"input_tokens({it}) >= cache_read({cr}) on a cache "
                      f"hit: cached content appears billed at full price too")
        else:
            reason = (f"cache hit looks honest: input_tokens({it}) < "
                      f"cache_read({cr})")
    return {"cache_read": cr, "cache_creation": cc, "input_tokens": it,
            "double_count_suspect": suspect, "reason": reason}


def run_cache_double_count(client, sleep: float = 1.0) -> dict:
    """Send a cached prompt twice and classify the second call's billing.

    Returns:
      - ``second_usage``: the usage dict of the second call
      - ``classification``: output of classify_cache_billing
      - ``detected``: True if double_count_suspect
      - ``inconclusive``: True if either call errored or no cache fields
    """
    base = client.base_url
    if base.endswith("/v1"):
        base = base[:-3]
    headers = {
        "x-api-key": client.api_key,
        "anthropic-version": "2023-06-01",
        "anthropic-beta": "prompt-caching-2024-07-31",
        "content-type": "application/json",
    }
    padding = "Cache billing probe. " * 80
    system = [{"type": "text", "text": "Concise assistant. " + padding,
               "cache_control": {"type": "ephemeral"}}]
    body = json.dumps({"model": client.model, "max_tokens": 16,
                       "system": system,
                       "messages": [{"role": "user", "content": "Reply: ok"}]
                       }).encode("utf-8")
    r1 = client.raw_request("POST", "/v1/messages", headers, body)
    time.sleep(sleep)
    r2 = client.raw_request("POST", "/v1/messages", headers, body)

    if r1.get("status") == 0 and r1.get("error"):
        return {"second_usage": None, "classification": None,
                "detected": False, "inconclusive": True, "error": r1.get("error")}
    if r2.get("status") == 0 and r2.get("error"):
        return {"second_usage": None, "classification": None,
                "detected": False, "inconclusive": True, "error": r2.get("error")}
    try:
        data = json.loads(r2.get("body") or "{}")
    except Exception:
        return {"second_usage": None, "classification": None,
                "detected": False, "inconclusive": True, "error": "bad json"}
    usage = data.get("usage", {}) if isinstance(data, dict) else {}
    cls = classify_cache_billing(usage)
    has_cache_fields = (cls["cache_read"] > 0 or cls["cache_creation"] > 0)
    return {"second_usage": usage, "classification": cls,
            "detected": cls["double_count_suspect"],
            "inconclusive": not has_cache_fields}


# ============================================================
# (c) input_tokens vs sent payload floor
# ============================================================

_INPUT_UNDERREPORT_RATIO = 0.2  # reported < 20% of floor => implausibly low


def run_input_underreport(client, sleep: float = 1.0) -> dict:
    """Flag implausibly small reported input_tokens vs the bytes sent.

    A relay that under-reports input_tokens (to look cheap) while charging
    the real amount exposes a broken/honest meter. We send a long, known
    prompt and require reported input_tokens >= INPUT_UNDERREPORT_RATIO *
    floor. Note this is a weak sanity signal; a relay can match the floor
    and still misbill, so this never escalates above yellow.

    Returns:
      - ``results``: per-probe {floor, reported, ratio, underreported}
      - ``detected``: True if any probe underreported
      - ``inconclusive``: True if every probe errored
    """
    long_text = ("The quick brown fox jumps over the lazy dog. " * 30)
    probes = [
        [{"role": "user", "content": long_text + "\nReply: ok"}],
    ]
    results = []
    detected = False
    usable = 0
    for msgs in probes:
        r = client.call(msgs, max_tokens=16)
        if "error" in r:
            results.append({"floor": None, "reported": None,
                            "ratio": None, "underreported": False, "error": True})
        else:
            usable += 1
            floor = estimate_input_tokens_floor(msgs)
            reported = r.get("input_tokens", 0) or 0
            ratio = reported / floor if floor > 0 else 0
            under = ratio < _INPUT_UNDERREPORT_RATIO
            if under:
                detected = True
            results.append({"floor": floor, "reported": reported,
                            "ratio": round(ratio, 2), "underreported": under,
                            "error": False})
        time.sleep(sleep)
    inconclusive = usable == 0
    return {"results": results, "detected": detected, "inconclusive": inconclusive}


# ============================================================
# Orchestrator + Reporter integration
# ============================================================

def test_billing(client, report, sleep: float = 1.0):
    """Run all billing sub-checks and emit a report section."""
    report.h2(f"15. {STEP_NAME_CN}")

    report.h3("15a. output_tokens inflation")
    report.p(
        "Send prompts that yield short ASCII replies and compare reported "
        "output_tokens against a length-based floor. Reported > 3x floor "
        "with a >50 token absolute gap flags inflation."
    )
    oi = run_output_inflation(client, sleep=sleep)
    report.p("| Reported | Floor | Ratio | Inflated? |")
    report.p("|----------|-------|-------|-----------|")
    for r in oi["results"]:
        if r.get("error"):
            report.p("| ERROR | - | - | - |")
        else:
            report.p(f"| {r['reported']} | {r['floor']} | {r['ratio']} | "
                      f"{'YES' if r['inflated'] else 'no'} |")
    if oi["detected"]:
        report.flag("red", "output_tokens inflation detected: relay reports far more tokens than the text justifies")
    elif oi["inconclusive"]:
        report.flag("yellow", "output inflation INCONCLUSIVE: all probes errored")
    else:
        report.flag("green", "output_tokens consistent with returned text length")

    report.h3("15b. Cached-input double counting")
    report.p(
        "Send a cached prompt twice and inspect the second call's usage. "
        "If input_tokens >= cache_read_input_tokens on a cache hit, the "
        "cached content is likely billed at full price too (double billing)."
    )
    cd = run_cache_double_count(client, sleep=sleep)
    if cd["inconclusive"]:
        report.flag("yellow", f"cache double-count INCONCLUSIVE: {cd.get('error','no cache fields')}")
    elif cd["detected"]:
        report.flag("yellow", f"Cached-input double billing suspected: {cd['classification']['reason']}")
    else:
        report.flag("green", "Cache billing looks honest")

    report.h3("15c. input_tokens under-report sanity")
    report.p(
        "Send a long prompt and verify reported input_tokens is at least "
        "20% of a length-based floor. Implausibly small values indicate a "
        "broken or deceptive meter (weak signal)."
    )
    iu = run_input_underreport(client, sleep=sleep)
    for r in iu["results"]:
        if r.get("error"):
            report.p("- probe errored")
        else:
            report.p(f"- floor={r['floor']} reported={r['reported']} ratio={r['ratio']}")
    if iu["detected"]:
        report.flag("yellow", "input_tokens implausibly small vs payload (broken/deceptive meter)")
    elif iu["inconclusive"]:
        report.flag("yellow", "input under-report INCONCLUSIVE: probe errored")
    else:
        report.flag("green", "input_tokens within plausible range")

    print("  Done: billing / usage integrity")
    return {"output_inflation": oi, "cache_double_count": cd,
            "input_underreport": iu}


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
        self._raw_calls = []

    def queue(self, *responses):
        self._responses.extend(responses)

    def call(self, messages, system=None, max_tokens=512):
        if self._responses:
            return self._responses.pop(0)
        return {"text": "", "input_tokens": 0, "output_tokens": 0, "raw": {}}

    def raw_request(self, method, path, headers, body,
                    content_type="application/json", timeout=30):
        idx = len(self._raw_calls)
        self._raw_calls.append(idx)
        if idx == 0:
            usage = {"input_tokens": 30, "cache_creation_input_tokens": 400,
                     "cache_read_input_tokens": 0}
        else:
            usage = {"input_tokens": 30, "cache_creation_input_tokens": 0,
                     "cache_read_input_tokens": 400}
        return {"status": 200, "headers": {}, "error": None,
                "body": json.dumps({"usage": usage,
                    "content": [{"type": "text", "text": "ok"}]})}


class _InflateMockClient(_MockClient):
    def call(self, messages, system=None, max_tokens=512):
        return {"text": "ok", "input_tokens": 20, "output_tokens": 600, "raw": {}}


class _DoubleCountMockClient(_MockClient):
    def raw_request(self, method, path, headers, body,
                    content_type="application/json", timeout=30):
        idx = len(self._raw_calls)
        self._raw_calls.append(idx)
        # input_tokens (500) >= cache_read (400) on a cache hit => suspect
        usage = {"input_tokens": 500, "cache_creation_input_tokens": 0,
                 "cache_read_input_tokens": 400}
        return {"status": 200, "headers": {}, "error": None,
                "body": json.dumps({"usage": usage})}


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
    # --- estimate_output_tokens_floor ---
    _assert(estimate_output_tokens_floor("") == 0, "empty => 0")
    _assert(estimate_output_tokens_floor("ok") >= 1, "ok >= 1")
    _assert(estimate_output_tokens_floor("hello world") >= 2, "hello world >= 2")
    _assert(estimate_output_tokens_floor("你好世界") >= 4, "4 cjk >= 4")
    # ascii 100 chars => floor 20
    _assert(estimate_output_tokens_floor("a" * 100) == 20, "100 ascii => 20 floor")

    # --- estimate_input_tokens_floor ---
    _assert(estimate_input_tokens_floor(None) >= 1, "none => >=1")
    _assert(estimate_input_tokens_floor(
        [{"role": "user", "content": "a" * 50}]) >= 10, "50 chars => 10 floor")
    _assert(estimate_input_tokens_floor(
        [{"role": "user", "content": "a" * 50}], system="b" * 50) >= 20,
        "with system 100 chars => 20 floor")

    # --- classify_cache_billing ---
    honest = classify_cache_billing({"input_tokens": 10,
                                     "cache_read_input_tokens": 400})
    _assert(honest["double_count_suspect"] is False, "honest cache not suspect")
    cheat = classify_cache_billing({"input_tokens": 500,
                                    "cache_read_input_tokens": 400})
    _assert(cheat["double_count_suspect"] is True, "input>=cacheread => suspect")
    nocache = classify_cache_billing({"input_tokens": 100})
    _assert(nocache["double_count_suspect"] is False, "no cache read => not suspect")
    _assert(classify_cache_billing(None)["reason"] == "no usage", "None usage")

    # --- run_output_inflation: honest ---
    c = _MockClient()
    c.queue({"text": "ok", "input_tokens": 20, "output_tokens": 2, "raw": {}},
            {"text": "hello world", "input_tokens": 20, "output_tokens": 3, "raw": {}},
            {"text": "42", "input_tokens": 20, "output_tokens": 1, "raw": {}})
    oi = run_output_inflation(c, sleep=0)
    _assert(oi["detected"] is False, "honest output => not detected")
    _assert(oi["inconclusive"] is False, "3 usable => not inconclusive")

    # inflated
    ci = _InflateMockClient()
    oi2 = run_output_inflation(ci, sleep=0)
    _assert(oi2["detected"] is True, "output_tokens 600 for 'ok' => inflated")
    _assert(all(r["inflated"] for r in oi2["results"]), "all probes inflated")

    # all error => inconclusive
    ce = _MockClient()
    ce.queue({"error": "x"}, {"error": "x"}, {"error": "x"})
    oi3 = run_output_inflation(ce, sleep=0)
    _assert(oi3["inconclusive"] is True, "all error => inconclusive")

    # --- run_cache_double_count: honest ---
    ch = _MockClient()
    cd = run_cache_double_count(ch, sleep=0)
    _assert(cd["inconclusive"] is False, "honest cache not inconclusive")
    _assert(cd["detected"] is False, "honest cache not detected")
    _assert(cd["classification"]["cache_read"] == 400, "cache_read 400")

    # double count
    cc2 = _DoubleCountMockClient()
    cd2 = run_cache_double_count(cc2, sleep=0)
    _assert(cd2["detected"] is True, "input>=cacheread => double count detected")

    # --- run_input_underreport: honest ---
    cu = _MockClient()
    cu.queue({"text": "ok", "input_tokens": 80, "output_tokens": 1, "raw": {}})
    iu = run_input_underreport(cu, sleep=0)
    _assert(iu["detected"] is False, "honest input => not detected")
    # underreport
    cu2 = _MockClient()
    cu2.queue({"text": "ok", "input_tokens": 1, "output_tokens": 1, "raw": {}})
    iu2 = run_input_underreport(cu2, sleep=0)
    _assert(iu2["detected"] is True, "input 1 vs floor ~150 => underreported")

    # --- orchestrator smoke (all honest) ---
    cs = _MockClient()
    cs.queue({"text": "ok", "input_tokens": 20, "output_tokens": 2, "raw": {}},
             {"text": "hello world", "input_tokens": 20, "output_tokens": 3, "raw": {}},
             {"text": "42", "input_tokens": 20, "output_tokens": 1, "raw": {}},
             {"text": "ok", "input_tokens": 80, "output_tokens": 1, "raw": {}})
    rep = _Report()
    summ = test_billing(cs, rep, sleep=0)
    _assert(summ["output_inflation"]["detected"] is False, "smoke output clean")
    _assert(summ["cache_double_count"]["detected"] is False, "smoke cache clean")
    _assert(summ["input_underreport"]["detected"] is False, "smoke input clean")

    print("audit_billing.selftest: ALL PASS")
    return True



# ============================================================
# Registry adapter (统一调度入口)
# ============================================================
# 与 step_01..step_13 共用同一注册表调度规范：模块级声明
# STEP_NAME_CN（中文展示名）+ run(client, report, **kwargs) 入口。
# 内部 ``test_billing`` 保留为可独立调用的实现（selftest 仍走它），
# 注册表通过 run() 调到它。

STEP_NAME_CN = "计费/用量完整性"

def run(client, report, **kwargs):
    """Registry entry: forward to the original ``test_billing``.

    ``**kwargs`` is forwarded so the registry can pass ``sleep`` /
    other per-call options. Step 18 (TLS) reads ``client.base_url``
    itself so the same signature works across the 6 companions.
    """
    return test_billing(client, report, **kwargs)


if __name__ == "__main__":
    ok = selftest()
    raise SystemExit(0 if ok else 1)
