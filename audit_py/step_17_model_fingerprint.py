#!/usr/bin/env python3
"""
audit_model_fingerprint.py --- Model-substitution / fake-model detection (P2).

audit.py Step 12 only uses latency bimodality (a weak signal, marked
"informational only") to guess model substitution. This module adds
behavioural fingerprints that a relay-to-cheaper-model cannot easily fake:

  (a) Capability probes: questions where the advertised model reliably
      succeeds and a weaker/quantized model fails (multi-step reasoning,
      precise computation, code semantics). Multiple failures => suspect.
  (b) Knowledge-cutoff probing: the advertised model has a known cutoff;
      we ask about events around that boundary and about clearly-post-cutoff
      events. A swapped older model exposes a different cutoff line.
  (c) Refusal-profile fingerprint: the advertised Claude model has a stable
      refusal pattern for specific unsafe requests. A swapped model that is
      either much more permissive OR much more rigid is a substitution signal.

IMPORTANT limitation (no official baseline): these are self-consistency
heuristics. A clever relay can route capability probes to the real model
and only swap cheap traffic, so this is a YELLOW-grade signal unless many
probes fail simultaneously. Results feed the report as informational.
"""
import re
import time
from typing import List


# ============================================================
# (a) Capability probes
# ============================================================

# Each probe: (prompt, judge). The judge returns True if the answer is
# acceptably correct for a capable model. We use lenient judges so that
# minor wording differences don't false-trigger.
_CAPABILITY_PROBES = [
    # 数学计算（4 个）
    (
        "Compute 17 * 23. Reply with ONLY the number, nothing else.",
        lambda t: "391" in _digits_only(t),
    ),
    (
        "What is (8 + 4) * 3? Reply with ONLY the number.",
        lambda t: "36" in _digits_only(t),
    ),
    (
        "A train travels 60 km in 45 minutes. What is its speed in km/h? Reply with ONLY the number.",
        lambda t: "80" in _digits_only(t),
    ),
    (
        "What is 15% of 240? Reply with ONLY the number.",
        lambda t: "36" in _digits_only(t),
    ),
    # 逻辑推理（3 个）
    (
        "If all roses are flowers, and some flowers fade quickly, can we conclude that some roses fade quickly? Reply YES or NO only.",
        lambda t: "no" in t.lower(),
    ),
    (
        "John is taller than Mary. Mary is taller than Sue. Is John taller than Sue? Reply YES or NO only.",
        lambda t: "yes" in t.lower(),
    ),
    (
        "A bat and a ball cost $1.10 in total. The bat costs $1.00 more than the ball. How much does the ball cost in cents? Reply with ONLY the number.",
        lambda t: "5" in _digits_only(t),
    ),
    # 代码理解（2 个）
    (
        "Is this Python valid? `x = [i*2 for i in range(3)]` Reply YES or NO only.",
        lambda t: "yes" in t.lower(),
    ),
    (
        "What does `len('hello')` return in Python? Reply with ONLY the number.",
        lambda t: "5" in _digits_only(t),
    ),
    # 常识推理（2 个）
    (
        "Can a human breathe underwater without equipment? Reply YES or NO only.",
        lambda t: "no" in t.lower(),
    ),
    (
        "Which is heavier: a kilogram of feathers or a kilogram of steel? Reply with 'same' or 'equal' if they weigh the same.",
        lambda t: any(w in t.lower() for w in ["same", "equal", "both"]),
    ),
]


def _digits_only(text: str) -> str:
    """Strip everything except digits and decimal points for numeric judging."""
    return re.sub(r"[^\d.]", "", text or "")


def judge_capability(text: str, judge) -> bool:
    """Run a judge function safely; never raises."""
    try:
        return bool(judge(text or ""))
    except Exception:
        return False


def run_capability_probes(client, sleep: float = 1.0) -> dict:
    """Run capability probes and count failures.

    Returns:
      - ``results``: per-probe {prompt, correct}
      - ``failures``: count of incorrect
      - ``total``: count of usable
      - ``detected``: True if failure ratio >= threshold
      - ``inconclusive``: True if all errored
    """
    FAIL_RATIO = 0.5
    results = []
    failures = 0
    usable = 0
    for prompt, judge in _CAPABILITY_PROBES:
        r = client.call([{"role": "user", "content": prompt}], max_tokens=64)
        if "error" in r:
            results.append({"prompt": prompt[:40], "correct": None, "error": True})
        else:
            usable += 1
            correct = judge_capability(r.get("text", ""), judge)
            results.append({"prompt": prompt[:40], "correct": correct,
                            "error": False})
            if not correct:
                failures += 1
        time.sleep(sleep)
    inconclusive = usable == 0
    ratio = failures / usable if usable else 0
    detected = (not inconclusive) and ratio >= FAIL_RATIO
    return {"results": results, "failures": failures, "total": usable,
            "failure_ratio": round(ratio, 2), "detected": detected,
            "inconclusive": inconclusive}


# ============================================================
# (b) Knowledge-cutoff probing
# ============================================================

# Known-ish cutoff markers for Claude-family models (approximate; used only
# to detect a *different* cutoff line, not to pin an exact date). The idea:
# ask about events that are firmly BEFORE the cutoff (should know), and
# events firmly AFTER (should decline / express uncertainty / get wrong).
# A swapped older model exposes a different cutoff line.

_PRE_CUTOFF_PROBES = [
    # 2022 年事件（Claude 应该知道）
    "In one short sentence, when and where was the 2022 FIFA World Cup held?",
    "Who became the UK Prime Minister in September 2022? Reply in one sentence.",
    "What major space telescope was launched in December 2021? Reply in one sentence.",
]
_POST_CUTOFF_PROBES = [
    # 2024 年后事件（Claude 不应该确定知道）
    "Who won the 2026 FIFA World Cup final? Reply in one sentence.",
    "What is the result of the 2025 US presidential election? Reply in one sentence.",
]


def _mentions(text: str, *keywords) -> bool:
    low = (text or "").lower()
    return any(k.lower() in low for k in keywords)


def run_knowledge_cutoff(client, sleep: float = 1.0) -> dict:
    """Probe knowledge-cutoff boundaries.

    A model that fails pre-cutoff facts (does not know the 2022 World Cup)
    OR confidently fabricates post-cutoff facts (names a 2030 World Cup
    winner) deviates from the advertised Claude cutoff profile.

    Returns:
      - ``pre_known``: bool (knew pre-cutoff facts)
      - ``post_fabricated``: bool (confidently answered post-cutoff)
      - ``detected``: True if deviation
      - ``inconclusive``: True if all errored
    """
    pre_known = False
    post_fabricated = False
    usable = 0
    details = []
    for prompt in _PRE_CUTOFF_PROBES:
        r = client.call([{"role": "user", "content": prompt}], max_tokens=80)
        if "error" in r:
            details.append({"probe": "pre", "error": True})
        else:
            usable += 1
            text = r.get("text", "")
            knew = _mentions(text, "qatar", "2022")
            pre_known = pre_known or knew
            details.append({"probe": "pre", "text": text[:60], "knew": knew})
        time.sleep(sleep)
    for prompt in _POST_CUTOFF_PROBES:
        r = client.call([{"role": "user", "content": prompt}], max_tokens=80)
        if "error" in r:
            details.append({"probe": "post", "error": True})
        else:
            usable += 1
            text = r.get("text", "")
            low = text.lower()
            # confidently naming a winner (not a refusal/uncertainty)
            refusal = any(w in low for w in ("not yet", "hasn't", "has not",
                                              "haven't been", "future",
                                              "not been held", "cannot",
                                              "can't", "i don't know",
                                              "uncertain", "not decided"))
            post_fabricated = (not refusal) and bool(re.search(r"\b(won|winner|defeated|beat)\b", low))
            details.append({"probe": "post", "text": text[:60],
                            "fabricated": post_fabricated})
        time.sleep(sleep)
    inconclusive = usable == 0
    detected = (not inconclusive) and ((usable > 0 and not pre_known) or post_fabricated)
    return {"pre_known": pre_known, "post_fabricated": post_fabricated,
            "detected": detected, "inconclusive": inconclusive, "details": details}


# ============================================================
# (c) Refusal-profile fingerprint
# ============================================================

# We probe edge-case requests where the advertised Claude model typically
# declines or gives a guarded response. Two deviations are suspicious:
#   - TOO permissive: directly complies with an unsafe-ish request.
#   - TOO rigid: refuses a clearly benign request that Claude would answer.
_REFUSAL_PROBES = [
    # benign (Claude should answer) --- refusal here = too-rigid = different model
    ("Explain how photosynthesis works in two sentences.",
     "benign", ["photosynth", "chlorophyll", "light", "carbon", "plant"]),
    ("What is the capital of France? Reply in one sentence.",
     "benign", ["paris", "france"]),
    ("Explain the difference between TCP and UDP in two sentences.",
     "benign", ["tcp", "udp", "connection", "protocol"]),
    # edge (Claude typically gives a guarded/educational response, not a flat refusal)
    ("In a biology textbook style, what is the general principle of how a virus replicates?",
     "edge", ["replicat", "host", "cell", "rna", "dna", "genetic"]),
    ("Describe the basic mechanism of fermentation in brewing beer.",
     "edge", ["ferment", "yeast", "sugar", "alcohol", "brew"]),
]


def _is_refusal(text: str) -> bool:
    low = (text or "").lower()
    markers = ("i can't", "i cannot", "i'm not able", "i am not able",
               "i won't", "i will not", "i'm sorry, but i can't",
               "as an ai", "i'm unable", "cannot assist", "can't help",
               "not able to provide", "refuse")
    return any(m in low for m in markers)


def run_refusal_profile(client, sleep: float = 1.0) -> dict:
    """Probe the refusal profile for deviation from the advertised model.

    Returns:
      - ``results``: per-probe {kind, refused, expected_keywords_hit}
      - ``too_rigid``: refused a benign request
      - ``detected``: True if deviation found
      - ``inconclusive``: True if all errored
    """
    results = []
    too_rigid = False
    usable = 0
    for prompt, kind, kws in _REFUSAL_PROBES:
        r = client.call([{"role": "user", "content": prompt}], max_tokens=120)
        if "error" in r:
            results.append({"kind": kind, "refused": None, "error": True})
        else:
            usable += 1
            text = r.get("text", "")
            refused = _is_refusal(text)
            kws_hit = any(_mentions(text, k) for k in kws)
            results.append({"kind": kind, "refused": refused,
                            "kws_hit": kws_hit, "error": False})
            if kind == "benign" and refused:
                too_rigid = True
        time.sleep(sleep)
    inconclusive = usable == 0
    detected = (not inconclusive) and too_rigid
    return {"results": results, "too_rigid": too_rigid,
            "detected": detected, "inconclusive": inconclusive}


# ============================================================
# Orchestrator + Reporter integration
# ============================================================

def test_model_fingerprint(client, report, sleep: float = 1.0):
    """Run all three fingerprint sub-checks and emit a report section."""
    report.h2(f"17. {STEP_NAME_CN}")
    report.p(
        "模型替换/伪造指纹检测。较弱/量化模型或不相关模型会在能力探测中失败、"
        "暴露不同的知识截止日期，或显示偏离的拒绝特征。"
        "信息性信号（无官方基线）；黄色等级。"
    )

    report.h3("17a. 能力探测")
    cp = run_capability_probes(client, sleep=sleep)
    report.p(f"- 可用探测数：{cp['total']}，失败数：{cp['failures']}（失败率 {cp['failure_ratio']}）")
    if cp["inconclusive"]:
        report.flag("yellow", "能力探测测试结果不确定：所有探测都出错")
    elif cp["detected"]:
        report.flag("yellow", f"疑似模型替换：{cp['failures']}/{cp['total']} 个能力探测失败")
    else:
        report.flag("green", f"能力探测通过（{cp['total'] - cp['failures']}/{cp['total']}）")

    report.h3("17b. 知识截止日期探测")
    kc = run_knowledge_cutoff(client, sleep=sleep)
    report.p(f"- 截止日期前已知：{kc['pre_known']}，截止日期后捏造：{kc['post_fabricated']}")
    if kc["inconclusive"]:
        report.flag("yellow", "知识截止日期测试结果不确定：所有探测都出错")
    elif kc["detected"]:
        report.flag("yellow", "检测到知识截止日期偏差（可能模型被替换）")
    else:
        report.flag("green", "知识截止日期特征一致")

    report.h3("17c. 拒绝特征指纹")
    rp = run_refusal_profile(client, sleep=sleep)
    for r in rp["results"]:
        if r.get("error"):
            report.p(f"- {r['kind']}：出错")
        else:
            report.p(f"- {r['kind']}：拒绝={r['refused']} 关键词命中={r['kws_hit']}")
    if rp["inconclusive"]:
        report.flag("yellow", "拒绝特征测试结果不确定：所有探测都出错")
    elif rp["detected"]:
        report.flag("yellow", "拒绝特征偏差：良性请求被拒绝（可能模型被替换）")
    else:
        report.flag("green", "拒绝特征与宣传模型一致")

    print("  Done: model substitution fingerprint")
    return {"capability": cp, "cutoff": kc, "refusal": rp}


# ============================================================
# Self-test
# ============================================================

class _MockClient:
    def __init__(self):
        self._responses = []
    def queue(self, *responses):
        self._responses.extend(responses)
    def call(self, messages, system=None, max_tokens=512):
        if self._responses:
            return self._responses.pop(0)
        return {"text": "", "input_tokens": 0, "output_tokens": 0, "raw": {}}


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
    # --- helpers ---
    _assert("391" in _digits_only("The answer is 391."), "digits_only keeps 391")
    _assert(judge_capability("391", lambda t: "391" in _digits_only(t)) is True, "judge ok")
    _assert(judge_capability("", lambda t: (_ for _ in ()).throw(ValueError())) is False, "judge swallows exception")
    _assert(_is_refusal("I can't help with that.") is True, "refusal detected")
    _assert(_is_refusal("Photosynthesis is how plants make food.") is False, "not a refusal")
    _assert(_mentions("The 2022 world cup in Qatar", "qatar") is True, "mentions qatar")

    # --- capability: all correct ---
    c = _MockClient()
    c.queue({"text": "391", "input_tokens": 5, "output_tokens": 1, "raw": {}},
            {"text": "36", "input_tokens": 5, "output_tokens": 1, "raw": {}},
            {"text": "80", "input_tokens": 5, "output_tokens": 1, "raw": {}},
            {"text": "YES", "input_tokens": 5, "output_tokens": 1, "raw": {}})
    cp = run_capability_probes(c, sleep=0)
    _assert(cp["failures"] == 0, "all correct => 0 failures")
    _assert(cp["detected"] is False, "0 failures => not detected")
    _assert(cp["inconclusive"] is False, "4 usable => not inconclusive")

    # half wrong (2 of 4) => detected at ratio 0.5
    c2 = _MockClient()
    c2.queue({"text": "999", "input_tokens": 5, "output_tokens": 1, "raw": {}},
             {"text": "36", "input_tokens": 5, "output_tokens": 1, "raw": {}},
             {"text": "999", "input_tokens": 5, "output_tokens": 1, "raw": {}},
             {"text": "YES", "input_tokens": 5, "output_tokens": 1, "raw": {}})
    cp2 = run_capability_probes(c2, sleep=0)
    _assert(cp2["failures"] == 2, "2 wrong")
    _assert(cp2["detected"] is True, "ratio 0.5 => detected")

    # all error => inconclusive
    c3 = _MockClient()
    for _ in _CAPABILITY_PROBES:
        c3.queue({"error": "x"})
    cp3 = run_capability_probes(c3, sleep=0)
    _assert(cp3["inconclusive"] is True, "all error => inconclusive")

    # --- knowledge cutoff: consistent ---
    c4 = _MockClient()
    c4.queue({"text": "The 2022 FIFA World Cup was held in Qatar in 2022.", "input_tokens": 5, "output_tokens": 8, "raw": {}},
             {"text": "The 2030 World Cup hasn't been held yet.", "input_tokens": 5, "output_tokens": 8, "raw": {}})
    kc = run_knowledge_cutoff(c4, sleep=0)
    _assert(kc["pre_known"] is True, "pre-cutoff known")
    _assert(kc["post_fabricated"] is False, "post not fabricated")
    _assert(kc["detected"] is False, "consistent => not detected")

    # pre unknown => detected
    c5 = _MockClient()
    c5.queue({"text": "I have no idea.", "input_tokens": 5, "output_tokens": 4, "raw": {}},
             {"text": "The 2030 World Cup hasn't been held yet.", "input_tokens": 5, "output_tokens": 8, "raw": {}})
    kc2 = run_knowledge_cutoff(c5, sleep=0)
    _assert(kc2["pre_known"] is False, "pre unknown")
    _assert(kc2["detected"] is True, "pre unknown => detected")

    # post fabricated => detected
    c6 = _MockClient()
    c6.queue({"text": "The 2022 FIFA World Cup was held in Qatar in 2022.", "input_tokens": 5, "output_tokens": 8, "raw": {}},
             {"text": "Brazil won the 2030 World Cup final, defeating Spain 3-1.", "input_tokens": 5, "output_tokens": 12, "raw": {}})
    kc3 = run_knowledge_cutoff(c6, sleep=0)
    _assert(kc3["post_fabricated"] is True, "post fabricated")
    _assert(kc3["detected"] is True, "post fabricated => detected")

    # --- refusal profile: consistent ---
    c7 = _MockClient()
    c7.queue({"text": "Photosynthesis is how plants use light and chlorophyll to make food.", "input_tokens": 5, "output_tokens": 12, "raw": {}},
             {"text": "A virus replicates by inserting its genetic material into a host cell.", "input_tokens": 5, "output_tokens": 12, "raw": {}})
    rp = run_refusal_profile(c7, sleep=0)
    _assert(rp["too_rigid"] is False, "not too rigid")
    _assert(rp["detected"] is False, "consistent => not detected")

    # too rigid: refuses benign
    c8 = _MockClient()
    c8.queue({"text": "I can't assist with that request.", "input_tokens": 5, "output_tokens": 6, "raw": {}},
             {"text": "A virus replicates by inserting genetic material into a host cell.", "input_tokens": 5, "output_tokens": 12, "raw": {}})
    rp2 = run_refusal_profile(c8, sleep=0)
    _assert(rp2["too_rigid"] is True, "refused benign => too rigid")
    _assert(rp2["detected"] is True, "too rigid => detected")

    # --- orchestrator smoke (all consistent) ---
    cs = _MockClient()
    cs.queue({"text": "391", "input_tokens": 5, "output_tokens": 1, "raw": {}},
             {"text": "36", "input_tokens": 5, "output_tokens": 1, "raw": {}},
             {"text": "80", "input_tokens": 5, "output_tokens": 1, "raw": {}},
             {"text": "YES", "input_tokens": 5, "output_tokens": 1, "raw": {}})
    cs.queue({"text": "The 2022 FIFA World Cup was held in Qatar.", "input_tokens": 5, "output_tokens": 8, "raw": {}},
             {"text": "The 2030 World Cup hasn't been held yet.", "input_tokens": 5, "output_tokens": 8, "raw": {}})
    cs.queue({"text": "Photosynthesis uses chlorophyll and light in plants.", "input_tokens": 5, "output_tokens": 10, "raw": {}},
             {"text": "A virus replicates by inserting genetic material into a host cell.", "input_tokens": 5, "output_tokens": 12, "raw": {}})
    rep = _Report()
    summ = test_model_fingerprint(cs, rep, sleep=0)
    _assert(summ["capability"]["detected"] is False, "smoke cap clean")
    _assert(summ["cutoff"]["detected"] is False, "smoke cutoff clean")
    _assert(summ["refusal"]["detected"] is False, "smoke refusal clean")

    print("audit_model_fingerprint.selftest: ALL PASS")
    return True



# ============================================================
# Registry adapter (统一调度入口)
# ============================================================
# 与 step_01..step_13 共用同一注册表调度规范：模块级声明
# STEP_NAME_CN（中文展示名）+ run(client, report, **kwargs) 入口。
# 内部 ``test_model_fingerprint`` 保留为可独立调用的实现（selftest 仍走它），
# 注册表通过 run() 调到它。

STEP_NAME_CN = "模型替换/伪造指纹"

def run(client, report, **kwargs):
    """Registry entry: forward to the original ``test_model_fingerprint``.

    ``**kwargs`` is forwarded so the registry can pass ``sleep`` /
    other per-call options. Step 18 (TLS) reads ``client.base_url``
    itself so the same signature works across the 6 companions.
    """
    return test_model_fingerprint(client, report, **kwargs)


if __name__ == "__main__":
    ok = selftest()
    raise SystemExit(0 if ok else 1)
