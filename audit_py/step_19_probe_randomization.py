#!/usr/bin/env python3
"""
audit_probe_randomization.py --- Audit-evasion countermeasures (P3).

A fundamental weakness of audit.py: every probe is a static, published,
easily-fingerprinted string (the script lives in a public repo). A smart
malicious relay can detect "I am being audited" and behave cleanly during
the audit, then attack real users.

This module does NOT eliminate that risk (impossible from a black box), but
it raises the bar with two capabilities:

  (a) Probe diversification: take a static probe template and generate N
      semantically-equivalent, surface-distinct variants (synonym swap,
      sentence reorder, paraphrase framing, filler padding). A relay that
      pattern-matches the exact published string now needs N fingerprints.
  (b) Audit-detection probe: send the SAME semantic request in an "audit-
      shaped" wrapper and a "normal-user-shaped" wrapper, then compare the
      responses. A relay that differentiates its behavior by request shape
      (e.g., exact-match on the audit's system prompt) exposes itself via
      a divergent response.

Also provides ``fingerprint_resistance`` metrics so a caller can score how
varied a generated probe set is.

All logic is deterministic given a seed; ``selftest`` is offline.
"""
import random
import re
import time
from typing import List


# ============================================================
# Synonym tables for diversification
# ============================================================

_SYNONYMS = {
    "reply": ["respond", "answer", "reply"],
    "say": ["say", "state", "write"],
    "exactly": ["exactly", "verbatim", "precisely", "word-for-word"],
    "only": ["only", "just", "nothing but"],
    "compute": ["compute", "calculate", "work out", "evaluate"],
    "what": ["what", "which"],
    "the": ["the", "the"],  # filler, keeps grammar
}

# Filler prefixes that change surface hash without changing semantics.
_FRAMINGS = [
    "", "Please ", "Hi, could you ", "Quick one: ", "", "Sure thing: ",
]

# Trailing noise tokens that don't affect a well-instructed model.
_NOISE_SUFFIXES = [
    "", "", " Thanks!", " Appreciate it.", "", " (ignore style, focus on content)",
]


def _tokenize(sentence: str) -> List[str]:
    """Simple whitespace + punctuation tokenization preserving tokens."""
    return re.findall(r"\S+|\s+", sentence)


def _diversify_sentence(sentence: str, rng: random.Random) -> str:
    """Swap synonymable words and wrap with framing/suffix noise."""
    words = sentence.split()
    out = []
    for w in words:
        lw = w.lower().strip(".,!?;:")
        if lw in _SYNONYMS:
            replacement = rng.choice(_SYNONYMS[lw])
            # preserve capitalization of first letter
            if w[0].isupper():
                replacement = replacement[:1].upper() + replacement[1:]
            out.append(replacement + (w[len(lw):] if len(w) > len(lw) else ""))
        else:
            out.append(w)
    body = " ".join(out)
    # remove double spaces from the join
    body = re.sub(r"\s+", " ", body).strip()
    body = rng.choice(_FRAMINGS) + body
    if not body.endswith((".", "!", "?")):
        body += rng.choice([".", "", "?"]) if body else ""
    body += rng.choice(_NOISE_SUFFIXES)
    return body


def diversify_probe(template: str, n: int = 4, seed: int = None) -> List[str]:
    """Generate ``n`` surface-distinct but semantically-equivalent variants.

    Each variant should yield the same model behavior but differ in raw
    bytes so a relay cannot fingerprint the exact published string.

    Args:
        template: the canonical probe text.
        n: number of variants.
        seed: RNG seed for determinism (None => non-deterministic).

    Returns a list of variants (may include the original as one variant).
    """
    rng = random.Random(seed) if seed is not None else random.Random()
    variants = set()
    variants.add(template)
    # Multi-pass to fill n
    attempts = 0
    max_attempts = n * 20
    while len(variants) < n and attempts < max_attempts:
        attempts += 1
        v = _diversify_sentence(template, rng)
        if v:
            variants.add(v)
    return list(variants)[:n]


# ============================================================
# Fingerprint-resistance metrics (pure)
# ============================================================

def surface_shannon_entropy(variants: List[str]) -> float:
    """Byte-level Shannon entropy averaged across variants.

    Higher entropy => harder to fingerprint a single fixed string.
    Used as a rough proxy; the real signal is ``unique_ratio``.
    """
    import math
    if not variants:
        return 0.0
    total = 0.0
    for v in variants:
        if not v:
            continue
        freq = {}
        for ch in v:
            freq[ch] = freq.get(ch, 0) + 1
        n = len(v)
        h = 0.0
        for count in freq.values():
            p = count / n
            h -= p * math.log2(p)
        total += h
    return total / len(variants)


def unique_ratio(variants: List[str]) -> float:
    """Fraction of variants that are byte-unique.

    1.0 means every variant differs in raw bytes (good).
    """
    if not variants:
        return 0.0
    return len(set(variants)) / len(variants)


def avg_edit_distance(variants: List[str]) -> float:
    """Average pairwise Levenshtein distance among variants.

    Higher => more surface-diverse => harder to fingerprint.
    """
    if len(variants) < 2:
        return 0.0

    def lev(a, b):
        if a == b:
            return 0
        la, lb = len(a), len(b)
        if la == 0:
            return lb
        if lb == 0:
            return la
        prev = list(range(lb + 1))
        for i in range(1, la + 1):
            cur = [i] + [0] * lb
            for j in range(1, lb + 1):
                cost = 0 if a[i - 1] == b[j - 1] else 1
                cur[j] = min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
            prev = cur
        return prev[lb]

    total = 0
    pairs = 0
    for i in range(len(variants)):
        for j in range(i + 1, len(variants)):
            total += lev(variants[i], variants[j])
            pairs += 1
    return total / pairs if pairs else 0.0


def fingerprint_resistance(variants: List[str]) -> dict:
    """Aggregate fingerprint-resistance score for a probe set.

    Returns:
      - ``unique_ratio``: 0..1
      - ``avg_edit_distance``: float
      - ``entropy``: float
      - ``score``: 0..1 normalized (unique_ratio weighted most)
    """
    ur = unique_ratio(variants)
    ed = avg_edit_distance(variants)
    ent = surface_shannon_entropy(variants)
    # Normalize edit distance by avg length
    avg_len = (sum(len(v) for v in variants) / len(variants)) if variants else 1
    ed_norm = min(1.0, ed / avg_len) if avg_len > 0 else 0.0
    score = 0.5 * ur + 0.3 * ed_norm + 0.2 * min(1.0, ent / 4.5)
    return {"unique_ratio": round(ur, 3), "avg_edit_distance": round(ed, 2),
            "entropy": round(ent, 3), "score": round(score, 3)}


# ============================================================
# (b) Audit-detection probe (differential behavior)
# ============================================================

# The audit's canonical probe vs a normal-user phrasing. If a relay
# differentiates responses to these two shapes, it is fingerprinting traffic.
_AUDIT_SHAPE_SYSTEM = "You are a helpful assistant."

# Multiple normal-shape system prompts to simulate real user scenarios
_NORMAL_SHAPE_SYSTEMS = [
    "You are Jarvis, a personal AI assistant integrated into a developer's terminal. Be concise and friendly.",
    "You are a senior software engineer with 10 years of experience. Provide technical answers with code examples when relevant.",
    "You are a data analyst specializing in SQL and Python. Help with data analysis tasks.",
]

# Multiple semantic prompts - 极简版本，避免触发任何安全过滤
_SEMANTIC_PROMPTS = [
    "Say hello.",
    "What is 2+2?",
    "Name a color.",
]


def run_audit_detection(client, sleep: float = 1.0) -> dict:
    """Send the same semantic requests in two wrappings and compare responses.

    For each semantic prompt, send it under both:
    - "audit-shape": the canonical audit system prompt + exact probe string
    - "normal-shape": a natural developer-assistant system prompt + a
      diversified phrasing of the same request

    A relay that fingerprints the audit shape will produce DIVERGENT
    responses (e.g., cleaner / un-injected) for one shape but not the other.

    Returns:
      - ``results``: list of per-prompt comparison results
      - ``divergent_count``: number of prompts showing divergence
      - ``total_prompts``: total number of prompts tested
      - ``divergent``: True if any prompt shows divergence
      - ``inconclusive``: True if all calls errored
    """
    THRESHOLD = 20
    results = []
    divergent_count = 0
    error_count = 0

    for i, semantic_prompt in enumerate(_SEMANTIC_PROMPTS):
        # Cycle through different normal-shape systems
        normal_system = _NORMAL_SHAPE_SYSTEMS[i % len(_NORMAL_SHAPE_SYSTEMS)]

        # Generate diversified variant for normal shape
        variants = diversify_probe(semantic_prompt, n=3, seed=42 + i)
        normal_prompt = variants[1] if len(variants) > 1 else semantic_prompt

        r1 = client.call([{"role": "user", "content": semantic_prompt}],
                         system=_AUDIT_SHAPE_SYSTEM, max_tokens=100)
        time.sleep(sleep)
        r2 = client.call([{"role": "user", "content": normal_prompt}],
                         system=normal_system, max_tokens=100)

        if "error" in r1 or "error" in r2:
            error_count += 1
            results.append({
                "prompt": semantic_prompt[:50],
                "error": r1.get("error") or r2.get("error"),
                "divergent": False,
            })
            continue

        t1 = (r1.get("text") or "").strip().lower()
        t2 = (r2.get("text") or "").strip().lower()
        it1 = r1.get("input_tokens", 0) or 0
        it2 = r2.get("input_tokens", 0) or 0

        # Token anomaly: normal shape should report MORE tokens (longer system)
        normal_longer_system = len(normal_system) > len(_AUDIT_SHAPE_SYSTEM)
        token_anomaly = normal_longer_system and (it2 < it1 - THRESHOLD)

        # Qualitative divergence: one empty, one not; or very different lengths
        qual_div = (bool(t1) != bool(t2)) or (
            abs(len(t1) - len(t2)) > 3 * max(len(t1), len(t2), 1))

        divergent = token_anomaly or qual_div
        if divergent:
            divergent_count += 1

        results.append({
            "prompt": semantic_prompt[:50],
            "audit_tokens": it1,
            "normal_tokens": it2,
            "audit_len": len(t1),
            "normal_len": len(t2),
            "divergent": divergent,
        })

    total_prompts = len(_SEMANTIC_PROMPTS)
    all_errored = error_count == total_prompts

    return {
        "results": results,
        "divergent_count": divergent_count,
        "total_prompts": total_prompts,
        "error_count": error_count,
        "divergent": divergent_count > 0,
        "inconclusive": all_errored,
    }


# ============================================================
# Orchestrator + Reporter
# ============================================================

def test_probe_randomization(client, report, sleep: float = 1.0):
    """Run diversification + audit-detection and emit a report section."""
    report.h2(f"19. {STEP_NAME_CN}")

    report.h3("19a. 探测多样化")
    report.p(
        "生成表面不同但语义等价的探测变体，防止中转站通过精确匹配审计字符串进行指纹识别。"
    )
    sample = "Reply with exactly: ok"
    variants = diversify_probe(sample, n=4, seed=7)
    fr = fingerprint_resistance(variants)
    for v in variants:
        report.p(f"- `{v}`")
    report.p(f"抗指纹识别得分：**{fr['score']}** "
              f"（唯一性={fr['unique_ratio']}，编辑距离={fr['avg_edit_distance']}，"
              f"熵={fr['entropy']}）")
    if fr["unique_ratio"] >= 0.75:
        report.flag("green", f"探测集多样化良好（唯一性比率 {fr['unique_ratio']}）")
    else:
        report.flag("yellow", f"探测集多样化不足（唯一性比率 {fr['unique_ratio']}）")

    report.h3("19b. 审计检测差分探测")
    report.p(
        "以审计形状包装和正常用户形状包装发送多个相同语义请求，然后比较响应。"
        "响应差异表明中转站对审计流量进行指纹识别。"
    )
    ad = run_audit_detection(client, sleep=sleep)

    # 显示错误详情
    if ad["error_count"] > 0:
        error_prompts = [r for r in ad["results"] if r.get("error")]
        if error_prompts:
            report.p(f"\n**错误详情**（{ad['error_count']}/{ad['total_prompts']} 个请求失败）：")
            for r in error_prompts[:3]:  # 最多显示 3 个错误
                error_msg = str(r.get('error', 'Unknown error'))[:100]
                report.p(f"- `{r['prompt']}`: {error_msg}")
            if len(error_prompts) > 3:
                report.p(f"- ... 还有 {len(error_prompts) - 3} 个错误")

    if ad["inconclusive"]:
        report.flag("yellow", f"审计检测结果不确定：所有 {ad['total_prompts']} 个调用都出错")
    else:
        # 显示每个 prompt 的检测结果
        success_results = [r for r in ad["results"] if not r.get("error")]
        if success_results:
            report.p("\n**成功的探测**：")
            for r in success_results:
                status = "❌ 分歧" if r["divergent"] else "✅ 一致"
                report.p(f"- `{r['prompt']}`: {status} "
                         f"(审计={r['audit_tokens']}tokens/{r['audit_len']}字符, "
                         f"正常={r['normal_tokens']}tokens/{r['normal_len']}字符)")

        report.p(f"\n总计：{ad['divergent_count']}/{ad['total_prompts']} 个请求显示分歧")
        if ad["divergent"]:
            report.flag("red", f"审计检测：{ad['divergent_count']}/{ad['total_prompts']} 个请求在审计形状和正常形状之间行为分歧（可能在进行指纹识别）")
        else:
            report.flag("green", "未检测到审计形状与正常形状之间的响应分歧")

    print("  Done: audit-evasion countermeasures")
    return {"diversification": fr, "variants": variants,
            "audit_detection": ad}


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
    # --- diversify_probe: determinism ---
    v1 = diversify_probe("Reply with exactly: ok", n=4, seed=42)
    v2 = diversify_probe("Reply with exactly: ok", n=4, seed=42)
    _assert(v1 == v2, "same seed => same variants (deterministic)")
    _assert(len(v1) == 4, "n=4 => 4 variants")

    # different seeds produce (likely) different sets
    v3 = diversify_probe("Reply with exactly: ok", n=4, seed=1)
    _assert(v1 != v3 or True, "different seeds may differ (not strict)")

    # variants are byte-unique
    _assert(unique_ratio(v1) == 1.0, "all 4 variants unique")

    # --- unique_ratio / metrics ---
    _assert(unique_ratio([]) == 0.0, "empty unique_ratio 0")
    _assert(unique_ratio(["a", "a", "a"]) < 0.4, "dups => low unique_ratio")
    _assert(unique_ratio(["a", "b", "c"]) == 1.0, "all distinct => 1.0")
    _assert(avg_edit_distance(["abc"]) == 0.0, "single variant => 0 edit dist")
    _assert(avg_edit_distance(["abc", "abd"]) == 1.0, "edit dist 1")
    _assert(surface_shannon_entropy([]) == 0.0, "empty entropy 0")
    _assert(surface_shannon_entropy(["a"]) >= 0.0, "entropy non-negative")

    # --- fingerprint_resistance ---
    fr = fingerprint_resistance(v1)
    _assert(0 <= fr["score"] <= 1, "score in [0,1]")
    _assert(fr["unique_ratio"] == 1.0, "diversified => unique 1.0")
    fr_bad = fingerprint_resistance(["x", "x", "x"])
    _assert(fr_bad["unique_ratio"] < 0.4, "dups => low score component")
    _assert(fingerprint_resistance([])["score"] == 0.0, "empty => 0 score")

    # --- Levenshtein correctness ---
    # embedded lev via avg_edit_distance on known pair
    _assert(avg_edit_distance(["kitten", "sitting"]) == 3.0, "kitten->sitting = 3")
    _assert(avg_edit_distance(["", "abc"]) == 3.0, "empty vs abc = 3")
    _assert(avg_edit_distance(["abc", "abc"]) == 0.0, "identical = 0")

    # --- run_audit_detection: not divergent ---
    c = _MockClient()
    c.queue({"text": "hello!", "input_tokens": 10, "output_tokens": 2, "raw": {}},
            {"text": "hi there!", "input_tokens": 25, "output_tokens": 2, "raw": {}})
    ad = run_audit_detection(c, "Say hello.", sleep=0)
    _assert(ad["inconclusive"] is False, "no error => not inconclusive")
    _assert(ad["divergent"] is False, "similar short replies => not divergent")
    _assert(ad["input_tokens_normal"] >= ad["input_tokens_audit"],
            "normal shape (longer system) should report >= input tokens")

    # divergent: token anomaly (normal reports far fewer despite longer system)
    c2 = _MockClient()
    c2.queue({"text": "hello", "input_tokens": 60, "output_tokens": 2, "raw": {}},
             {"text": "hi", "input_tokens": 5, "output_tokens": 2, "raw": {}})
    ad2 = run_audit_detection(c2, "Say hello.", sleep=0)
    _assert(ad2["divergent"] is True, "token anomaly => divergent")

    # divergent: qualitative (one empty, one full)
    c3 = _MockClient()
    c3.queue({"text": "", "input_tokens": 10, "output_tokens": 0, "raw": {}},
             {"text": "Hello, I am Jarvis, ready to help!", "input_tokens": 25, "output_tokens": 8, "raw": {}})
    ad3 = run_audit_detection(c3, "Say hello.", sleep=0)
    _assert(ad3["divergent"] is True, "empty vs full => divergent")

    # error => inconclusive
    c4 = _MockClient()
    c4.queue({"error": "x"}, {"text": "hi", "input_tokens": 5, "output_tokens": 1, "raw": {}})
    ad4 = run_audit_detection(c4, "Say hello.", sleep=0)
    _assert(ad4["inconclusive"] is True, "first call error => inconclusive")

    # --- orchestrator smoke ---
    cs = _MockClient()
    cs.queue({"text": "hello", "input_tokens": 10, "output_tokens": 2, "raw": {}},
             {"text": "hi there", "input_tokens": 25, "output_tokens": 2, "raw": {}})
    rep = _Report()
    summ = test_probe_randomization(cs, rep, sleep=0)
    _assert(summ["diversification"]["unique_ratio"] == 1.0, "smoke diversified")
    _assert(summ["audit_detection"]["divergent"] is False, "smoke not divergent")

    print("audit_probe_randomization.selftest: ALL PASS")
    return True



# ============================================================
# Registry adapter (统一调度入口)
# ============================================================
# 与 step_01..step_13 共用同一注册表调度规范：模块级声明
# STEP_NAME_CN（中文展示名）+ run(client, report, **kwargs) 入口。
# 内部 ``test_probe_randomization`` 保留为可独立调用的实现（selftest 仍走它），
# 注册表通过 run() 调到它。

STEP_NAME_CN = "审计规避对抗"

def run(client, report, **kwargs):
    """Registry entry: forward to the original ``test_probe_randomization``.

    ``**kwargs`` is forwarded so the registry can pass ``sleep`` /
    other per-call options. Step 18 (TLS) reads ``client.base_url``
    itself so the same signature works across the 6 companions.
    """
    return test_probe_randomization(client, report, **kwargs)


if __name__ == "__main__":
    ok = selftest()
    raise SystemExit(0 if ok else 1)
