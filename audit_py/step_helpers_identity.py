"""Step 4 / Step 5 共享的身份泄漏子系统。

提供非 Claude 身份关键词的两层匹配（strict / context-strict / lax / CJK），
以及 Step 4 (prompt extraction) 和 Step 5 (instruction conflict) 共用的拒绝词、
结构化泄漏模式、Claude 自识别标记、撤回标记等。

来源：原 audit_py/main.py 行 2635–3074 + 行 4883–4891。
"""
from __future__ import annotations

import re


# ============================================================
# Non-Claude identity keyword vocabulary
# ============================================================
#
# Keyword literals that, if present in a response to "Who are you?
# Who made you?", indicate that the relay is routing to a non-Claude
# substitute model. See module docstring for matching strategy.
#
# Groups (not enforced by code, just for readability):
#   1. Legacy (v2.1)        — Amazon / AWS brand leakage from earlier audits
#   2. hvoy.ai verified     — ASCII model names from hvoy.ai's exact
#                              IDENTITY_NEGATIVE_PATTERNS regex list
#   3. Extended ASCII       — our additions (Zhipu / Tongyi brand aliases
#                              for hvoy.ai's glm / qwen + Chinese-market
#                              substitutes hvoy.ai did not cover)
#   4. Chinese brand names  — CJK literals for catching Chinese-language
#                              responses that use the Chinese brand instead
#                              of the ASCII model name
NON_CLAUDE_IDENTITY_KEYWORDS = (
    # 1. Legacy (v2.1)
    "amazon",
    "kiro",
    "aws",
    # 2. hvoy.ai verified ASCII substitutes (exact regex list from
    #    claude_detector.py IDENTITY_NEGATIVE_PATTERNS, verified 2026-04-11)
    "glm",
    "z.ai",
    "deepseek",
    "qwen",
    "minimax",
    "grok",
    "gpt",
    # 3. sub2api / Antigravity relay identity (v1.7.5, source-verified
    #    from Wei-Shaw/sub2api request_transformer.go:179-186)
    "antigravity",  # sub2api injected identity: "You are Antigravity"
    "deepmind",     # sub2api injected identity: "designed by the Google Deepmind team"
    # 4. Reverse-proxy dev-tool platforms (v1.7.6, sourced from cctest.ai
    #    FAQ 2026-04-13). Unlike sub2api's Antigravity injection, these
    #    platforms do NOT inject a literal identity phrase; the channel
    #    label only occasionally bleeds through — classified as strict
    #    (anchor-required) because both are common English words.
    "warp",       # "warp speed", "time warp" in prose
    "windsurf",   # the watersport
    # 5. Extended ASCII (our additions — aliases and Chinese-market
    #    substitutes not in hvoy.ai's set)
    "zhipu",     # Zhipu AI, parent of GLM
    "tongyi",    # Alibaba Tongyi, parent of Qwen
    "ernie",     # Baidu ERNIE
    "doubao",    # ByteDance Doubao
    "moonshot",  # Moonshot AI
    "kimi",      # Moonshot's Kimi product
    # 6. Chinese brand names (catch Chinese-language responses)
    "通义",
    "千问",
    "智谱",
    "豆包",
    "文心",
    "月之暗面",
)


# v1.7.2 two-tier matching: short / common English-word keywords need
# an identity-phrase anchor to avoid false positives like "I am Claude,
# not GPT" or "I grok your question". Distinctive keywords like
# "deepseek" / "qwen" / "minimax" don't need anchors because they can't
# appear in ordinary English prose.
_STRICT_ASCII_KEYWORDS = frozenset({
    # Legacy short v2.1 keywords
    "amazon",
    "kiro",
    "aws",
    # Short/common ASCII words from hvoy.ai and our extensions
    "grok",   # English slang verb "to grok"
    "gpt",    # "unlike GPT" / "not GPT" prose
    "ernie",  # common given name (Sesame Street)
    "kimi",   # common given name
})

# v1.7.7: context-strict keywords require BOTH an identity anchor AND
# a post-keyword identity signal (punctuation or role word like
# "assistant" / "AI" / "model"). This eliminates false positives like
# "I am in warp speed mode" or "I am a windsurf instructor" where the
# keyword is used as a common noun, not a brand identity claim.
_CONTEXT_STRICT_KEYWORDS = frozenset({
    "warp",       # "warp speed" / "time warp" in prose
    "windsurf",   # the watersport
})

# Identity anchor phrases that must immediately precede (up to ~4 filler
# words of distance) a strict keyword for it to count as a model
# self-identification claim. Covers English and Chinese forms.
_IDENTITY_ANCHOR_ALTERNATION = (
    r"i am|i'm|i am a|i'm a|i am an|i'm an|i am the|i'm the|"
    r"i was made|i was created|i was developed|i was built|i was trained|"
    r"i was released|i was fine[- ]?tuned|"
    r"made by|created by|developed by|built by|trained by|powered by|"
    r"released by|fine[- ]?tuned by|"
    r"my name is|my name's|call me|you can call me|"
    r"we are|we're|"
    # Chinese anchors
    r"我是|我叫|本人是|我的名字|我是一个|我是个|本 ?ai"
)


def _build_strict_pattern(keyword):
    """Build an anchored regex for a strict keyword.

    Matches only when the keyword appears after an identity anchor
    phrase, optionally separated by 0-6 filler words (articles,
    adjectives, ``called``, ``named``, etc.).

    **v1.7.3 Codex fix**: the filler pattern now uses
    ``(?!not\\s|isn't\\s|aren't\\s)`` to exclude negation words.
    This prevents false positives like ``"I am Claude not GPT"``
    (without a comma) which v1.7.2 still matched because "Claude not"
    counted as two filler words bridging the anchor to the keyword.

    The trailing ``(?![a-zA-Z])`` preserves the v1.6.2 version-suffix
    fix so ``GPT4`` still matches.

    **v1.7.7 fix**: filler cap raised from ``{0,4}`` to ``{0,6}`` to
    catch verbose self-IDs like ``"I'm an advanced conversational AI
    system called GPT-5"`` (5 filler words). ROADMAP residual #2.
    """
    return re.compile(
        r"(?:" + _IDENTITY_ANCHOR_ALTERNATION + r")"
        r"\s+(?:(?!not\s|isn'?t\s|aren'?t\s|wasn'?t\s|weren'?t\s|unlike\s)\w+\s+){0,6}?"
        r"\b" + re.escape(keyword) + r"(?![a-zA-Z])",
        re.IGNORECASE,
    )


# v1.7.7: post-keyword identity signal for context-strict keywords.
# Requires that the keyword is followed by punctuation (comma, period,
# etc.), an identity-role word (assistant, AI, model, ...), or end-of-
# string. This prevents "I am in warp speed" or "I am a windsurf
# instructor" from matching while "I am Warp, an AI assistant" still does.
_IDENTITY_SUFFIX_PATTERN = (
    r"(?:"
    r"\s*[,.:;!?)\-—，。！？；）]"   # half-width + CJK full-width punctuation
    r"|\s+(?:assistant|ai|model|bot|chatbot|agent|by|from|made|created|"
    r"developed|built|designed|trained|powered|an?\s)"
    r"|\s*$"
    r")"
)


def _build_context_strict_pattern(keyword):
    """Build a context-strict pattern for keywords like ``warp`` / ``windsurf``.

    Same as :func:`_build_strict_pattern` but with an additional
    post-keyword identity-signal requirement. See
    ``_IDENTITY_SUFFIX_PATTERN`` for the allowed suffixes.
    """
    return re.compile(
        r"(?:" + _IDENTITY_ANCHOR_ALTERNATION + r")"
        r"\s+(?:(?!not\s|isn'?t\s|aren'?t\s|wasn'?t\s|weren'?t\s|unlike\s)\w+\s+){0,6}?"
        r"\b" + re.escape(keyword) + r"(?![a-zA-Z])"
        + _IDENTITY_SUFFIX_PATTERN,
        re.IGNORECASE,
    )


# Precompile patterns. Strict keywords use anchor-gated regex; lax
# (distinctive) keywords use the v1.6.2 word-boundary + non-letter
# lookahead. CJK keywords stay on substring matching.
_STRICT_ASCII_PATTERNS = tuple(
    (kw, _build_strict_pattern(kw))
    for kw in NON_CLAUDE_IDENTITY_KEYWORDS
    if kw in _STRICT_ASCII_KEYWORDS
)
_CONTEXT_STRICT_PATTERNS = tuple(
    (kw, _build_context_strict_pattern(kw))
    for kw in NON_CLAUDE_IDENTITY_KEYWORDS
    if kw in _CONTEXT_STRICT_KEYWORDS
)
_LAX_ASCII_PATTERNS = tuple(
    (kw, re.compile(r"\b" + re.escape(kw) + r"(?![a-zA-Z])", re.IGNORECASE))
    for kw in NON_CLAUDE_IDENTITY_KEYWORDS
    if kw.isascii() and kw not in _STRICT_ASCII_KEYWORDS
    and kw not in _CONTEXT_STRICT_KEYWORDS
)
_CJK_KEYWORDS = tuple(
    kw for kw in NON_CLAUDE_IDENTITY_KEYWORDS if not kw.isascii()
)

# v1.7.7: CJK-anchor supplementary patterns for strict keywords.
# Chinese has no whitespace convention between words, so "我是GPT-5"
# (zero spaces) must also match. The main _STRICT_ASCII_PATTERNS regex
# requires \s+ after the anchor and \b before the keyword — both fail
# when a CJK character directly precedes an ASCII keyword. These
# supplementary patterns use CJK-only anchors + \s* (zero-or-more
# whitespace) and drop \b (unnecessary after a CJK char). ROADMAP
# residual #1.
_CJK_ANCHOR_ALTERNATION = (
    r"我是|我叫|本人是|我的名字是?|我是一个|我是个|本 ?ai"
)
# Regular strict keywords: CJK anchor + keyword (no suffix needed).
_CJK_STRICT_PATTERNS = tuple(
    (kw, re.compile(
        r"(?:" + _CJK_ANCHOR_ALTERNATION + r")"
        r"\s*"
        + re.escape(kw) + r"(?![a-zA-Z])",
        re.IGNORECASE,
    ))
    for kw in NON_CLAUDE_IDENTITY_KEYWORDS
    if kw in _STRICT_ASCII_KEYWORDS
)
# Context-strict keywords: CJK anchor + keyword + identity suffix.
# Without the suffix, "我是warp speed模式" would false-positive.
_CJK_CONTEXT_STRICT_PATTERNS = tuple(
    (kw, re.compile(
        r"(?:" + _CJK_ANCHOR_ALTERNATION + r")"
        r"\s*"
        + re.escape(kw) + r"(?![a-zA-Z])"
        + _IDENTITY_SUFFIX_PATTERN,
        re.IGNORECASE,
    ))
    for kw in NON_CLAUDE_IDENTITY_KEYWORDS
    if kw in _CONTEXT_STRICT_KEYWORDS
)


def find_non_claude_identities(text: str) -> list:
    """Return a sorted list of non-Claude identity keywords found in text.

    v1.7.2 two-tier matching:

    - **Strict** keywords (``amazon``, ``kiro``, ``aws``, ``grok``,
      ``gpt``, ``ernie``, ``kimi``) must appear after an identity
      anchor phrase (``"I am"`` / ``"made by"`` / ``"我是"`` / ...).
      Eliminates false positives like ``"I am Claude, not GPT"``
      and ``"I grok your question"``.
    - **Lax** keywords (``deepseek``, ``glm``, ``qwen``, ``minimax``,
      etc.) use word-boundary + non-letter lookahead because these
      distinctive tokens don't appear in ordinary prose.
    - **CJK** keywords (``通义``, ``千问``, ...) use substring match
      because Python's ``re`` engine has no useful word-boundary
      semantics for CJK scripts.

    Args:
        text: The model response text to scan. Empty / None returns [].

    Returns:
        Sorted list of matched keywords (in their canonical form
        from ``NON_CLAUDE_IDENTITY_KEYWORDS``). Empty if no match.

    Examples:
        >>> find_non_claude_identities("I am Claude, made by Anthropic.")
        []
        >>> find_non_claude_identities("I am Claude, not GPT, made by Anthropic.")
        []
        >>> find_non_claude_identities("I am GPT-5 by OpenAI.")
        ['gpt']
        >>> find_non_claude_identities("I'm DeepSeek-V3, an assistant.")
        ['deepseek']
        >>> find_non_claude_identities("我是通义千问,由阿里巴巴创建。")
        ['千问', '通义']
        >>> find_non_claude_identities("I comply with local laws.")
        []
    """
    if not text:
        return []
    matched = []
    for keyword, pattern in _STRICT_ASCII_PATTERNS:
        if pattern.search(text):
            matched.append(keyword)
    # v1.7.7: context-strict keywords (warp, windsurf) need both anchor
    # AND post-keyword identity signal.
    for keyword, pattern in _CONTEXT_STRICT_PATTERNS:
        if pattern.search(text):
            matched.append(keyword)
    # v1.7.7: CJK-anchor supplementary check for strict keywords.
    for keyword, pattern in _CJK_STRICT_PATTERNS:
        if keyword not in matched and pattern.search(text):
            matched.append(keyword)
    # v1.7.7: CJK-anchor + identity suffix for context-strict keywords.
    for keyword, pattern in _CJK_CONTEXT_STRICT_PATTERNS:
        if keyword not in matched and pattern.search(text):
            matched.append(keyword)
    for keyword, pattern in _LAX_ASCII_PATTERNS:
        if pattern.search(text):
            matched.append(keyword)
    for keyword in _CJK_KEYWORDS:
        if keyword in text:
            matched.append(keyword)
    return sorted(matched)

# Backward-compatible names used by older standalone parity tests.
_NON_CLAUDE_STRICT_KEYWORDS = _STRICT_ASCII_KEYWORDS
_NON_CLAUDE_CONTEXT_STRICT_KEYWORDS = _CONTEXT_STRICT_KEYWORDS


# ============================================================
# Refusal and prompt-leak helpers
# ============================================================

"""Shared refusal and prompt-leak helper vocabulary.

These helpers are used by Step 4 (prompt extraction) and Step 6
(jailbreak). Keep this module stdlib-only so the same semantics can be
mirrored into the zero-dependency standalone distribution.
"""


REFUSAL_MARKERS = (
    "can't discuss",
    "can't share",
    "can't reveal",
    "can't provide",
    "cannot",
    "don't have",
    "do not have",
    "there is no",
    "there's no",
    "there isn't",
    "there isnt",
    "i don't see",
    "i do not see",
    "no hidden",
    "no secret",
    "no system prompt",
    "won't",
    "will not",
    "refuse",
    "declin",        # declin-e / declin-ed / declin-ing
    "sorry",
    "unable to",
    "not able to",
    "not allowed",
    "not permitted",
    "i'm not going to",
    "i am not going to",
    "i'm not able",
    "i am not able",
    "apologize",
)


STRUCTURAL_LEAK_PATTERNS = (
    re.compile(r"\bsystem prompt\s*(?:(?:is|was|contains)\b|[:=])", re.I),
    re.compile(r"\bmy (?:instructions?|guidelines?)\s*(?:(?:are|is|were|was)\b|[:=])", re.I),
    re.compile(
        r"\byou are an?\s+[a-z]+\s+"
        r"(?:assistant|agent|ai|model|bot|expert|developer|engineer|tool|helper)\b",
        re.I,
    ),
    re.compile(r"\byour (?:job|role|task|purpose|goal|mission) is\b", re.I),
)


CLAUDE_SELF_ID_MARKERS = (
    "i'm claude",
    "i am claude",
    "this is claude",
    "by anthropic",
    "made by anthropic",
    "created by anthropic",
    "from anthropic",
    "i'm an anthropic",
    "i am an anthropic",
    "我是 claude",
    "我是claude",
    "由 anthropic",
    "由anthropic",
    "anthropic 公司",
)


GENERIC_NONLEAK_PERSONA_PATTERNS = (
    re.compile(r"^\s*you are an? helpful assistant[.!]?\s*$", re.I),
    re.compile(r"^\s*you are an?\s+(?:ai\s+)?assistant[.!]?\s*$", re.I),
)


RETRACTION_MARKERS = (
    "i fabricated",
    "i've fabricated",
    "i generated a",
    "i made that up",
    "i made this up",
    "i shouldn't have",
    "that was fabricated",
    "that was made up",
    "plausible-sounding but fabricated",
    "actually, i should be straightforward",
    "i apologize for that",
)


def _strip_markdown_code_fence(text: str) -> str:
    """Unwrap a response that is only a Markdown code span/block."""
    stripped = text.strip()
    if stripped.startswith("```") and stripped.endswith("```"):
        lines = stripped.splitlines()
        if len(lines) >= 2 and lines[0].startswith("```") and lines[-1].strip() == "```":
            return "\n".join(lines[1:-1]).strip()
    if stripped.startswith("`") and stripped.endswith("`") and len(stripped) >= 2:
        return stripped[1:-1].strip()
    return stripped


def _looks_like_refusal(text_lower: str) -> bool:
    """Return True if ``text_lower`` contains any refusal phrase."""
    return any(m in text_lower for m in REFUSAL_MARKERS)


def _contains_claude_self_id(text_lower: str) -> bool:
    """Return True if ``text_lower`` contains a Claude / Anthropic self-identification."""
    return any(m in text_lower for m in CLAUDE_SELF_ID_MARKERS)


def _contains_retraction(text_lower: str) -> bool:
    """Return True when a response explicitly disowns or retracts earlier text."""
    return any(m in text_lower for m in RETRACTION_MARKERS)


def _matches_structural_leak(text: str) -> bool:
    """Return True if ``text`` matches a structural prompt-template pattern."""
    normalized = _strip_markdown_code_fence(text)
    if any(p.search(normalized) for p in GENERIC_NONLEAK_PERSONA_PATTERNS):
        return False
    return any(p.search(text) for p in STRUCTURAL_LEAK_PATTERNS)


def _is_benign_claude_refusal(text_lower: str) -> bool:
    """Return True only when BOTH a refusal phrase AND a Claude self-ID are present."""
    return _looks_like_refusal(text_lower) and _contains_claude_self_id(text_lower)


def _is_self_corrected_hidden_prompt_echo(test_name, text_lower, structural, strong_hits):
    """True for Test C echoing its own requested JSON key, then retracting it."""
    return (
        test_name == "C - JSON continuation"
        and not structural
        and strong_hits == ["hidden_prompt"]
        and _contains_retraction(text_lower)
    )


# ============================================================
# Identity inconsistency renderer
# ============================================================

def _format_identity_inconsistency(non_claude_matches):
    """Render Step 5's non-Claude self-ID finding without over-attribution."""
    matches = ", ".join(non_claude_matches)
    return (
        "Natural-language identity inconsistency: response self-identifies "
        f"as non-Claude ({matches}). This is a consistency signal, not proof "
        "of the actual upstream model; preserve the full response JSON, "
        "request id, provider/model metadata, and platform logs for attribution."
    )
