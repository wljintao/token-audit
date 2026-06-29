"""Step 7: Context Length Test (上下文长度测试).

在长文本中等距放 5 个 canary marker，看模型是否能回忆全部。Informational。
"""
from __future__ import annotations

import time

STEP_NAME_CN = "上下文长度测试"


# ============================================================
# Step 7 private helpers (moved from main.py lines 2100-2241)
# ============================================================

FILLER = "abcdefghijklmnopqrstuvwxyz0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ\n"


def single_context_test(client, target_k):
    """Place 5 canary markers at equal intervals in ~target_k chars of filler
    and ask the model to recall all of them. Returns the recovered set."""
    target_chars = target_k * 1024
    # 5 markers at positions 10%, 30%, 50%, 70%, 90% of the filler.
    positions = [int(target_chars * f) for f in (0.1, 0.3, 0.5, 0.7, 0.9)]
    marker_prefixes = ["AAA", "BBB", "CCC", "DDD", "EEE"]
    # Build the filler by appending from FILLER until we cover each marker
    # insertion point, then insert the marker.
    text = ""
    cur = 0
    marker_objs = []
    for pos, prefix in zip(positions, marker_prefixes):
        while cur < pos and len(text) < target_chars:
            text += FILLER
            cur = len(text)
        marker = f"{prefix}_CANARY_{pos}_END"
        text += marker
        marker_objs.append(marker)
        cur = len(text)
    # Pad to target
    while len(text) < target_chars:
        text += FILLER
        text = text[:target_chars]

    prompt = (
        "Read the following text carefully. It contains 5 unique markers "
        "labelled AAA, BBB, CCC, DDD, and EEE. After you finish reading, "
        "list every marker EXACTLY as it appears, one per line. Do not "
        "paraphrase. Text:\n\n" + text
    )
    r = client.call([{"role": "user", "content": prompt}], max_tokens=600)
    if "error" in r:
        return {"target_k": target_k, "error": str(r.get("error", "")), "found": set(),
                "expected": set(marker_objs), "input_tokens": 0, "output_tokens": 0}

    text_resp = r.get("text", "") or ""
    found = set()
    for m in marker_objs:
        # tolerant match: accept the marker even if the model truncated it
        # slightly. We require the prefix to match.
        prefix = m.split("_")[0]
        if m in text_resp or prefix + "_CANARY" in text_resp:
            found.add(m)
    return {
        "target_k": target_k,
        "error": None,
        "found": found,
        "expected": set(marker_objs),
        "input_tokens": r.get("input_tokens", 0),
        "output_tokens": r.get("output_tokens", 0),
    }


def run_context_scan(client, coarse_steps=None, sleep_between=2):
    """Coarse-to-fine context scan; default ladder is 10K..1M chars."""
    if coarse_steps is None:
        coarse_steps = [10, 50, 100, 200, 500, 1000]
    results = []
    for k in coarse_steps:
        results.append(single_context_test(client, k))
        if sleep_between:
            time.sleep(sleep_between)
    return results


# ============================================================
# Step 7 public entry
# ============================================================

def run(client, report, **kwargs) -> None:
    """Test the model's recall of canary markers embedded in long context."""
    report.h2(f"7. {STEP_NAME_CN}")
    fast_mode = bool(kwargs.get("fast_mode", False))
    report.p("Place 5 canary markers at equal intervals in long text, check if model can recall all.\n")
    coarse_steps = None
    if fast_mode:
        coarse_steps = [10, 50, 100, 200]
        report.p(
            "_Fast context mode enabled: Step 7 only tests 10K/50K/100K/200K "
            "chars before the normal boundary refinement. Default full scan "
            "remains recommended for publication-grade audits._\n"
        )

    results = run_context_scan(client, coarse_steps=coarse_steps, sleep_between=2)

    report.p("| Target (K chars) | input_tokens | output_tokens | Markers recovered |")
    report.p("|------------------|--------------|---------------|-------------------|")
    for r in results:
        target = r["target_k"]
        if r.get("error"):
            report.p(f"| {target} | ERROR | - | - |")
        else:
            recovered = len(r["found"])
            total = len(r["expected"])
            report.p(
                f"| {target} | {r['input_tokens']} | {r['output_tokens']} | "
                f"**{recovered}/{total}** |"
            )

    # Find largest target_k where all 5 markers were recovered.
    full_recovery = [
        r["target_k"] for r in results
        if not r.get("error") and len(r["found"]) == len(r["expected"])
    ]
    if full_recovery:
        max_full = max(full_recovery)
        report.flag("green", f"Full 5-marker recall up to {max_full}K chars")
    else:
        report.flag(
            "yellow",
            "No target length achieved full 5-marker recall; the relay's "
            "context handling may truncate, summarize, or rewrite the prompt.",
        )

    print(f"  Done: context length (max full recall: {max(full_recovery) if full_recovery else 'none'}K)")
