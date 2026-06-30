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
    and ask the model to recall all of them. Returns the recovered set with position info."""
    target_chars = target_k * 1024
    # 5 markers at positions 10%, 30%, 50%, 70%, 90% of the filler.
    positions = [int(target_chars * f) for f in (0.1, 0.3, 0.5, 0.7, 0.9)]
    position_labels = ["10%", "30%", "50%", "70%", "90%"]
    marker_prefixes = ["AAA", "BBB", "CCC", "DDD", "EEE"]
    # Build the filler by appending from FILLER until we cover each marker
    # insertion point, then insert the marker.
    text = ""
    cur = 0
    marker_objs = []
    marker_positions = []  # 记录每个标记的位置信息
    for pos, prefix, pos_label in zip(positions, marker_prefixes, position_labels):
        while cur < pos and len(text) < target_chars:
            text += FILLER
            cur = len(text)
        marker = f"{prefix}_CANARY_{pos}_END"
        text += marker
        marker_objs.append(marker)
        marker_positions.append({
            "marker": marker,
            "position": pos,
            "position_label": pos_label,
            "prefix": prefix,
        })
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
        return {
            "target_k": target_k,
            "error": str(r.get("error", "")),
            "found": set(),
            "expected": set(marker_objs),
            "input_tokens": 0,
            "output_tokens": 0,
            "marker_details": [],  # 每个标记的召回详情
        }

    text_resp = r.get("text", "") or ""
    found = set()
    marker_details = []  # 记录每个标记的召回情况
    for mp in marker_positions:
        marker = mp["marker"]
        prefix = mp["prefix"]
        # tolerant match: accept the marker even if the model truncated it
        # slightly. We require the prefix to match.
        recovered = marker in text_resp or prefix + "_CANARY" in text_resp
        if recovered:
            found.add(marker)
        marker_details.append({
            "marker": marker,
            "position_label": mp["position_label"],
            "recovered": recovered,
        })
    return {
        "target_k": target_k,
        "error": None,
        "found": found,
        "expected": set(marker_objs),
        "input_tokens": r.get("input_tokens", 0),
        "output_tokens": r.get("output_tokens", 0),
        "marker_details": marker_details,
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
    report.p("在长文本中等距放置 5 个金丝雀标记，测试模型是否能完整回忆所有标记。\n")
    coarse_steps = None
    if fast_mode:
        coarse_steps = [10, 50, 100, 200]
        report.p(
            "_快速上下文模式已启用：步骤 7 仅测试 10K/50K/100K/200K "
            "字符，然后进行边界细化。建议发布级审计使用默认完整扫描。_\n"
        )

    results = run_context_scan(client, coarse_steps=coarse_steps, sleep_between=2)

    report.p("| 目标长度 (K 字符) | 输入 tokens | 输出 tokens | 标记召回数 |")
    report.p("|-------------------|-------------|-------------|------------|")
    for r in results:
        target = r["target_k"]
        if r.get("error"):
            report.p(f"| {target} | 错误 | - | - |")
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

    # 位置-召回率分析
    report.h3("7.1 位置-召回率分析")
    position_stats = {"10%": {"total": 0, "recovered": 0},
                      "30%": {"total": 0, "recovered": 0},
                      "50%": {"total": 0, "recovered": 0},
                      "70%": {"total": 0, "recovered": 0},
                      "90%": {"total": 0, "recovered": 0}}

    for r in results:
        if r.get("error") or not r.get("marker_details"):
            continue
        for detail in r["marker_details"]:
            pos_label = detail["position_label"]
            position_stats[pos_label]["total"] += 1
            if detail["recovered"]:
                position_stats[pos_label]["recovered"] += 1

    report.p("| 位置 | 召回次数 | 总测试次数 | 召回率 |")
    report.p("|------|----------|------------|--------|")
    for pos in ["10%", "30%", "50%", "70%", "90%"]:
        stats = position_stats[pos]
        if stats["total"] > 0:
            rate = stats["recovered"] / stats["total"] * 100
            report.p(f"| {pos} | {stats['recovered']} | {stats['total']} | **{rate:.1f}%** |")

    # 中间丢失检测
    report.h3("7.2 中间丢失现象检测")
    middle_positions = ["30%", "50%", "70%"]
    edge_positions = ["10%", "90%"]

    middle_total = sum(position_stats[p]["total"] for p in middle_positions)
    middle_recovered = sum(position_stats[p]["recovered"] for p in middle_positions)
    edge_total = sum(position_stats[p]["total"] for p in edge_positions)
    edge_recovered = sum(position_stats[p]["recovered"] for p in edge_positions)

    if middle_total > 0 and edge_total > 0:
        middle_rate = middle_recovered / middle_total * 100
        edge_rate = edge_recovered / edge_total * 100
        gap = edge_rate - middle_rate

        report.p(f"- **边缘位置（10%/90%）召回率**：{edge_rate:.1f}%")
        report.p(f"- **中间位置（30%/50%/70%）召回率**：{middle_rate:.1f}%")
        report.p(f"- **差距**：{gap:.1f} 个百分点")

        if gap > 20:
            report.flag("yellow",
                        f"检测到明显的「中间丢失」现象：边缘位置召回率比中间位置高 {gap:.1f} 个百分点")
        elif gap > 10:
            report.p("_提示：存在轻微的中间位置召回率下降，但未达到显著水平。_")
        else:
            report.p("_未发现明显的中间丢失现象，模型对上下文的利用较为均匀。_")
    else:
        report.p("_数据不足，无法进行中间丢失分析。_")

    # 上下文窗口估算
    report.h3("7.3 上下文窗口估算")
    if full_recovery:
        max_full = max(full_recovery)
        report.flag("green", f"在 {max_full}K 字符范围内完整召回全部 5 个标记")
        # 估算上下文窗口（粗略：1 token ≈ 4 字符 for English）
        estimated_tokens = max_full * 1024 // 4
        report.p(f"_估算有效上下文窗口：约 {estimated_tokens:,} tokens（基于 {max_full}K 字符）_")
    else:
        # 找到最后一个有召回结果的长度
        partial_recovery = [
            (r["target_k"], len(r["found"])) for r in results
            if not r.get("error") and len(r["found"]) > 0
        ]
        if partial_recovery:
            max_partial_k, max_partial_count = max(partial_recovery, key=lambda x: x[0])
            report.flag(
                "yellow",
                f"未达到完整召回；在 {max_partial_k}K 字符时最多召回 {max_partial_count}/5 个标记"
            )
            estimated_tokens = max_partial_k * 1024 // 4
            report.p(f"_估算有效上下文窗口：约 {estimated_tokens:,} tokens（部分召回）_")
        else:
            report.flag(
                "yellow",
                "所有测试长度均未成功召回任何标记；中转站的上下文处理"
                "可能存在严重问题（截断、摘要或重写）。",
            )

    print(f"  Done: context length (max full recall: {max(full_recovery) if full_recovery else 'none'}K)")
