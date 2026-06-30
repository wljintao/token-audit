"""Step 12: Latency Variance (延迟方差分析).

发送 N 个相同的最小请求，测量每请求端到端延迟；输出描述性统计和简单
bimodality 启发式。Informational only — 不进 6D 风险矩阵。
"""
from __future__ import annotations

import statistics
import time

from step_helpers import format_diagnosis, _diagnosis_for_error

STEP_NAME_CN = "延迟方差分析"


# ============================================================
# Step 12 private helpers (moved from main.py lines 4301-4488)
# ============================================================

DEFAULT_PROBE_COUNT = 10
DEFAULT_PROBE_PROMPT = "Reply with the single word: ok"
DEFAULT_PROBE_MAX_TOKENS = 8
DEFAULT_INTER_PROBE_SLEEP = 0.2

BIMODAL_GAP_THRESHOLD = 0.5
CV_STABLE_CUTOFF = 0.25
CV_VARIABLE_CUTOFF = 0.5


def summarize_latencies(latencies):
    """Compute descriptive statistics for a list of latencies (seconds)."""
    if not latencies:
        return {}
    n = len(latencies)
    result = {
        "count": n,
        "min": min(latencies),
        "max": max(latencies),
        "mean": statistics.mean(latencies),
        "median": statistics.median(latencies),
    }
    if n >= 2:
        result["stdev"] = statistics.stdev(latencies)
        result["cv"] = (
            result["stdev"] / result["mean"] if result["mean"] > 0 else 0.0
        )
    else:
        result["stdev"] = 0.0
        result["cv"] = 0.0
    return result


def detect_bimodality(latencies):
    """Return ``(is_bimodal, gap_ratio)``."""
    n = len(latencies)
    if n < 4:
        return False, 0.0
    median = statistics.median(latencies)
    if median <= 0:
        return False, 0.0
    sorted_lats = sorted(latencies)
    best_ratio = 0.0
    for i in range(1, n - 2):
        gap = sorted_lats[i + 1] - sorted_lats[i]
        ratio = gap / median
        if ratio > best_ratio:
            best_ratio = ratio
    return best_ratio > BIMODAL_GAP_THRESHOLD, best_ratio


def classify_variance(stats, is_bimodal):
    """Return verdict: stable / variable / high-variance / bimodal / inconclusive."""
    if not stats or stats.get("count", 0) < 3:
        return "inconclusive"
    if is_bimodal:
        return "bimodal"
    cv = stats.get("cv", 0.0)
    if cv < CV_STABLE_CUTOFF:
        return "stable"
    if cv < CV_VARIABLE_CUTOFF:
        return "variable"
    return "high-variance"


def run_latency_variance(client, count=DEFAULT_PROBE_COUNT,
                         prompt=DEFAULT_PROBE_PROMPT,
                         max_tokens=DEFAULT_PROBE_MAX_TOKENS,
                         sleep=DEFAULT_INTER_PROBE_SLEEP):
    """Fire ``count`` identical minimal requests and measure latency."""
    if hasattr(client, "ensure_format"):
        client.ensure_format()

    latencies = []
    errors = []
    for i in range(count):
        t0 = time.perf_counter()
        r = client.call(
            [{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
        )
        elapsed = time.perf_counter() - t0
        if "error" in r:
            errors.append(r["error"])
        else:
            latencies.append(elapsed)
        if sleep > 0 and i < count - 1:
            time.sleep(sleep)

    stats = summarize_latencies(latencies)
    is_bimodal, gap_ratio = detect_bimodality(latencies)
    verdict = classify_variance(stats, is_bimodal)

    return {
        "latencies": latencies,
        "errors": errors,
        "stats": stats,
        "bimodal": is_bimodal,
        "gap_ratio": gap_ratio,
        "verdict": verdict,
    }


# ============================================================
# Step 12 public entry
# ============================================================

def run(client, report, **kwargs):
    """Latency variance fingerprinting (v1.8). Informational only."""
    probe_count = int(kwargs.get("probe_count", DEFAULT_PROBE_COUNT))
    report.h2(f"12. {STEP_NAME_CN}")
    report.p(
        f"发送 {probe_count} 个相同的最小请求（`max_tokens=8`），"
        "测量每个请求的端到端延迟。计算描述性统计和基于间隔比的双峰分布检测。"
        "原理：如果中转站在宣传模型和廉价替代品之间进行静默 A/B 测试，"
        "会产生双峰延迟分布；队列多路复用的中转站会显示多峰模式。"
        "稳定的低方差延迟是诚实基线。v1.8 中**仅为信息性**——不纳入整体风险评级。\n"
    )

    result = run_latency_variance(client, count=probe_count)
    latencies = result["latencies"]
    errors = result["errors"]
    stats = result["stats"]

    if not latencies:
        if errors:
            report.p("\n**错误诊断**：")
            for idx, error in enumerate(errors, start=1):
                report.p(
                    f"- 探测 {idx}："
                    f"{format_diagnosis(_diagnosis_for_error(error))}"
                )
        report.flag(
            "yellow",
            f"延迟方差测试结果不确定：所有 {len(errors)} 个探测都失败。"
            "中转站拒绝或错误处理了即使是最小的请求。",
        )
        print("  Done: latency variance (inconclusive, all probes errored)")
        return result

    report.p("| 指标 | 值 |")
    report.p("|------|-----|")
    report.p(f"| 成功探测数 | {stats['count']} / {probe_count} |")
    report.p(f"| 失败探测数 | {len(errors)} |")
    report.p(f"| 最小值 | {stats['min']:.3f}s |")
    report.p(f"| 中位数 | {stats['median']:.3f}s |")
    report.p(f"| 最大值 | {stats['max']:.3f}s |")
    report.p(f"| 平均值 | {stats['mean']:.3f}s |")
    report.p(f"| 标准差 | {stats['stdev']:.3f}s |")
    report.p(f"| 变异系数 | {stats['cv']:.3f} |")
    report.p(f"| 最大间隔/中位数 | {result['gap_ratio']:.3f} |")
    report.p(f"| 判定结果 | `{_verdict_cn(result['verdict'])}` |")

    if errors:
        report.p("\n**错误诊断**：")
        for idx, error in enumerate(errors, start=1):
            report.p(f"- 失败的探测 {idx}：{format_diagnosis(_diagnosis_for_error(error))}")

    verdict = result["verdict"]
    if verdict == "bimodal":
        report.flag(
            "yellow",
            "延迟分布呈**双峰**：探测结果聚集成两个不同的响应时间组。"
            "可能在宣传模型和廉价替代品之间进行静默 A/B 测试。"
            "v1.8 中仅为信息性——请结合步骤 5 身份检查和步骤 11 基础设施指纹验证。",
        )
    elif verdict == "high-variance":
        report.flag(
            "yellow",
            f"延迟**高方差**（CV={stats['cv']:.2f}）。"
            "v1.8 中仅为信息性；可能是网络抖动、上游拥塞或路由不稳定。",
        )
    elif verdict == "variable":
        report.flag(
            "green",
            f"延迟**有变化**（CV={stats['cv']:.2f}）。"
            "在典型网络抖动范围内。",
        )
    elif verdict == "stable":
        report.flag(
            "green",
            f"延迟**稳定**（CV={stats['cv']:.2f}）。"
            "与单一诚实上游一致。",
        )
    else:
        report.flag(
            "yellow",
            f"延迟方差**结果不确定**（仅 {stats['count']} 个成功探测）。"
            "请使用 --latency-probe-count >= 4 重新运行。",
        )

    print(f"  Done: latency variance ({verdict}, "
          f"CV={stats['cv']:.2f}, n={stats['count']})")
    return result


def _verdict_cn(verdict: str) -> str:
    """将判定结果翻译为中文。"""
    return {
        "stable": "稳定",
        "variable": "有变化",
        "high-variance": "高方差",
        "bimodal": "双峰",
        "inconclusive": "不确定",
    }.get(verdict, verdict)
