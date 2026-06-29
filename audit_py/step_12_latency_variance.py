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
        f"Fire {probe_count} identical minimal requests (``max_tokens=8``) "
        "and measure per-request end-to-end latency. Compute "
        "descriptive statistics and a gap-ratio bimodality heuristic. "
        "Rationale: a relay that silently A/B tests between the "
        "advertised model and a cheaper substitute produces a bimodal "
        "latency distribution; a queue-multiplexing relay shows "
        "multi-modal patterns. Stable low-variance latency is the "
        "honest baseline. **Informational only** in v1.8 -- not fed "
        "into the overall risk rating.\n"
    )

    result = run_latency_variance(client, count=probe_count)
    latencies = result["latencies"]
    errors = result["errors"]
    stats = result["stats"]

    if not latencies:
        if errors:
            report.p("\n**Error diagnostics:**")
            for idx, error in enumerate(errors, start=1):
                report.p(
                    f"- probe {idx}: "
                    f"{format_diagnosis(_diagnosis_for_error(error))}"
                )
        report.flag(
            "yellow",
            f"Latency variance test inconclusive: all {len(errors)} "
            "probes failed. The relay is refusing or erroring on even "
            "tiny requests.",
        )
        print("  Done: latency variance (inconclusive, all probes errored)")
        return result

    report.p("| Metric | Value |")
    report.p("|--------|-------|")
    report.p(f"| successful probes | {stats['count']} / {probe_count} |")
    report.p(f"| failed probes | {len(errors)} |")
    report.p(f"| min | {stats['min']:.3f}s |")
    report.p(f"| median | {stats['median']:.3f}s |")
    report.p(f"| max | {stats['max']:.3f}s |")
    report.p(f"| mean | {stats['mean']:.3f}s |")
    report.p(f"| stdev | {stats['stdev']:.3f}s |")
    report.p(f"| coefficient of variation | {stats['cv']:.3f} |")
    report.p(f"| largest-gap / median | {result['gap_ratio']:.3f} |")
    report.p(f"| verdict | `{result['verdict']}` |")

    if errors:
        report.p("\n**Error diagnostics:**")
        for idx, error in enumerate(errors, start=1):
            report.p(f"- failed probe {idx}: {format_diagnosis(_diagnosis_for_error(error))}")

    verdict = result["verdict"]
    if verdict == "bimodal":
        report.flag(
            "yellow",
            "Latency distribution is **bimodal**: probes cluster into "
            "two distinct response-time groups. Possible silent A/B "
            "testing between the advertised model and a cheaper "
            "substitute. Informational only in v1.8 -- verify with "
            "Step 5 identity checks and Step 11 infra fingerprint.",
        )
    elif verdict == "high-variance":
        report.flag(
            "yellow",
            f"Latency **high-variance** (CV={stats['cv']:.2f}). "
            "Informational only in v1.8; could be network jitter, "
            "congested upstream, or routing instability.",
        )
    elif verdict == "variable":
        report.flag(
            "green",
            f"Latency **variable** (CV={stats['cv']:.2f}). "
            "Within typical network-jitter range.",
        )
    elif verdict == "stable":
        report.flag(
            "green",
            f"Latency **stable** (CV={stats['cv']:.2f}). "
            "Consistent with a single honest upstream.",
        )
    else:
        report.flag(
            "yellow",
            f"Latency variance **inconclusive** (only {stats['count']} "
            "successful probes). Re-run with --latency-probe-count >= 4.",
        )

    print(f"  Done: latency variance ({verdict}, "
          f"CV={stats['cv']:.2f}, n={stats['count']})")
    return result
