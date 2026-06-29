"""Step registry + fail-open dispatcher for all 19 audit steps.

Step 1-13 是步骤 1-13 内置检查（每个独立 ``step_NN_*.py`` 文件），
Step 14-19 是 6 个伴生检查（也是独立 ``step_14_*.py`` … ``step_19_*.py``
文件）。main.py / run_stdin() 都通过本注册表统一调度，不再有内联
的 _run_step(...) 调用块。

spec 表的字段顺序：
  (number, module, name_cn, skip_attr_or_None, default, ret_shape)

ret_shape 决定 main() 中风险矩阵变量如何绑定：
  - "none" / "framework_confidence" — 无返回值绑定
  - "optional_int" — 绑到 ``injection``
  - "bool" — 绑到 ``leaked``
  - "optional_bool" — 绑到 ``overridden``
  - "detected_inconclusive" — 解构成 (substitution_detected, substitution_inconclusive)
  - "severity_inconclusive" — 解构成 (err_severity, err_inconclusive)
  - "verdict_inconclusive" — 解构成 (stream_verdict, stream_inconclusive)
  - "summary" — Step 14-19 返回的 summary dict，绑到 ``<module_var>_summary``
                （module 变量名与下划线 _summary 后缀拼接，便于 main.py 直接
                 读 ``bindings["long_task_summary"]`` 等）
"""
from __future__ import annotations

import sys
import traceback
from typing import Any, Callable


def _load_specs():
    # Imports kept inside the function to defer side-effects (any
    # step_NN_*.py module-level work) until registry is actually used.
    import step_01_infrastructure
    import step_02_models
    import step_03_token_injection
    import step_04_prompt_extraction
    import step_05_instruction_conflict
    import step_06_jailbreak
    import step_07_context_length
    import step_08_tool_substitution
    import step_09_error_leakage
    import step_10_stream_integrity
    import step_11_infra_fingerprint
    import step_12_latency_variance
    import step_13_channel_classifier
    import step_14_long_task
    import step_15_billing
    import step_16_api_consistency
    import step_17_model_fingerprint
    import step_18_tls
    import step_19_probe_randomization

    return [
        # (N, module, name_cn, skip_attr, default, ret_shape)
        (1,  step_01_infrastructure,         "基础设施侦察",          "skip_infra",            None,                 "none"),
        (2,  step_02_models,                 "模型列表",              None,                    None,                 "none"),
        (3,  step_03_token_injection,        "令牌注入检测",          None,                    None,                 "optional_int"),
        (4,  step_04_prompt_extraction,      "提示词提取测试",        None,                    False,                "bool"),
        (5,  step_05_instruction_conflict,   "指令冲突测试",          None,                    None,                 "optional_bool"),
        (6,  step_06_jailbreak,              "越狱测试",              None,                    None,                 "none"),
        (7,  step_07_context_length,         "上下文长度测试",        "skip_context",          None,                 "none"),
        (8,  step_08_tool_substitution,      "工具调用替换测试 (AC-1.a)", "skip_tool_substitution", (False, True),    "detected_inconclusive"),
        (9,  step_09_error_leakage,          "错误响应泄露测试 (AC-2)", "skip_error_leakage",   ("none", True),       "severity_inconclusive"),
        (10, step_10_stream_integrity,        "流完整性测试",          "skip_stream_integrity", ("clean", True),      "verdict_inconclusive"),
        (11, step_11_infra_fingerprint,       "基础设施指纹",          "skip_infra_fingerprint", (None, "unknown"),   "framework_confidence"),
        (12, step_12_latency_variance,        "延迟方差分析",          "skip_latency_variance", None,                 "none"),
        (13, step_13_channel_classifier,      "上游通道分类",          "skip_channel_classifier", None,               "none"),
        # Steps 14-19: companion sub-checks. ret_shape "summary" tells
        # _bind() to write the returned dict into a key derived from the
        # module's __name__ (e.g. step_14_long_task -> "long_task_summary").
        (14, step_14_long_task,              "长任务/多请求完整性",     "skip_long_task",        None,                 "summary"),
        (15, step_15_billing,                "计费/用量完整性",        "skip_billing",          None,                 "summary"),
        (16, step_16_api_consistency,        "API 一致性/静默降级",    "skip_api_consistency",  None,                 "summary"),
        (17, step_17_model_fingerprint,      "模型替换/伪造指纹",      "skip_model_fingerprint", None,                "summary"),
        (18, step_18_tls,                    "传输层安全 (TLS)",       "skip_tls",              None,                 "summary"),
        (19, step_19_probe_randomization,    "审计规避对抗",          "skip_probe_randomization", None,               "summary"),
    ]


# Module-level step specs are loaded lazily to break the import cycle:
# main.py imports this module for run_registered_steps; several step_NN_*.py
# modules import main directly (for APIClient / StreamSignals). If we
# pre-built the spec table at import time, the cycle would fire before
# either side finished initializing.
_STEPS: list[tuple] | None = None


def _get_steps() -> list[tuple]:
    global _STEPS
    if _STEPS is None:
        _STEPS = _load_specs()
    return _STEPS


def _step_name_cn_map() -> dict[int, str]:
    return {n: name for (n, _, name, *_) in _get_steps()}


def _step_modules_map() -> dict[int, Any]:
    return {n: mod for (n, mod, *_) in _get_steps()}


def _step_run_map() -> dict[int, Callable]:
    return {n: mod.run for (n, mod, *_) in _get_steps()}


def _run_step(name: str, reporter, step_fn: Callable, *args, default=None,
              crashes: list | None = None, **kwargs) -> Any:
    """Fail-open wrapper — identical semantics to the original engine.py
    function at lines 6379-6409. A single step crashing must not lose
    the output of all the others; the crashed step's name is appended
    to ``crashes`` so the risk-matrix can add a catch-all MEDIUM
    escalation.

    ``**kwargs`` are forwarded to ``step_fn`` so each step's run() can
    accept its own per-call options (fast_mode / args / probe_count)
    without _run_step having to know about them.

    注：前置期崩溃（h2 之前抛异常）导致该步不发 step 事件的问题，
    不在此处补救——串行调度下上一步未关闭，has_current_step 恒真，
    无法干净判断。改由 run_registered_steps 末尾用 reporter.ensure_step
    对漏发编号统一补占位终态。
    """
    try:
        return step_fn(*args, **kwargs)
    except KeyboardInterrupt:
        raise
    except Exception as e:
        exc_type = type(e).__name__
        print(f"\n[{name}] CRASHED: {exc_type}: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        if crashes is not None:
            crashes.append(name)
        try:
            reporter.flag(
                "yellow",
                f"{name} crashed mid-step: {exc_type}: {e} "
                "(continued with inconclusive default)",
            )
        except Exception:
            pass  # Reporter itself is broken; stderr already has the trace
        return default


def _kwargs_for_step(n: int, args) -> dict:
    """Build the kwargs needed by step ``n``'s ``run()`` signature."""
    if n == 7:
        return {"fast_mode": args.fast_context}
    if n == 9:
        return {"args": args}
    if n == 12:
        return {"probe_count": args.latency_probe_count}
    return {}


def _bind(n: int, mod, ret: Any, bindings: dict) -> None:
    """Write step ``n``'s return value into the main()-side bindings dict
    using the ret_shape convention declared in the spec table.

    ``mod`` is the step's module object — needed to derive the summary
    binding key for Steps 14-19 (``step_14_long_task`` →
    ``bindings["long_task_summary"]``).
    """
    if ret is None:
        return
    if n == 3:
        bindings["injection"] = ret
    elif n == 4:
        bindings["leaked"] = ret
    elif n == 5:
        bindings["overridden"] = ret
    elif n == 8:
        bindings["substitution_detected"], bindings["substitution_inconclusive"] = ret
    elif n == 9:
        bindings["err_severity"], bindings["err_inconclusive"] = ret
    elif n == 10:
        bindings["stream_verdict"], bindings["stream_inconclusive"] = ret
    elif 14 <= n <= 19 and isinstance(ret, dict):
        # Derive ``long_task_summary`` / ``billing_summary`` / etc. from the
        # module's bare name (strip the ``step_NN_`` prefix).
        bare = mod.__name__.split("_", 2)[-1]   # e.g. "long_task"
        bindings[f"{bare}_summary"] = ret
    # 11/12/13 — informational, no binding needed


def run_registered_steps(*, args, client, report, step_crashes: list) -> dict:
    """Run all 19 audit steps (1-13 in-line + 14-19 companions) per ``args``.

    Returns a ``bindings`` dict with the keys main()'s risk-matrix
    roll-up reads: ``injection`` / ``leaked`` / ``overridden`` /
    ``substitution_*`` / ``err_*`` / ``stream_*`` (Steps 1-14)
    plus ``long_task_summary`` / ``billing_summary`` / etc. (Steps 15-20).
    run_stdin() ignores the return value (it only cares about step_crashes
    and SSE events).
    """
    bindings: dict = {}
    total = len(_get_steps())
    for n, mod, name_cn, skip_attr, default, _ret_shape in _get_steps():
        if skip_attr and getattr(args, skip_attr, False):
            print(f"[{n}/{total}] {name_cn} (skipped)")
            continue
        print(f"[{n}/{total}] {name_cn}...")
        kwargs = _kwargs_for_step(n, args)
        ret = _run_step(
            f"Step {n} {name_cn}",
            report,
            mod.run,
            client,
            report,
            **kwargs,
            default=default,
            crashes=step_crashes,
        )
        _bind(n, mod, ret, bindings)
    # 漏发补齐：对 1..total 中从未发过 step 事件的编号补一个 warn 占位
    # 终态（前置期崩溃/被 skip 的步），保证前端 steps 与 totalSteps 对齐、
    # 进度条能到满。已正常发过 h2 的编号 ensure_step 内部跳过。
    for n, _, name_cn, *_ in _get_steps():
        report.ensure_step(n, name_cn)
    return bindings


# Backwards-compatible lazy accessors. Older code / tests that imported
# ``STEPS_1_14`` / ``STEP_NAME_CN`` etc. continue to work — they just
# trigger the spec load on first access.
def __getattr__(name):
    if name == "STEPS_1_14":
        # Legacy alias — pre-Step-15 callers may still reference this.
        return _get_steps()
    if name == "STEPS":
        return _get_steps()
    if name == "STEP_NAME_CN":
        return _step_name_cn_map()
    if name == "STEP_MODULES":
        return _step_modules_map()
    if name == "STEP_RUN":
        return _step_run_map()
    raise AttributeError(f"module 'step_registry' has no attribute {name!r}")
