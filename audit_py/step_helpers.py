"""跨步骤共享的辅助函数（C 类）。

供 14 个 stepN_*.py 共同使用，包括：
- 错误诊断渲染（format_diagnosis / _diagnosis_for_error / _report_error）
- Claude Code 客户端门识别（_looks_like_claude_code_client_gate）

错误诊断**引擎**（diagnose_error / _HTTP_STATUS_RE / _coerce_status /
_status_from_error / _diagnosis）继续留在 main.py，因为 APIClient 和
run_connectivity_check 还要直接使用。
"""
from __future__ import annotations

# 延迟导入避免循环：main.py 自身也要 import 本模块。具体的
# diagnose_error / format_diagnosis 会在 _diagnosis_for_error /
# _report_error 第一次被调用时通过 ``main`` 模块解析。sys.modules
# 在 import 完成时已经包含 main，所以函数内 import 是零成本的。


def _resolve_engine_helpers():
    """解析 main 侧的 diagnose_error / format_diagnosis，延迟加载 + 缓存。"""
    global _DIAGNOSIS_FNS
    if _DIAGNOSIS_FNS is not None:
        return _DIAGNOSIS_FNS
    import main
    _DIAGNOSIS_FNS = (main.diagnose_error, main.format_diagnosis)
    return _DIAGNOSIS_FNS


# 延迟模块级代理。``from step_helpers import format_diagnosis`` 会捕获这些
# 可调用对象；每次调用首次解析 main 模块，之后即一行派发。避免顶层
# ``from main import format_diagnosis`` 带来的循环 import。
_DIAGNOSIS_FNS = None


def diagnose_error(error, status=None):
    """``main.diagnose_error`` 的延迟代理。"""
    de, _ = _resolve_engine_helpers()
    return de(error, status=status)


def format_diagnosis(diagnosis):
    """``main.format_diagnosis`` 的延迟代理（把诊断 dict 渲染成一行紧凑 Markdown）。"""
    _, fd = _resolve_engine_helpers()
    return fd(diagnosis)


def _diagnosis_for_error(error, status=None):
    """返回对某个错误最贴切的用户可见诊断。"""
    diagnose_error, _ = _resolve_engine_helpers()
    return diagnose_error(error, status=status)


def _report_error(report, error, status=None):
    """渲染一行简短错误 + 一条运维诊断。

    诊断仅供参考：帮助用户修复认证、模型、端点、配额或网络问题，但
    不影响风险矩阵。
    """
    _, format_diagnosis = _resolve_engine_helpers()
    report.p(f"Error: {error}")
    report.p(format_diagnosis(_diagnosis_for_error(error, status=status)))


def _looks_like_claude_code_client_gate(error) -> bool:
    """当错误串看起来像 Claude Code 专属门时返回 True。

    某些中转把 ``/v1/models`` 开放给普通 API token，但对 ``/v1/messages``
    要求调用方是真正的 Claude Code 客户端。我们刻意**不**冒充 Claude Code
    请求头（按 ROADMAP / CLAUDE.md 不在范围内）；转而把受影响的步骤降级
    为诚实的 inconclusive 判定。
    """
    if not error:
        return False
    text = str(error).lower()
    return (
        "claude code" in text
        and "client" in text
        and ("only allow" in text or "only allows" in text)
    )
