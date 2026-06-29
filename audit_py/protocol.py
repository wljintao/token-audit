"""审计协议层。

集中处理向 stdout 输出 NDJSON 事件（每个 AuditEvent 一行）的细节：
序列化、行缓冲、立即 flush。所有事件发射都必须经 emit()，避免漏 flush
导致前端 SSE 拿不到实时流。

事件契约与 server/src/types.ts 的 AuditEvent 联合类型严格对齐，前端
(client/src/composables/useAudit.ts) 按 `data:` 行 JSON.parse 后 switch
(ev.type) 渲染，字段缺失/类型不符会静默跳过 —— 因此本文件严格约束类型。
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any, TypedDict


# AuditStep.status 枚举（与 types.ts 的 AuditStepStatus 一致）
STEP_RUNNING = "running"
STEP_PASS = "pass"
STEP_WARN = "warn"
STEP_FAIL = "fail"

# log.level 枚举（与 types.ts 一致）
LOG_INFO = "info"
LOG_WARN = "warn"
LOG_ERROR = "error"


class Step(TypedDict, total=False):
    """与 types.ts 的 AuditStep 对齐。ts 必须是 int 毫秒时间戳。"""

    id: str
    label: str
    status: str
    detail: str
    data: Any
    ts: int


def ts() -> int:
    """JS epoch 毫秒整数（不能是 float，否则 JSON 带小数点，前端 ts 字段不符）。"""
    return int(time.time() * 1000)


def _configure_stdio() -> None:
    """管道（非 TTY）下 stdout 默认块缓冲，必须改为行缓冲，否则前端收不到实时流。"""
    try:
        sys.stdout.reconfigure(line_buffering=True)  # type: ignore[attr-defined]
    except Exception:
        pass  # 老版本或重定向流不支持 reconfigure，靠 emit() 显式 flush 兜底
    try:
        sys.stderr.reconfigure(line_buffering=True)  # type: ignore[attr-defined]
    except Exception:
        pass


# 捕获真实的 stdout（进程管道）。run_stdin() 会把 sys.stdout 重定向到
# stderr，让业务代码的 print() 进 stderr（TS 收集不转发前端），而 emit()
# 仍写真实 stdout 输出 NDJSON。必须在任何重定向之前捕获。
_REAL_STDOUT = sys.stdout


def bind_stdout(stream) -> None:
    """让 emit 写到指定流。run_stdin 用它把 emit 绑到真实 stdout，
    再把 sys.stdout 重新赋给 stderr 以吸收业务 print。"""
    global _REAL_STDOUT
    _REAL_STDOUT = stream


# 一旦真实 stdout 关闭（消费端断连），后续 emit 全部静默跳过，
# 避免反复抛 BrokenPipeError 刷屏 stderr。
_STDOUT_CLOSED = False


def emit(event: dict[str, Any]) -> None:
    """写一个 NDJSON 事件行到真实 stdout 并立即 flush。

    用 _REAL_STDOUT 而非 sys.stdout，这样即便 run_stdin 把 sys.stdout
    重定向到 stderr（吸收业务 print），NDJSON 仍只走真实 stdout。
    若真实 stdout 已关闭（BrokenPipe），静默跳过不抛异常。
    """
    global _STDOUT_CLOSED
    if _STDOUT_CLOSED:
        return
    try:
        _REAL_STDOUT.write(json.dumps(event, ensure_ascii=False) + "\n")
        _REAL_STDOUT.flush()
    except (BrokenPipeError, ValueError, OSError):
        _STDOUT_CLOSED = True


# ── 事件构造器：集中约束字段名与类型，避免散落各处写错 ───────────────

def build_start(title: str, total_steps: int) -> dict[str, Any]:
    return {"type": "start", "title": title, "totalSteps": total_steps}


def build_step(
    sid: str,
    label: str,
    status: str,
    *,
    detail: str | None = None,
    data: Any = None,
    duration_ms: int | None = None,
) -> dict[str, Any]:
    step: dict[str, Any] = {"id": sid, "label": label, "status": status, "ts": ts()}
    if detail is not None:
        step["detail"] = detail
    if data is not None:
        step["data"] = data
    if duration_ms is not None:
        step["durationMs"] = duration_ms
    return {"type": "step", "step": step}


def build_log(message: str, level: str = LOG_INFO, *, step_id: str | None = None) -> dict[str, Any]:
    """构造 log 事件。

    step_id 为当前所属 step 的 id（EventReporter._cur_id），让前端能把
    日志挂到对应节点下。无归属（如 warmup 段，h2 之前）时传 None，
    不写 stepId 键，保持与旧契约一致，前端归入全局兜底区。
    """
    ev: dict[str, Any] = {"type": "log", "message": message, "level": level}
    if step_id is not None:
        ev["stepId"] = step_id
    return ev


def build_done(passed: int, warned: int, failed: int, duration_ms: int) -> dict[str, Any]:
    return {
        "type": "done",
        "passed": passed,
        "warned": warned,
        "failed": failed,
        "durationMs": duration_ms,
    }


def build_error(message: str) -> dict[str, Any]:
    return {"type": "error", "message": message}


def build_report(file: str) -> dict[str, Any]:
    """构造 report 事件：通知前端整体 Markdown 报告已落盘的文件名。

    只传文件名（如 ``report_example_202606291621.md``），不传服务器绝对路径，
    避免暴露文件系统结构；前端据此调 ``/api/report/<file>`` 下载。
    """
    return {"type": "report", "file": file}


def log_stderr(message: str) -> None:
    """写诊断日志到 stderr（TS 端收集但不转发前端）。"""
    sys.stderr.write(message.rstrip("\n") + "\n")
    sys.stderr.flush()


# 启动即配置行缓冲
_configure_stdio()
