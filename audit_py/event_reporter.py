"""EventReporter —— 把 markdown Reporter 接口适配成 NDJSON 事件流。

设备的审计引擎（engine.py）和 6 个子模块都通过 `report.h2/h3/p/code/flag`
这样的统一接口输出结果（原本写进 markdown 报告）。本类实现同样的接口，
但把每次调用实时映射成 AuditEvent，经 protocol.emit() 写到 stdout，
供 TS 端 runner.ts 逐行解析后经 SSE 推给前端。

事件契约见 protocol.py / server/src/types.ts，前端 useAudit.ts 按
`data:` 行 JSON.parse 后 switch(ev.type) 渲染，字段缺失/类型不符会
静默跳过 —— 因此本类严格约束字段。

状态机要点：
  - h2 开新 step(running)；开新 step 前若旧 step 无 flag，先关闭成 pass。
  - 一个 h2 内多 flag：取最高严重度（red>yellow>green），不各开新 step
    （前端 upsertStep 按 id 原地更新，只留最后态）。
  - h3/p/code → log(info)；flag → 更新当前 step 态 + 一条 log。
  - flag 在 h2 之前（无当前 step）→ 路由成 log，不发 step。
  - 末尾 flush() 关闭最后一个未关闭 step，返回 (passed, warned, failed)。

除发事件外，本类还**并行累积**一份原始 Markdown 片段（_md_sections /
_md_summary），供 render_markdown() 在审计末尾渲染整体 Markdown 报告
落盘。累积层照 CLI 版 Reporter 的映射（h2→`##`、h3→`###`、p→原样段落、
code→围栏块、flag→图标+粗体），与事件层独立——事件层仍发 log/step 事件，
累积层保留 Markdown 结构（表格的 `|` 语法、代码块、子节标题等）。
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

import protocol
from protocol import (
    LOG_ERROR,
    LOG_INFO,
    LOG_WARN,
    STEP_FAIL,
    STEP_PASS,
    STEP_RUNNING,
    STEP_WARN,
    build_log,
    build_step,
    emit,
    ts,
)

# Reporter.flag 的 level（red/yellow/green）→ step status + log level。
# 严重度序：fail(red) > warn(yellow) > pass(green)。
_LEVEL_TO_STATUS = {
    "red": (STEP_FAIL, LOG_ERROR),
    "yellow": (STEP_WARN, LOG_WARN),
    "green": (STEP_PASS, LOG_INFO),
}
# 严重度数值，用于“取最高”比较。
_SEVERITY = {STEP_FAIL: 3, STEP_WARN: 2, STEP_PASS: 1, STEP_RUNNING: 0}

# level → 报告里的图标（与 CLI Reporter 一致）。
_LEVEL_ICON = {"red": "🔴", "yellow": "🟡", "green": "🟢"}

_H2_RE = re.compile(r"^\s*(\d+)\.\s*(.+)$")


def _slugify(text: str) -> str:
    """无编号 h2 的 id 生成：小写 + 非字母数字转连字符。"""
    s = re.sub(r"[^a-zA-Z0-9]+", "-", text.strip()).strip("-").lower()
    return s or "section"


def _fix_table_blanklines(md: str) -> str:
    """移除 Markdown 表格行之间的多余空行，使表格能正确渲染。

    p() 每条追加 '\\n'，render_markdown 用 '\\n'.join() 拼接，
    导致两个连续 p() 输出的表格行之间出现空行（\\n\\n）。
    空行在 Markdown 中会打断表格的连续性，使渲染器逐行显示而非表格格式。

    算法：逐行扫描，当上一行和下一行都以 '|' 开头时，跳过中间的空行。
    """
    lines = md.split("\n")
    out: list[str] = []
    prev_is_table = False
    for line in lines:
        is_table = line.lstrip().startswith("|")
        if line.strip() == "" and prev_is_table:
            # 可能是表格行间的空行——暂存，等下一行判定。
            # 如果下一行也是表格行，则跳过此空行；
            # 如果下一行不是表格行，则保留（正常的段落间距）。
            out.append(line)
        else:
            # 检查：是否要把 out 末尾的空行（暂存）删掉？
            if is_table and out and out[-1].strip() == "":
                # 前一行是空行，当前行是表格行 → 前面的空行是多余的，
                # 但要确认空行之前的一行也是表格行才删（避免误删 h2/h3 后的正常间距）。
                # 简化：只要 prev_is_table 且当前行也是表格行，删掉暂存空行。
                if prev_is_table:
                    out.pop()  # 删除暂存的空行
            out.append(line)
            prev_is_table = is_table
    return "\n".join(out)


class EventReporter:
    """实现 Reporter 全接口，把调用映射成 NDJSON 事件，并累积 Markdown 片段。

    替代 engine.py 原本的 Reporter 类 —— 业务代码（test_* / 6 子模块）
    完全不感知差异，只换注入对象。
    """

    def __init__(self, total_steps: int = 20) -> None:
        self._total_steps = total_steps
        # 当前 step 状态：None 表示尚无 h2 开过 step。
        self._cur_id: str | None = None
        self._cur_label: str = ""
        self._cur_status: str | None = None  # None=还没收到 flag
        # 当前 step 开始时刻（毫秒），用于算终态 durationMs。
        self._cur_start: int | None = None
        self._used_ids: set[str] = set()
        self._passed = 0
        self._warned = 0
        self._failed = 0
        # 报告累积层：原始 Markdown 片段（照 CLI Reporter 映射），render_markdown join。
        self._md_sections: list[str] = []
        # 风险摘要：(icon, msg) 列表，由 flag 累积，render_markdown 头部后输出。
        self._md_summary: list[tuple[str, str]] = []

    # -- 内部辅助 ---------------------------------------------------------

    def _cur_duration(self) -> int | None:
        """当前 step 从开始到现在的毫秒数；无当前 step 返回 None。"""
        if self._cur_start is None:
            return None
        return max(0, ts() - self._cur_start)

    def _close_current(self) -> None:
        """关闭当前 step：若无 flag 则计 pass 并发一个 pass 事件。"""
        if self._cur_id is None:
            return
        if self._cur_status is None:
            # 无 flag 的 step：视为通过（信息不足，不判 fail）。
            emit(build_step(self._cur_id, self._cur_label, STEP_PASS,
                            detail="(本项无明确结论)",
                            duration_ms=self._cur_duration()))
            self._passed += 1
        else:
            self._count(self._cur_status)
        self._cur_id = None
        self._cur_label = ""
        self._cur_status = None
        self._cur_start = None

    def _count(self, status: str) -> None:
        if status == STEP_PASS:
            self._passed += 1
        elif status == STEP_WARN:
            self._warned += 1
        elif status == STEP_FAIL:
            self._failed += 1

    def ensure_step(self, step_no: int, label: str) -> None:
        """对漏发 step 事件编号补一个占位终态。

        run_registered_steps 末尾对 1..total 逐个调用：若该编号从未开过
        h2（前置期崩溃、或被 skip 但仍想在前端留项），补开一个 h2 并
        直接 flag 成 warn（「本步未产出结果」），保证前端 steps 列表
        与 totalSteps 对齐、进度条能到满。已发过的编号跳过。
        """
        sid = f"step-{step_no}"
        if sid in self._used_ids:
            return
        self._new_step(f"{step_no}. {label}")
        # _new_step 已发 running；这里补一个 warn 终态 + 计数。
        self._cur_status = STEP_WARN
        emit(build_step(self._cur_id, self._cur_label, STEP_WARN,
                        detail="本步未产出结果（崩溃或被跳过）",
                        duration_ms=self._cur_duration()))
        emit(build_log("本步未产出结果（崩溃或被跳过）", LOG_WARN,
                        step_id=self._cur_id))
        self._warned += 1
        # 累积层：补一条 warn 结论（进 summary + sections）。
        self._md_summary.append((_LEVEL_ICON["yellow"], "本步未产出结果（崩溃或被跳过）"))
        self._md_sections.append(f'{_LEVEL_ICON["yellow"]} **本步未产出结果（崩溃或被跳过）**\n')
        # 已发终态，置空当前 step，避免下一个 ensure_step 的 _new_step
        # 经 _close_current 重复 _count 这一项。
        self._cur_id = None
        self._cur_label = ""
        self._cur_status = None
        self._cur_start = None

    def _new_step(self, raw_title: str) -> None:
        """开新 step：先关闭旧的，解析 id/label，发 running 事件。"""
        self._close_current()
        m = _H2_RE.match(raw_title)
        if m:
            base_id = "step-" + m.group(1)
            label = m.group(2).strip()
        else:
            base_id = _slugify(raw_title)
            label = raw_title.strip()
        # id 去重：撞 id 时加后缀 -b/-c/...
        sid = base_id
        suffix = ord("b")
        while sid in self._used_ids:
            sid = base_id + "-" + chr(suffix)
            suffix += 1
        self._used_ids.add(sid)
        self._cur_id = sid
        self._cur_label = label
        self._cur_status = None
        self._cur_start = ts()
        # 累积层：照 CLI Reporter，h2 → "## title"。
        self._md_sections.append(f"\n## {raw_title.strip()}\n")
        emit(build_step(sid, label, STEP_RUNNING))

    # -- Reporter 接口 ----------------------------------------------------

    def h1(self, t: str) -> None:
        """忽略：事件流的 title 已由 start 事件携带；累积层也不需要 h1。"""
        return None

    def h2(self, t: str) -> None:
        self._new_step(t)

    def h3(self, t: str) -> None:
        emit(build_log(t, LOG_INFO, step_id=self._cur_id))
        # 累积层：h3 → "### title"。
        self._md_sections.append(f"\n### {t}\n")

    def p(self, t: Any) -> None:
        msg = str(t)
        emit(build_log(msg, LOG_INFO, step_id=self._cur_id))
        # 累积层：原样段落（不加前缀，保留表格 | 语法）。
        self._md_sections.append(f"{msg}\n")

    def code(self, t: Any, lang: str = "") -> None:
        msg = f"[code] {t}"
        emit(build_log(msg, LOG_INFO, step_id=self._cur_id))
        # 累积层：围栏代码块。
        # 如果内容本身包含三反引号，用四反引号围栏避免嵌套冲突。
        text = str(t)
        fence_len = 3
        while "```" + ("`" * (fence_len - 3)) in text:
            fence_len += 1
        fence = "`" * fence_len
        self._md_sections.append(f"{fence}{lang}\n{text}\n{fence}\n")

    def flag(self, level: str, msg: str) -> None:
        status, log_level = _LEVEL_TO_STATUS.get(
            (level or "").lower(), (STEP_WARN, LOG_WARN)
        )
        icon = _LEVEL_ICON.get((level or "").lower(), "🟡")
        if self._cur_id is None:
            # flag 在任何 h2 之前（如 warmup 段）：路由成 log，不发 step，
            # 也不带 step_id（无归属，前端归入全局兜底区）。
            emit(build_log(f"[{level}] {msg}", log_level))
            # 累积层：warmup 等无 step 归属的 flag 也进 summary + sections。
            self._md_summary.append((icon, msg))
            self._md_sections.append(f"{icon} **{msg}**\n")
            return
        # 取最高严重度：新 flag 比当前态更严重才升级 status。
        if self._cur_status is None or _SEVERITY[status] > _SEVERITY[self._cur_status]:
            self._cur_status = status
        emit(build_step(self._cur_id, self._cur_label, self._cur_status,
                        detail=msg, duration_ms=self._cur_duration()))
        emit(build_log(msg, log_level, step_id=self._cur_id))
        # 累积层：图标 + 粗体结论（进 summary + sections）。
        self._md_summary.append((icon, msg))
        self._md_sections.append(f"{icon} **{msg}**\n")

    def render(self, target_url: str = "", model: str = "", **kw: Any) -> str:
        """事件流不需要 markdown 汇总，返回空串。

        engine.py 末尾仍可能调用 render()，这里不产出任何事件。
        整体报告改由 render_markdown() 单独生成。
        """
        return ""

    # -- 生命周期 ---------------------------------------------------------

    def flush(self) -> tuple[int, int, int]:
        """关闭最后一个未关闭 step，返回 (passed, warned, failed)。"""
        self._close_current()
        return self._passed, self._warned, self._failed

    # -- 整体 Markdown 报告 ----------------------------------------------

    def render_markdown(
        self,
        base_url: str,
        model: str,
        duration_ms: int,
        passed: int,
        warned: int,
        failed: int,
    ) -> str:
        """把累积的 _md_sections / _md_summary 渲染成整体 Markdown 报告。

        结构对齐 CLI 版样例：头部（目标/模型/耗时/统计）+ 风险摘要（逐条
        图标结论）+ 所有 step 的结构化明细（子节/段落/代码块/表格原样保留）。
        末尾的总体评级节由 emit_overall_rating() 经 report.p 注入 _md_sections。
        """
        lines: list[str] = []
        lines.append("# API 中转站安全审计报告")
        lines.append("")
        lines.append(f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        if base_url:
            lines.append(f"**目标**: `{base_url}`")
        if model:
            lines.append(f"**模型**: `{model}`")
        lines.append(f"**耗时**: {duration_ms / 1000:.1f}s")
        lines.append(
            f"**统计**: ✅ {passed} 通过 / ⚠️ {warned} 警告 / ❌ {failed} 失败"
        )
        lines.append("")
        lines.append("## 风险摘要")
        lines.append("")
        if self._md_summary:
            for icon, msg in self._md_summary:
                lines.append(f"- {icon} {msg}")
        else:
            lines.append("-（无结论性发现）")
        lines.append("")
        lines.append("---")
        lines.append("")
        # 各 step 的结构化明细 + 末尾总体评级节。
        # 逐片段拼接，再修复 Markdown 表格行间的多余空行：
        # p() 每行末尾带 \n，join 又插入 \n → 表格行间出现空行，
        # 导致表格无法在渲染器中正确预览。此处将连续的 | 开头行
        # 之间的空行压缩掉。
        raw = "\n".join(self._md_sections).strip()
        # _fix_table_blanklines: 连续 | 行之间的空行去掉。
        body = _fix_table_blanklines(raw)
        return "\n".join(lines) + "\n" + body + "\n"
