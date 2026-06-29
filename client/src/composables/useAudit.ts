import { computed, reactive, ref } from "vue";
import type {
  AuditEvent,
  AuditLog,
  AuditRequest,
  AuditStep,
  AuditSummary,
} from "../types";

export type AuditPhase = "idle" | "running" | "done" | "error";

export function useAudit() {
  const phase = ref<AuditPhase>("idle");
  const title = ref("");
  const totalSteps = ref(0);
  const steps = reactive<AuditStep[]>([]);
  const logs = ref<AuditLog[]>([]);
  const summary = ref<AuditSummary | null>(null);
  const errorMsg = ref<string | null>(null);
  // 本次审计落盘的报告文件名（由 report 事件携带，null=未生成/生成失败）。
  const reportFile = ref<string | null>(null);

  // 节点展开状态：仅记录用户手动 toggle 的覆盖项。
  // 默认行为由 status 派生（running 自动展开，完成即收起），这里只存用户
  // 在「已完成」节点上手动展开/收起的覆盖，点击 toggle 即写入。
  const expandedSteps = reactive<Record<string, boolean>>({});

  // 日志按 stepId 分桶：归属到具体节点的日志。
  const logsByStep = computed<Record<string, AuditLog[]>>(() => {
    const m: Record<string, AuditLog[]> = {};
    for (const l of logs.value) {
      if (!l.stepId) continue;
      (m[l.stepId] ??= []).push(l);
    }
    return m;
  });

  // 无归属日志（warmup 段，stepId 缺失）→ 全局兜底区。
  const globalLogs = computed<AuditLog[]>(() =>
    logs.value.filter((l) => !l.stepId),
  );

  function reset() {
    phase.value = "running";
    title.value = "";
    totalSteps.value = 0;
    steps.splice(0, steps.length);
    logs.value = [];
    summary.value = null;
    errorMsg.value = null;
    reportFile.value = null;
    // 全部清空重置：展开状态回到默认（running 展开/完成收起）。
    for (const k of Object.keys(expandedSteps)) delete expandedSteps[k];
  }

  function upsertStep(step: AuditStep) {
    const idx = steps.findIndex((s) => s.id === step.id);
    if (idx >= 0) steps[idx] = step;
    else steps.push(step);
  }

  function handleEvent(ev: AuditEvent) {
    switch (ev.type) {
      case "start":
        title.value = ev.title;
        totalSteps.value = ev.totalSteps;
        phase.value = "running";
        break;
      case "step":
        upsertStep(ev.step);
        break;
      case "log":
        logs.value.push({
          message: ev.message,
          level: ev.level ?? "info",
          ts: Date.now(),
          stepId: ev.stepId,
        });
        break;
      case "done":
        summary.value = {
          passed: ev.passed,
          warned: ev.warned,
          failed: ev.failed,
          durationMs: ev.durationMs,
        };
        phase.value = "done";
        break;
      case "report":
        reportFile.value = ev.file;
        break;
      case "error":
        errorMsg.value = ev.message;
        phase.value = "error";
        break;
    }
  }

  async function runAudit(req: AuditRequest): Promise<void> {
    reset();
    let res: Response;
    try {
      res = await fetch("/api/audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req),
      });
    } catch (e) {
      errorMsg.value = e instanceof Error ? e.message : String(e);
      phase.value = "error";
      return;
    }

    if (!res.ok || !res.body) {
      let detail = `${res.status || "error"}`;
      try {
        const j = (await res.json()) as { error?: string };
        if (j?.error) detail = j.error;
      } catch {
        /* ignore */
      }
      errorMsg.value = detail;
      phase.value = "error";
      return;
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let sep: number;
        while ((sep = buffer.indexOf("\n\n")) >= 0) {
          const chunk = buffer.slice(0, sep);
          buffer = buffer.slice(sep + 2);
          const dataLine = chunk
            .split("\n")
            .find((l) => l.startsWith("data:"));
          if (!dataLine) continue;
          try {
            handleEvent(JSON.parse(dataLine.slice(5).trim()) as AuditEvent);
          } catch {
            /* skip malformed event */
          }
        }
      }
    } catch (e) {
      errorMsg.value = e instanceof Error ? e.message : String(e);
      phase.value = "error";
      return;
    }

    // Stream ended without an explicit done/error event.
    if (phase.value === "running") {
      phase.value = "done";
    }
  }

  // 判断某节点日志框是否展开：
  // - running：自动展开（用户无需点）；完成节点默认保持展开（方便看到日志）。
  // - 用户可点击已完成节点收缩/展开 → expandedSteps[id] 记录覆盖。
  function isStepExpanded(step: AuditStep): boolean {
    if (step.status === "running") return true;
    return expandedSteps[step.id] === true;
  }

  // 点击节点切换展开：仅对有日志的节点有意义（无日志节点不应调用）。
  // running 节点自动展开，点击不收起（避免打断实时观看）；完成后 toggle 生效。
  // 默认完成节点展开（用户无需手动点开看日志），点击则收起；再点击展开。
  function toggleStep(id: string) {
    const currentlyExpanded = expandedSteps[id] !== false;
    expandedSteps[id] = !currentlyExpanded;
  }

  return {
    phase,
    title,
    totalSteps,
    steps,
    logs,
    summary,
    errorMsg,
    reportFile,
    expandedSteps,
    logsByStep,
    globalLogs,
    isStepExpanded,
    toggleStep,
    runAudit,
  };
}
