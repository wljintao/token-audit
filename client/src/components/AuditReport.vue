<script setup lang="ts">
import { computed, ref, watch, nextTick } from "vue";
import type { AuditLog, AuditStep, AuditStepStatus, AuditSummary } from "../types";
import { marked } from "marked";
import { apiUrl } from "../api";

const props = defineProps<{
  phase: "idle" | "running" | "done" | "error";
  title: string;
  totalSteps: number;
  steps: AuditStep[];
  logsByStep: Record<string, AuditLog[]>;
  globalLogs: AuditLog[];
  expandedSteps: Record<string, boolean>;
  summary: AuditSummary | null;
  errorMsg: string | null;
  reportFile: string | null;
}>();

const emit = defineEmits<{ (e: "toggle-step", id: string): void }>();

const completed = computed(() => {
  // done 后强制满：后端 ensure_step 已保证 19 项全有终态事件，
  // 但运行中可能因 SSE 抖动少计；done 时以 totalSteps 为权威。
  if (props.phase === "done") return props.totalSteps;
  return props.steps.filter(
    (s) => s.status !== "running" && s.status !== "pending",
  ).length;
});
const progress = computed(() =>
  props.totalSteps > 0 ? Math.round((completed.value / props.totalSteps) * 100) : 0,
);

const statusMeta: Record<AuditStepStatus, { icon: string; cls: string }> = {
  pending: { icon: "•", cls: "st--pending" },
  running: { icon: "", cls: "st--running" },
  pass: { icon: "✓", cls: "st--pass" },
  warn: { icon: "!", cls: "st--warn" },
  fail: { icon: "✕", cls: "st--fail" },
};

// 从 step.id（形如 "step-1"/"step-12"）提取序号；无法解析时回退到列表下标+1。
function stepNo(s: AuditStep, idx: number): number {
  const m = /step-(\d+)/.exec(s.id);
  if (m) return Number(m[1]);
  return idx + 1;
}

// 毫秒耗时格式化：<1s 显示 ms，否则显示 s（保留一位小数）。
function fmtDuration(ms?: number): string {
  if (ms == null) return "";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

// summary 总耗时格式化：转秒 + 千位分隔符，保留两位小数。
function fmtSeconds(ms?: number): string {
  if (ms == null) return "0s";
  const s = ms / 1000;
  return `${s.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}s`;
}

// 该节点是否有日志（无日志则不显示展开按钮、点击无反应）。
function hasLogs(s: AuditStep): boolean {
  return (props.logsByStep[s.id]?.length ?? 0) > 0;
}
function stepLogs(s: AuditStep): AuditLog[] {
  return props.logsByStep[s.id] ?? [];
}
// 展开判定：running 自动展开；完成节点默认保持展开（方便看到结果日志），
// 用户可点击收缩/展开。无日志节点始终不展示展开区域。
function isExpanded(s: AuditStep): boolean {
  // undefined = never toggled → expanded (default); false = user collapsed; true = user expanded.
  if (!hasLogs(s)) return false;
  return s.status === "running" || props.expandedSteps[s.id] !== false;
}
function onStepClick(s: AuditStep): void {
  // 无日志节点点击无反应。
  if (!hasLogs(s)) return;
  // running 节点自动展开，点击不收起，避免打断实时观看。
  if (s.status === "running") return;
  emit("toggle-step", s.id);
}

// ── 自动滚动：每个展开节点的日志框 + 全局日志框，新日志到底 ──────
const globalLogRef = ref<HTMLElement | null>(null);
const logBoxRefs = ref<Record<string, HTMLElement | null>>({});
function setLogBoxRef(id: string) {
  return (el: Element | { $el?: Element } | null) => {
    const node = el instanceof Element ? el : el?.$el ?? null;
    logBoxRefs.value[id] = node as HTMLElement | null;
  };
}

const totalStepLogs = computed(() =>
  Object.values(props.logsByStep).reduce((n, a) => n + a.length, 0),
);

async function scrollAll() {
  await nextTick();
  if (globalLogRef.value) {
    globalLogRef.value.scrollTop = globalLogRef.value.scrollHeight;
  }
  for (const id in logBoxRefs.value) {
    const el = logBoxRefs.value[id];
    if (el) el.scrollTop = el.scrollHeight;
  }
}

// 日志数变化（running 节点新增日志）或用户展开节点 → 滚到底。
watch(() => totalStepLogs.value, scrollAll);
watch(() => props.globalLogs.length, scrollAll);
watch(() => props.expandedSteps, scrollAll, { deep: true });

// ── 报告预览弹窗 ──────────────────────────────────────
const showModal = ref(false);
const reportContent = ref("");
const loadingContent = ref(false);

async function openReport() {
  if (!props.reportFile) return;
  showModal.value = true;
  loadingContent.value = true;
  reportContent.value = "";
  try {
    const res = await fetch(apiUrl(`/api/report/${encodeURIComponent(props.reportFile)}`));
    if (!res.ok) {
      reportContent.value = `**加载失败**：服务器返回 ${res.status}`;
      return;
    }
    reportContent.value = await res.text();
  } catch (e) {
    reportContent.value = `**加载失败**：${e instanceof Error ? e.message : String(e)}`;
  } finally {
    loadingContent.value = false;
  }
}

function closeModal() {
  showModal.value = false;
  reportContent.value = "";
}

function downloadReport() {
  if (!props.reportFile) return;
  const a = document.createElement("a");
  a.href = apiUrl(`/api/report/${encodeURIComponent(props.reportFile)}`);
  a.download = props.reportFile;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function renderedContent(): string {
  if (!reportContent.value) return "";
  try {
    return marked.parse(reportContent.value) as string;
  } catch {
    return reportContent.value;
  }
}
</script>

<template>
  <div class="report">
    <div v-if="phase === 'idle'" class="report__empty">
      填写左侧表单并点击「审计」，结果将在此实时呈现。
    </div>

    <template v-else>
      <div class="report__head">
        <h3>{{ title || (phase === 'running' ? '正在启动审计…' : '审计结果') }}</h3>
        <div class="report__actions">
          <span v-if="phase === 'running'" class="badge badge--run">
            <span class="dot" />运行中
          </span>
          <template v-else-if="phase === 'done'">
            <span class="badge badge--done">已完成</span>
            <button class="btn-download" @click="openReport">查看报告</button>
          </template>
          <span v-else class="badge badge--err">出错</span>
        </div>
      </div>

      <div class="progress">
        <div class="progress__bar" :style="{ width: progress + '%' }" />
      </div>
      <div class="progress__meta">{{ completed }}/{{ totalSteps }} 项 · {{ progress }}%</div>

      <div v-if="summary" class="summary summary--top">
        <div class="summary__item s-fail">高危 <b>{{ summary.failed }}</b></div>
        <div class="summary__item s-warn">中危 <b>{{ summary.warned }}</b></div>
        <div class="summary__item s-pass">通过 <b>{{ summary.passed }}</b></div>
        <div class="summary__item">耗时 <b>{{ fmtSeconds(summary.durationMs) }}</b></div>
      </div>

      <ul class="steps">
        <li
          v-for="(s, idx) in steps"
          :key="s.id"
          class="step"
          :class="[statusMeta[s.status].cls, { 'step--expandable': hasLogs(s) }]"
        >
          <div class="step__row" @click="onStepClick(s)">
            <span class="step__icon">
              <span class="step__no">{{ stepNo(s, idx) }}</span>
              <span v-if="s.status === 'running'" class="spinner" />
            </span>
            <div class="step__body">
              <div class="step__label">{{ s.label }}</div>
              <div v-if="s.detail" class="step__detail">{{ s.detail }}</div>
            </div>
            <span v-if="s.durationMs != null && s.status !== 'running'" class="step__dur">
              {{ fmtDuration(s.durationMs) }}
            </span>
            <span
              v-if="hasLogs(s)"
              class="step__chevron"
              :class="{ 'is-open': isExpanded(s) }"
              aria-hidden="true"
            >▾</span>
          </div>

          <div v-if="hasLogs(s) && isExpanded(s)" class="terminal terminal--step">
            <div class="terminal__bar">
              <span class="terminal__dot terminal__dot--r" />
              <span class="terminal__dot terminal__dot--y" />
              <span class="terminal__dot terminal__dot--g" />
              <span class="terminal__name">{{ s.label }}</span>
            </div>
            <div class="logs logs--step" :ref="setLogBoxRef(s.id)">
              <div
                v-for="(l, i) in stepLogs(s)"
                :key="i"
                class="log"
                :class="'log--' + l.level"
              >
                <span class="log__time">{{ new Date(l.ts).toLocaleTimeString() }}</span>
                <span class="log__msg">{{ l.message }}</span>
              </div>
            </div>
          </div>
        </li>
      </ul>

      <div v-if="errorMsg" class="report__error">{{ errorMsg }}</div>

      <!-- 报告预览弹窗 -->
      <Teleport to="body">
        <div v-if="showModal" class="report-modal" @click.self="closeModal">
          <div class="report-modal__overlay" @click="closeModal" />
          <div class="report-modal__panel">
            <div class="report-modal__head">
              <h3>{{ reportFile }}</h3>
              <div class="report-modal__actions">
                <button class="report-modal__btn report-modal__btn--download" @click="downloadReport">
                  ⬇ 下载
                </button>
                <button class="report-modal__btn" @click="closeModal">✕</button>
              </div>
            </div>
            <div class="report-modal__body">
              <div v-if="loadingContent" class="report-modal__loading">
                <span class="spinner" /> 加载报告中…
              </div>
              <div v-else-if="reportContent" v-html="renderedContent()" />
            </div>
          </div>
        </div>
      </Teleport>
    </template>
  </div>
</template>
