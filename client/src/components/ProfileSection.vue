<script setup lang="ts">
// 19 项审计能力定义：英文名、中文名、风险等级、mock 检测值
const capabilities = [
  { id: 1, nameEn: "Infrastructure Recon", nameCn: "基础设施侦察", risk: "pass" as const, detail: "CDN: Cloudflare, WAF: none" },
  { id: 2, nameEn: "Model List", nameCn: "模型列表", risk: "pass" as const, detail: "3 models: gpt-4o, gpt-4o-mini, o3" },
  { id: 3, nameEn: "Token Injection", nameCn: "令牌注入检测", risk: "warn" as const, detail: "+80 tokens injected" },
  { id: 4, nameEn: "Prompt Extraction", nameCn: "提示词提取测试", risk: "warn" as const, detail: "2/6 methods succeeded" },
  { id: 5, nameEn: "Instruction Conflict", nameCn: "指令冲突测试", risk: "pass" as const, detail: "System prompt preserved" },
  { id: 6, nameEn: "Jailbreak", nameCn: "越狱测试", risk: "pass" as const, detail: "All 4 jailbreak attempts blocked" },
  { id: 7, nameEn: "Context Length", nameCn: "上下文长度测试", risk: "pass" as const, detail: "~200K tokens OK" },
  { id: 8, nameEn: "Tool-Call Substitution (AC-1.a)", nameCn: "工具调用替换测试", risk: "pass" as const, detail: "5/5 tool calls intact" },
  { id: 9, nameEn: "Error Leakage (AC-2)", nameCn: "错误响应泄露测试", risk: "pass" as const, detail: "No internal details leaked" },
  { id: 10, nameEn: "Stream Integrity", nameCn: "流完整性测试", risk: "pass" as const, detail: "SSE stream complete, no tampering" },
  { id: 11, nameEn: "Infrastructure Fingerprint", nameCn: "基础设施指纹", risk: "warn" as const, detail: "Multi-domain shared cert detected" },
  { id: 12, nameEn: "Latency Variance", nameCn: "延迟方差分析", risk: "pass" as const, detail: "σ=12ms, consistent with direct API" },
  { id: 13, nameEn: "Upstream Channel Classifier", nameCn: "上游通道分类", risk: "pass" as const, detail: "Classified: OpenAI-compatible" },
  { id: 14, nameEn: "Long-Task Integrity", nameCn: "长任务/多请求完整性", risk: "pass" as const, detail: "3 long tasks completed intact" },
  { id: 15, nameEn: "Billing / Usage Integrity", nameCn: "计费/用量完整性", risk: "fail" as const, detail: "Token count inflated +15%" },
  { id: 16, nameEn: "API Consistency / Silent Degradation", nameCn: "API 一致性/静默降级", risk: "pass" as const, detail: "All endpoints consistent" },
  { id: 17, nameEn: "Model Fingerprint / Spoofing", nameCn: "模型替换/伪造指纹", risk: "fail" as const, detail: "Custom system prompt causes 422" },
  { id: 18, nameEn: "Transport Layer Security (TLS)", nameCn: "传输层安全 (TLS)", risk: "pass" as const, detail: "TLS 1.3, HSTS enabled" },
  { id: 19, nameEn: "Audit Evasion Resistance", nameCn: "审计规避对抗", risk: "pass" as const, detail: "Probe randomization not detected" },
];

const riskMeta: Record<string, { dot: string; label: string; cls: string }> = {
  pass: { dot: "🟢", label: "通过", cls: "res--ok" },
  warn: { dot: "🟡", label: "中危", cls: "res--warn" },
  fail: { dot: "🔴", label: "高危", cls: "res--err" },
};
</script>

<template>
  <section id="profile" class="screen">
    <header class="section__head">
      <h2>
        <span class="dot-live" />
        报告画像
      </h2>
      <p>19 项审计能力概览，覆盖从基础设施到模型行为的全面检测。</p>
    </header>

    <div class="profile-card">
      <!-- 顶部橙色条 -->
      <div class="profile-card__stripe" />

      <div class="profile-card__inner">
        <!-- 头部 -->
        <div class="profile-card__header">
          <div>
            <h3 class="profile-card__domain">example.com</h3>
            <span class="profile-card__version">Token审计报告</span>
          </div>
        </div>

        <!-- 汇总卡片 -->
        <div class="profile-card__stats">
          <div class="stat-card">
            <div class="stat-card__label">令牌注入</div>
            <div class="stat-card__value val--warn">+80 tokens</div>
            <div class="stat-card__sub">注入（Claude Code CLI 身份）</div>
          </div>
          <div class="stat-card">
            <div class="stat-card__label">提示词提取</div>
            <div class="stat-card__value val--warn">2/6 extracted</div>
            <div class="stat-card__sub">翻译与 JSON 续写方法</div>
          </div>
          <div class="stat-card">
            <div class="stat-card__label">上下文长度</div>
            <div class="stat-card__value val--ok">~200K</div>
            <div class="stat-card__sub">最大上下文窗口</div>
          </div>
          <div class="stat-card">
            <div class="stat-card__label">风险项</div>
            <div class="stat-card__value val--err">2</div>
            <div class="stat-card__sub">共发现问题数</div>
          </div>
        </div>

        <!-- 19 项能力表格 -->
        <table class="profile-card__table">
          <thead>
            <tr>
              <th class="col--num">#</th>
              <th class="col--en">Point</th>
              <th class="col--cn">中文名</th>
              <th class="col--result">结果</th>
              <th class="col--detail">详情</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="cap in capabilities" :key="cap.id">
              <td class="col--num">{{ String(cap.id).padStart(2, "0") }}</td>
              <td class="col--en">{{ cap.nameEn }}</td>
              <td class="col--cn">{{ cap.nameCn }}</td>
              <td class="col--result">
                <span class="profile-card__result" :class="riskMeta[cap.risk].cls">
                  {{ riskMeta[cap.risk].dot }} {{ riskMeta[cap.risk].label }}
                </span>
              </td>
              <td class="col--detail">{{ cap.detail }}</td>
            </tr>
          </tbody>
        </table>

        <!-- 总结框 -->
        <div class="profile-card__summary">
          注入约 80 个 Claude Code CLI Tokens。Translation 与 JSON 续写方法可提取提示词。上下文 ~200K tokens 完整。
        </div>

        <!-- 风险标签 -->
        <div class="profile-card__tags">
          <span class="profile-card__tag">隐藏系统提示词 ~80 tokens</span>
          <span class="profile-card__tag">多域名共享证书</span>
          <span class="profile-card__tag">自定义系统提示词导致 422 冲突</span>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
/* ── 报告卡片 ── */
.profile-card {
  position: relative;
  background: rgba(255, 255, 255, 0.02);
  border: 1px solid var(--border);
  border-radius: 12px;
  overflow: hidden;
  margin-top: 20px;
}

.profile-card__stripe {
  height: 3px;
  background: linear-gradient(90deg, #f59e0b, #f97316);
}

.profile-card__inner {
  padding: 28px 32px 24px;
}

/* 头部 */
.profile-card__header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  margin-bottom: 24px;
}

.profile-card__domain {
  font-family: var(--mono);
  font-size: 1.35rem;
  font-weight: 700;
  color: var(--text-strong);
  margin: 0 0 4px;
}

.profile-card__version {
  font-size: 0.82rem;
  color: var(--muted);
}

.profile-card__risk {
  font-family: var(--mono);
  font-size: 0.78rem;
  font-weight: 700;
  padding: 6px 16px;
  border-radius: 999px;
  letter-spacing: 0.04em;
  white-space: nowrap;
}

.risk--high {
  color: #f87171;
  border: 1px solid rgba(248, 113, 113, 0.4);
  background: rgba(248, 113, 113, 0.12);
}

.risk--medium {
  color: #fbbf24;
  border: 1px solid rgba(251, 191, 36, 0.4);
  background: rgba(251, 191, 36, 0.12);
}

.risk--low {
  color: #34d399;
  border: 1px solid rgba(52, 211, 153, 0.4);
  background: rgba(52, 211, 153, 0.12);
}

/* 汇总卡片 */
.profile-card__stats {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin-bottom: 28px;
}

@media (max-width: 768px) {
  .profile-card__stats {
    grid-template-columns: repeat(2, 1fr);
  }
}

.stat-card {
  background: rgba(255, 255, 255, 0.03);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
}

.stat-card__label {
  font-family: var(--mono);
  font-size: 0.68rem;
  color: var(--muted);
  letter-spacing: 0.06em;
  text-transform: uppercase;
  margin-bottom: 8px;
}

.stat-card__value {
  font-size: 1.2rem;
  font-weight: 700;
  margin-bottom: 4px;
}

.val--ok { color: var(--ok); }
.val--warn { color: #fbbf24; }
.val--err { color: #f87171; }

.stat-card__sub {
  font-size: 0.76rem;
  color: var(--muted);
  line-height: 1.4;
}

/* 表格 */
.profile-card__table {
  width: 100%;
  border-collapse: collapse;
  margin-bottom: 24px;
  font-size: 0.86rem;
}

.profile-card__table thead th {
  text-align: left;
  padding: 10px 12px;
  font-family: var(--mono);
  font-size: 0.72rem;
  font-weight: 600;
  color: var(--muted);
  border-bottom: 1px solid var(--border);
  letter-spacing: 0.06em;
  text-transform: uppercase;
}

.profile-card__table tbody tr {
  border-bottom: 1px solid rgba(255, 255, 255, 0.04);
  transition: background 0.12s;
}

.profile-card__table tbody tr:hover {
  background: rgba(255, 255, 255, 0.02);
}

.profile-card__table tbody td {
  padding: 11px 12px;
  vertical-align: middle;
}

/* 列宽 */
.col--num    { width: 40px;  font-family: var(--mono); font-size: 0.78rem; color: var(--muted); }
.col--en     { width: 300px; color: var(--text-2); font-size: 0.82rem; }
.col--cn     { width: 180px; font-weight: 600; color: var(--text-strong); }
.col--result { width: 110px; }
.col--detail { color: var(--muted); font-size: 0.82rem; font-family: var(--mono); }

/* 结果列 */
.profile-card__result {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-size: 0.82rem;
  font-weight: 500;
}

.res--ok   { color: var(--ok); }
.res--warn { color: #fbbf24; }
.res--err  { color: #f87171; }

/* 总结框 */
.profile-card__summary {
  border-left: 3px solid #3b82f6;
  background: rgba(59, 130, 246, 0.06);
  border-radius: 0 8px 8px 0;
  padding: 14px 18px;
  font-size: 0.86rem;
  color: var(--text-2);
  line-height: 1.6;
  margin-bottom: 16px;
}

/* 风险标签 */
.profile-card__tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.profile-card__tag {
  font-size: 0.78rem;
  padding: 5px 14px;
  border-radius: 6px;
  border: 1px solid rgba(248, 113, 113, 0.3);
  background: rgba(248, 113, 113, 0.08);
  color: #fca5a5;
}
</style>
