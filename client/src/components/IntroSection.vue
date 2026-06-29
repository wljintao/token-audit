<script setup lang="ts">
defineEmits<{ (e: "start"): void; (e: "report"): void }>();

const points = ["可达性", "鉴权", "模型真实性", "流式透明", "可追溯报告"];

const features = [
  {
    title: "流式审计",
    desc: "服务端逐项推送结果，前端实时呈现执行过程，所见即可信。",
    icon: "M4 6h16M4 12h12M4 18h8",
  },
  {
    title: "可追溯报告",
    desc: "每一步保留时间戳、级别与原始日志，导出即可作为审计凭证。",
    icon: "M9 12l2 2 4-4M5 4h14a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1z",
  },
  {
    title: "深度检测",
    desc: "覆盖可达性、鉴权、模型真实性、响应一致性、TLS 与延迟抖动。",
    icon: "M21 21l-4.35-4.35M11 19a8 8 0 1 1 0-16 8 8 0 0 1 0 16z",
  },
];
</script>

<template>
  <section id="intro" class="screen screen--full intro">
    <div class="intro__content">
      <span class="intro__badge">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2l2.2 6.8L21 11l-6.8 2.2L12 20l-2.2-6.8L3 11l6.8-2.2L12 2z" /></svg>
        OpenAI 兼容 · 流式审计
      </span>
      <h1 class="intro__title">
        Token 中转站 <em>深度审计</em>
      </h1>
      <p class="intro__desc">
        一键检测任意 OpenAI 兼容中转站的可达性、鉴权与模型真实性。
        流式执行，逐项落库，产出可追溯的安全与可用性报告。
      </p>
      <ul class="intro__points">
        <li v-for="p in points" :key="p">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M4.5 12.75l6 6 9-13.5" /></svg>
          {{ p }}
        </li>
      </ul>
      <div class="intro__actions">
        <button class="btn btn--primary intro__cta" @click="$emit('start')">立即开始</button>
        <button class="btn btn--ghost" @click="$emit('report')">查看报告</button>
      </div>

      <div class="intro__trust">
        <span><i class="dot" />HTTPS · TLS 校验</span>
        <span><i class="dot" />零留存 · 仅本地落库</span>
        <span><i class="dot" />流式输出 · 实时反馈</span>
      </div>
    </div>

    <div class="features">
      <div v-for="(f, i) in features" :key="i" class="feature">
        <div class="feature__icon">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path :d="f.icon" />
          </svg>
        </div>
        <h3 class="feature__title">{{ f.title }}</h3>
        <p class="feature__desc">{{ f.desc }}</p>
      </div>
    </div>
  </section>
</template>
