<script setup lang="ts">
import { ref } from "vue";

const faqs = [
  {
    q: "API Key 会被中转站记录或滥用吗?",
    a: "大多数中转站需要用你的 Key(或其自有 Key)转发请求,理论上能看到并留存你的 Key 与对话内容。建议只用可信站点,使用独立、低额度、可随时轮换的 Key,并避免提交敏感数据;同时关注其是否留存对话日志或转卖语料。",
  },
  {
    q: "会不会偷换模型(声明 gpt-4 实际给便宜模型)?",
    a: "存在 model spoofing 风险。审计会核对实际响应模型与请求 modelId 是否一致,并探测常见模型的真实可用性,帮助识别“挂羊头卖狗肉”的中转站;同时也能发现“按官方倍率计费”下的价格欺诈。",
  },
  {
    q: "请求和响应会被篡改吗?流量会被限流吗?",
    a: "自建或第三方中转站可在转发链路注入、删改内容(如插入广告、截断、替换回复);同时常对并发、速率、总量做限制,也可能超卖共享额度导致高峰不可用。HTTPS 能防外部窃听但无法阻止站点本身改动,审计关注响应一致性与延迟抖动。",
  },
  {
    q: "TLS 证书与中间人风险?",
    a: "若站点使用自签或异常证书,或诱导安装根证书,存在中间人攻击风险。审计会检查 BaseURL 是否 HTTPS 及证书可达性,作为最基本的安全基线。",
  },
  {
    q: "如何降低使用中转站的整体风险?",
    a: "用独立可轮换 Key、不开高额度、不传敏感数据、核对模型与用量、优先 HTTPS 与可信站点,并定期复审计结果;敏感场景建议直连官方或自建中转,避免对单一第三方形成依赖。",
  },
];

const open = ref<number | null>(0);
function toggle(i: number) {
  open.value = open.value === i ? null : i;
}
</script>

<template>
  <section id="faq" class="screen faq">
    <header class="section__head">
      <h2>常见问题</h2>
      <p>使用第三方 API 中转站前,这些风险值得了解。</p>
    </header>

    <div class="faq__list">
      <div
        v-for="(f, i) in faqs"
        :key="i"
        class="faq__item"
        :class="{ 'faq__item--open': open === i }"
      >
        <button
          class="faq__q"
          :aria-expanded="open === i"
          @click="toggle(i)"
        >
          <span class="faq__num">{{ String(i + 1).padStart(2, "0") }}</span>
          <span class="faq__q-text">{{ f.q }}</span>
          <span class="faq__chev" aria-hidden="true">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">
              <path d="M6 9l6 6 6-6" />
            </svg>
          </span>
        </button>
        <div class="faq__a">
          <div class="faq__a-inner">
            <p>{{ f.a }}</p>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>
