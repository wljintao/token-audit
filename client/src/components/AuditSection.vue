<script setup lang="ts">
import { ref, computed } from "vue";
import { useAudit } from "../composables/useAudit";
import AuditForm from "./AuditForm.vue";
import AuditReport from "./AuditReport.vue";
import type { AuditRequest } from "../types";

const audit = useAudit();
const activeTab = ref<1 | 2>(1);
const resultsReady = computed(() => audit.phase.value !== "idle");

function onSubmit(req: AuditRequest) {
  activeTab.value = 2;
  audit.runAudit(req);
}

function goTab(n: 1 | 2) {
  if (n === 2 && !resultsReady.value) return;
  activeTab.value = n;
}
</script>

<template>
  <section id="audit" class="screen">
    <header class="section__head">
      <h2>
        <span class="dot-live" />
        立即开始
      </h2>
      <p>输入中转站信息,点击审计,服务端将逐项流式返回结果,前端实时呈现。</p>
    </header>

    <div class="tabs" role="tablist">
      <button
        type="button"
        role="tab"
        class="tabs__item"
        :class="{ 'is-active': activeTab === 1 }"
        :aria-selected="activeTab === 1"
        @click="goTab(1)"
      >
        1、审计配置
      </button>
      <button
        type="button"
        role="tab"
        class="tabs__item"
        :class="['tabs__item', { 'is-active': activeTab === 2, 'is-locked': !resultsReady }]"
        :aria-selected="activeTab === 2"
        :disabled="!resultsReady"
        @click="goTab(2)"
      >
        2、实时结果
      </button>
    </div>

    <div class="tab-panels">
      <div v-show="activeTab === 1" class="tab-panel" role="tabpanel">
        <AuditForm
          :loading="audit.phase.value === 'running'"
          @submit="onSubmit"
        />
      </div>
      <div v-show="activeTab === 2" class="tab-panel" role="tabpanel">
        <AuditReport
          :phase="audit.phase.value"
          :title="audit.title.value"
          :total-steps="audit.totalSteps.value"
          :steps="audit.steps"
          :logs-by-step="audit.logsByStep.value"
          :global-logs="audit.globalLogs.value"
          :expanded-steps="audit.expandedSteps"
          :summary="audit.summary.value"
          :error-msg="audit.errorMsg.value"
          :report-file="audit.reportFile.value"
          @toggle-step="audit.toggleStep"
        />
      </div>
    </div>
  </section>
</template>
