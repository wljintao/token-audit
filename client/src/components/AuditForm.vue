<script setup lang="ts">
import { reactive, computed } from "vue";
import type { AuditRequest } from "../types";

const props = defineProps<{ loading: boolean }>();
const emit = defineEmits<{ (e: "submit", value: AuditRequest): void }>();

const form = reactive({
  baseUrl: "https://api.example.com/v1",
  apiKey: "",
  modelId: "",
});

const valid = computed(
  () => form.baseUrl.trim() && form.apiKey.trim() && form.modelId.trim(),
);

function onSubmit() {
  if (!valid.value || props.loading) return;
  emit("submit", {
    baseUrl: form.baseUrl.trim(),
    apiKey: form.apiKey.trim(),
    modelId: form.modelId.trim(),
  });
}
</script>

<template>
  <form class="aform" @submit.prevent="onSubmit">
    <label class="field">
      <span class="field__label">BaseURL</span>
      <input v-model="form.baseUrl" type="text" placeholder="https://your-relay.example.com" />
      <span class="field__hint">中转站入口地址,需以 http(s):// 开头</span>
    </label>

    <label class="field">
      <span class="field__label">API Key</span>
      <input v-model="form.apiKey" type="text" placeholder="sk-..." autocomplete="off" />
      <span class="field__hint">仅本次请求使用,不会持久化保存</span>
    </label>

    <label class="field">
      <span class="field__label">Model ID</span>
      <input v-model="form.modelId" type="text" placeholder="claude-opus-4-7" />
      <span class="field__hint">声明的模型标识,审计将核对实际响应模型</span>
    </label>

    <button class="btn btn--primary" type="submit" :disabled="!valid || props.loading">
      {{ props.loading ? "审计中…" : "开始审计" }}
    </button>
  </form>
</template>
