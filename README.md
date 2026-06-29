# Token Audit

核验任意 LLM API 中转站（relay）安全性的 Web 应用：在 Vue 前端填入 Base URL / API Key / 模型名，点击审计，前端经 Node.js 后端代理，由 **Python 审计引擎**执行 **19 项安全检查**，并以 SSE 流式把每一步进度实时回传前端。

Monorepo（npm workspaces）+ Python 子目录：

| 目录 | 说明 |
| --- | --- |
| `server/` | Express + TypeScript 后端，暴露 `/api/audit`、`/api/health` |
| `client/` | Vue 3 + Vite + TypeScript 单页前端 |
| `audit_py/` | Python 审计引擎（纯标准库 + curl），由后端以子进程方式调用 |


## `audit_py/` 引擎

- `main.py` — 主入口/引擎：`run_stdin()`（生产入口，读 stdin JSON → `EventReporter` 发 NDJSON 事件）+ `main()`（CLI，输出 Markdown 报告）+ `APIClient`（curl 双通道、Anthropic/OpenAI 格式自动检测、SSL 错误自动切 curl）、`Reporter`、`diagnose_error` 等共享基础设施。
- `step_registry.py` — 19 步注册表 + fail-open 调度器：spec 表 `(N, module, name_cn, skip_attr, default, ret_shape)`，`run_registered_steps()` 统一调度，`_run_step` 异常隔离（单项崩溃降级 warn 不中断整体）。
- `step_NN_*.py` — 每个步骤一个文件（`step_01`…`step_19`，编号连续），统一签名 `run(client, report, **kwargs)`，顶部声明中文展示名 `STEP_NAME_CN`。Step 1-13 内置检查，14-19 伴生检查。
- `step_helpers.py` / `step_helpers_identity.py` — 跨步共享辅助（错误诊断渲染、身份泄漏子系统）。
- `protocol.py` — 协议层：`emit()` 写 stdout + flush、`bind_stdout()` 让 emit 与业务 `print` 分流、`build_*` 事件构造器。

### 19 项审计检查

| # | 检查项 | # | 检查项 |
| --- | --- | --- | --- |
| 1 | Infrastructure Recon | 11 | Infrastructure Fingerprint |
| 2 | Model List | 12 | Latency Variance |
| 3 | Token Injection Detection | 13 | Upstream Channel Classifier |
| 4 | Prompt Extraction Tests | 14 | Long-Task / Multi-Request Integrity |
| 5 | Instruction Override Tests | 15 | Billing / Usage Integrity |
| 6 | Jailbreak & Role Impersonation | 16 | API Conformance / Silent Downgrade |
| 7 | Context Length Test | 17 | Model Substitution / Fake-Model Fingerprint |
| 8 | Tool-Call Package Substitution (AC-1.a) | 18 | Transport-Layer Security (TLS) |
| 9 | Error Response Leakage (AC-2) | 19 | Audit-Evasion Countermeasures |
| 10 | Stream Integrity (AC-1 SSE) | | |

## 快速开始

```bash
npm install              # 装 server/client 依赖
npm run python:setup     # 创建 audit_py/.venv（纯标准库，仅建环境+升级 pip）
npm run dev              # 后端 :3000 + 前端 :5173，Vite 代理 /api 到后端
```

## stdin 输入格式

`runner.ts` 经 stdin 传给 `main.py` 的 JSON：

```jsonc
{
  "baseUrl": "https://relay.example.com",   // 必填
  "apiKey": "sk-...",                        // 必填，只进 HTTP 头，不进日志
  "modelId": "claude-3-5-sonnet-20241022",   // 必填
  "skip": { "tls": false, "billing": false }, // 可选，跳过指定检查项（key 见下）
  "fastContext": false,                      // 可选：Step 7 快速模式
  "warmup": 0,                               // 可选：审计前发 N 个 benign 请求
  "timeout": 120                             // 可选：单请求超时秒数
}
```

`skip` 的 key：`infra`/`context`/`toolSubstitution`/`errorLeakage`/`streamIntegrity`/`infraFingerprint`/`latencyVariance`/`channelClassifier`/`longTask`/`billing`/`apiConsistency`/`modelFingerprint`/`tls`/`probeRandomization`。TS 端 `AuditRequest` 目前只含三个必填字段，可选字段不传时默认全跑。

## 使用 Python 直接调用 audit_py 引擎

```bash
# 直接调用 Python 引擎，输出 Markdown 报告
python audit_py/main.py \
  --key sk-xxx \
  --url https://relay.example.com/v1 \
  --model claude-3-5-sonnet-20241022
```

## 安全

- API Key 经 stdin 传入子进程，不进命令行参数（不出现在 `ps`）。
- Python 端只把 Key 放进 HTTP `Authorization` / `x-api-key` 头，永不写进 stdout / stderr / 事件 `detail` / `data`。
- 后端在子进程异常退出时，对收集到的 stderr 尾部脱敏（替换已知 Key 值）后才附进 error 事件。
- `_run_step` fail-open：任一检查项抛异常不中断整体审计，该项降级为 `warn`。
