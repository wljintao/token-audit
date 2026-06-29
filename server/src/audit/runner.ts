import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { AuditRequest, AuditEvent } from "../types.js";
import { config } from "../config.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// runner.ts 位于 server/src/audit/（比 index.ts 深一级），到项目根 audit_py/ 需 3 个 ../。
// tsc 把 src/audit/ 镜像到 dist/audit/，故 dev（tsx 在 src）与 prod（node 在 dist）路径一致。
const PYTHON_DIR = path.resolve(__dirname, "../../../audit_py");
const AUDIT_SCRIPT = path.join(PYTHON_DIR, "main.py");

/** Python 解释器优先级：配置/环境变量 > venv > 系统 python3 兜底。 */
function resolvePythonBin(): string {
  if (config.auditPython) return config.auditPython;
  const venvBin = path.join(PYTHON_DIR, ".venv/bin/python");
  if (existsSync(venvBin)) return venvBin;
  return "python3";
}

/** 单次审计超时（ms）。main.py 跑 19 项检查，Step 7 上下文长度（6 档）、
 * Step 12 延迟方差（10 探针）、Step 14 长任务（多轮）对慢中转站累计耗时较长，
 * 默认放宽到 10 分钟。上游挂起或死锁时硬上限，防 SSE 无限挂。
 * 值来自 config.json（可被环境变量 AUDIT_TIMEOUT_MS 覆盖）。 */
const TIMEOUT_MS = config.auditTimeoutMs;

/** 把 stderr 文本里出现的已知 apiKey 值替换掉，避免泄露给前端。 */
function redact(text: string, apiKey: string): string {
  if (!apiKey) return text;
  return text.split(apiKey).join("***");
}

/**
 * 审计执行器：spawn Python 子进程，把入参经 stdin 传入，逐行解析 stdout
 * 的 NDJSON 事件并 yield 为 AuditEvent。
 *
 * 协议：
 *   - stdin：单行 JSON {"baseUrl","apiKey","modelId"} + EOF
 *   - stdout：每个 AuditEvent 一行 JSON（Python 端逐行 flush）
 *   - stderr：诊断日志（收集但不转发前端，仅异常时附进 error message）
 *   - 进程：正常 exit 0；异常 exit 1；入参非法 exit 2
 */
export async function* runAudit(
  input: AuditRequest,
): AsyncGenerator<AuditEvent> {
  const child = spawn(resolvePythonBin(), [AUDIT_SCRIPT], {
    stdio: ["pipe", "pipe", "pipe"],
  });

  let stderrBuf = "";
  let sawError = false;
  let timedOut = false;

  // stderr：累积诊断日志，不转发前端。
  child.stderr.on("data", (d: Buffer) => {
    stderrBuf += d.toString("utf8");
  });

  // 超时：SIGTERM，5s 宽限后 SIGKILL。
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill("SIGTERM");
    setTimeout(() => {
      if (!child.killed && child.exitCode === null) child.kill("SIGKILL");
    }, 5000);
  }, TIMEOUT_MS);
  // 不阻塞事件循环退出。
  timer.unref?.();

  const cleanup = () => {
    clearTimeout(timer);
    // 用户中途断连（生成器被 return()）时杀掉残留 Python，防孤儿进程。
    if (!child.killed && child.exitCode === null) child.kill("SIGTERM");
  };

  try {
    // 写入 stdin 并 EOF，触发 Python readline 返回。
    child.stdin.write(JSON.stringify(input) + "\n");
    child.stdin.end();

    let buffer = "";
    for await (const chunk of child.stdout) {
      buffer += chunk.toString("utf8");
      let nl: number;
      while ((nl = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, nl).trim();
        buffer = buffer.slice(nl + 1);
        if (!line) continue;
        let ev: AuditEvent;
        try {
          ev = JSON.parse(line) as AuditEvent;
        } catch {
          // 坏行：记录并跳过，不中断流。
          console.warn(
            `[audit] 跳过无法解析的 Python 输出行: ${line.slice(0, 200)}`,
          );
          continue;
        }
        if (ev.type === "error") sawError = true;
        yield ev;
      }
    }

    // stdout EOF 后等待进程退出，拿退出码。
    const code: number | null = await new Promise((resolve) => {
      child.once("close", (c: number | null) => resolve(c));
    });

    if (timedOut) {
      throw new Error("Python 审计超时");
    }
    if (sawError) {
      // Python 已发 error 事件并 yield 出去，直接结束，避免重复 error。
      return;
    }
    if (code !== 0) {
      throw new Error(
        `Python 审计异常退出(code=${code}): ${redact(stderrBuf, input.apiKey).slice(-500)}`,
      );
    }
    // code === 0 但没收到 done/error：提前结束。
    // （正常情况 Python 会发 done 后 exit 0，这里兜底防御。）
  } finally {
    cleanup();
  }
}
