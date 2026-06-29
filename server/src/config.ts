import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// config.ts 在 server/src/（dev）或 server/dist/（prod），到项目根都是 ../../。
// tsc 镜像 src→dist，dev/prod 路径一致。
const PROJECT_ROOT = path.resolve(__dirname, "../..");

/** config.json 的形状（根目录）。 */
interface RawConfig {
  port?: number;
  auditPython?: string;
  auditTimeoutMs?: number;
}

/** 读取并解析一个 JSON 配置文件；不存在或解析失败返回空对象。 */
function loadJson(file: string): RawConfig {
  if (!existsSync(file)) return {};
  try {
    return JSON.parse(readFileSync(file, "utf8")) as RawConfig;
  } catch (e) {
    console.warn(`[config] ${path.basename(file)} 解析失败，忽略: ${e instanceof Error ? e.message : e}`);
    return {};
  }
}

// 基础：config.json；其上叠加 config.local.json（gitignored，本地覆盖）。
const base = loadJson(path.join(PROJECT_ROOT, "config.json"));
const local = loadJson(path.join(PROJECT_ROOT, "config.local.json"));
const file: RawConfig = { ...base, ...local };

/**
 * 配置解析：环境变量 > 配置文件 > 内置默认。
 * 环境变量保留部署灵活性（docker/k8s/CI），config.json 集中可见的常用默认值。
 */
export const config = {
  /** 后端监听端口。 */
  port: Number(process.env.PORT ?? file.port ?? 3000),
  /** 显式指定 Python 解释器路径；空=venv 优先、系统 python3 兜底。 */
  auditPython: process.env.AUDIT_PYTHON ?? file.auditPython ?? "",
  /** 单次审计超时（ms），超时 SIGTERM 杀 Python 子进程。 */
  auditTimeoutMs: Number(process.env.AUDIT_TIMEOUT_MS ?? file.auditTimeoutMs ?? 600_000),
};
