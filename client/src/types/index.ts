export interface AuditRequest {
  baseUrl: string;
  apiKey: string;
  modelId: string;
}

export type AuditStepStatus = "pending" | "running" | "pass" | "warn" | "fail";

export interface AuditStep {
  id: string;
  label: string;
  status: AuditStepStatus;
  detail?: string;
  data?: unknown;
  ts: number;
  durationMs?: number;
}

export type AuditEvent =
  | { type: "start"; title: string; totalSteps: number }
  | { type: "step"; step: AuditStep }
  | {
      type: "log";
      message: string;
      level?: "info" | "warn" | "error";
      stepId?: string;
    }
  | {
      type: "done";
      passed: number;
      warned: number;
      failed: number;
      durationMs: number;
    }
  | { type: "report"; file: string }
  | { type: "error"; message: string };

export interface AuditLog {
  message: string;
  level: "info" | "warn" | "error";
  ts: number;
  stepId?: string;
}

export interface AuditSummary {
  passed: number;
  warned: number;
  failed: number;
  durationMs: number;
}
