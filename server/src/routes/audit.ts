import { Router } from "express";
import type { AuditEvent, AuditRequest } from "../types.js";
import { runAudit } from "../audit/runner.js";

export const auditRouter = Router();

auditRouter.post("/", (req, res) => {
  const body = req.body as Partial<AuditRequest>;
  const { baseUrl, apiKey, modelId } = body;

  if (!baseUrl || !apiKey || !modelId) {
    res
      .status(400)
      .json({ error: "baseUrl、apiKey、modelId 均为必填项" });
    return;
  }

  res.writeHead(200, {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });

  const writeable = () => !res.destroyed && !res.writableEnded;
  const send = (event: AuditEvent) => {
    if (writeable()) res.write(`data: ${JSON.stringify(event)}\n\n`);
  };

  // Keep the connection alive during long audits (SSE comment, ignored by client).
  const heartbeat = setInterval(() => {
    if (writeable()) res.write(": ping\n\n");
  }, 15000);

  const cleanup = () => clearInterval(heartbeat);
  req.on("close", cleanup);

  (async () => {
    try {
      for await (const event of runAudit({ baseUrl, apiKey, modelId })) {
        if (res.destroyed) break;
        send(event);
      }
    } catch (e) {
      send({
        type: "error",
        message: e instanceof Error ? e.message : String(e),
      });
    } finally {
      cleanup();
      if (!res.writableEnded) res.end();
    }
  })();
});
