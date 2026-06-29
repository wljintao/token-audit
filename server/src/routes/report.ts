import { Router } from "express";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// reports/ 在项目根；server/src/routes（dev）与 server/dist/routes（prod）到项目根都是 ../../../。
// 与 audit/runner.ts 的 PYTHON_DIR 推算同款（src/audit → 项目根也是 ../../../），dev/prod 一致。
const REPORTS_DIR = path.resolve(__dirname, "../../../reports");

// 合法报告文件名：report_<一级域名>_<YYYYMMDDHHMM>.md
// 与 audit_py/main.py 的生成规则一致，一级域名已做安全化（非字母数字转 _）。
const VALID_NAME = /^report_[A-Za-z0-9_]+_\d{12}\.md$/;

export const reportRouter = Router();

/** GET /api/report/:filename —— 下载指定审计报告（Markdown）。 */
reportRouter.get("/:filename", (req, res) => {
  // 路径穿越防护：basename 剥掉任何路径分隔/..，再用正则校验整体形态。
  const filename = path.basename(req.params.filename);
  if (!VALID_NAME.test(filename)) {
    res.status(400).json({ error: "非法的报告文件名" });
    return;
  }
  const fullPath = path.join(REPORTS_DIR, filename);
  // join 后再校验仍在 REPORTS_DIR 内（双保险，防符号链接等边界）。
  if (!fullPath.startsWith(REPORTS_DIR + path.sep)) {
    res.status(400).json({ error: "非法的报告文件名" });
    return;
  }
  if (!existsSync(fullPath)) {
    res.status(404).json({ error: "报告不存在" });
    return;
  }
  // res.download 触发浏览器下载（Content-Disposition: attachment）。
  res.download(fullPath, filename);
});
