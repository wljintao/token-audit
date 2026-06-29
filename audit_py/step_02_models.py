"""Step 2: Model List (模型列表).

列出 /v1/models 的全部 model id。Informational only — 不进 6D 风险矩阵。
"""
from __future__ import annotations


STEP_NAME_CN = "模型列表"


def run(client, report, **kwargs) -> None:
    """List all models exposed by the relay's /v1/models endpoint."""
    report.h2(f"2. {STEP_NAME_CN}")
    models = client.get_models()
    if models:
        report.p(f"Total **{len(models)}** models:\n")
        for m in models:
            report.p(f"- `{m.get('id', '?')}` (owned_by: {m.get('owned_by', '?')})")
        # 信息性步骤：汇总模型数量作为结论，避免前端显示"(本项无明确结论)"。
        report.flag("green", f"Found {len(models)} models")
    else:
        report.p("Failed to retrieve model list")
        report.flag("yellow", "Failed to retrieve model list")
    print(f"  Done: model list ({len(models)} models)")
