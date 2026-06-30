"""Step 2: Model List (模型列表).

列出 /v1/models 的全部 model id，按上游提供商分组统计。
Informational only — 不进 6D 风险矩阵。
"""
from __future__ import annotations

import time
from collections import defaultdict

STEP_NAME_CN = "模型列表"


# 常见上游提供商归一化映射（owned_by 小写匹配 → 显示名）
_PROVIDER_NORMALIZE = {
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "google": "Google",
    "deepseek": "DeepSeek",
    "moonshot": "Moonshot / 月之暗面",
    "zhipu": "智谱 AI",
    "qwen": "通义千问 / 阿里云",
    "baidu": "百度 / 文心",
    "meta": "Meta",
    "meta-llama": "Meta (Llama)",
    "mistral": "Mistral",
    "cohere": "Cohere",
    "x-ai": "xAI (Grok)",
    "replit": "Replit",
    "microsoft": "Microsoft",
    "01-ai": "01.AI / 零一万物",
    "minimax": "MiniMax",
    "baichuan": "百川智能",
    "yi": "零一万物 (Yi)",
    "internlm": "InternLM / 书生",
    "system": "系统内置",
}


def _normalize_provider(owned_by):
    """将 owned_by 归一化为可读的提供商名称。"""
    if not owned_by or owned_by == "?":
        return "未知来源"
    key = owned_by.lower().strip()
    # 精确匹配
    if key in _PROVIDER_NORMALIZE:
        return _PROVIDER_NORMALIZE[key]
    # 前缀匹配（如 "org-xxx"、"team-xxx"、"user-xxx"）
    for prefix, label in _PROVIDER_NORMALIZE.items():
        if key.startswith(prefix):
            return label
    return owned_by


def _format_timestamp(ts):
    """将 Unix 时间戳转为可读日期；无效值返回 None。"""
    if not ts or not isinstance(ts, (int, float)):
        return None
    try:
        return time.strftime("%Y-%m-%d", time.gmtime(ts))
    except Exception:
        return None


def run(client, report, **kwargs) -> None:
    """List all models exposed by the relay's /v1/models endpoint."""
    report.h2(f"2. {STEP_NAME_CN}")
    models = client.get_models()
    if not models:
        report.p("无法获取模型列表（接口未返回数据或认证失败）")
        report.flag("yellow", "无法获取模型列表")
        print("  Done: model list (0 models)")
        return

    # ── 2.1 API Key 有效性 ──
    report.h3("2.1 API Key 状态")
    report.p("✅ `/v1/models` 接口调用成功，API Key 有效")

    # ── 2.2 模型总览 ──
    report.h3("2.2 模型总览")
    report.p(f"共发现 **{len(models)}** 个模型：\n")
    for m in models:
        mid = m.get("id", "?")
        owned_by = m.get("owned_by", "?")
        created = _format_timestamp(m.get("created"))
        line = f"- `{mid}` （来源：{owned_by}"
        if created:
            line += f"，创建时间：{created}"
        line += "）"
        report.p(line)

    # ── 2.3 上游提供商分布 ──
    report.h3("2.3 上游提供商分布")
    provider_models = defaultdict(list)
    for m in models:
        provider = _normalize_provider(m.get("owned_by", "?"))
        provider_models[provider].append(m.get("id", "?"))

    for provider, mids in sorted(provider_models.items(), key=lambda x: -len(x[1])):
        report.p(f"- **{provider}**：{len(mids)} 个模型"
                 + (f"（{', '.join('`' + mid + '`' for mid in mids[:5])}"
                    + ("…" if len(mids) > 5 else "") + "）"))

    # ── 2.4 可疑命名检测 ──
    suspicious = []
    for m in models:
        mid = m.get("id", "?")
        # 常见伪造/替换特征：名称中含 "relay"、"proxy"、"custom" 等
        lower_id = mid.lower()
        if any(kw in lower_id for kw in ("relay", "proxy", "custom", "forward", "tunnel")):
            suspicious.append((mid, "模型名称含中转/代理特征词"))
        # 名称与 owned_by 明显不匹配（如 owned_by=openai 但模型名不像 OpenAI 模型）
        owned_by = (m.get("owned_by") or "").lower()
        if owned_by == "openai" and not any(
            lower_id.startswith(p) for p in ("gpt-", "o1", "o3", "o4", "text-embedding", "dall-e", "whisper", "tts-")
        ):
            suspicious.append((mid, "声称来自 OpenAI 但模型名不符合 OpenAI 命名规范"))
        if owned_by == "anthropic" and not lower_id.startswith("claude"):
            suspicious.append((mid, "声称来自 Anthropic 但模型名不符合 Anthropic 命名规范"))

    if suspicious:
        report.h3("2.4 可疑命名检测")
        for mid, reason in suspicious:
            report.p(f"- ⚠️ `{mid}`：{reason}")

    # ── 结论 ──
    provider_summary = "、".join(
        f"{p}({len(ids)}个)" for p, ids in
        sorted(provider_models.items(), key=lambda x: -len(x[1]))
    )
    flag_msg = f"发现 {len(models)} 个模型，上游分布：{provider_summary}"
    if suspicious:
        flag_msg += f"；发现 {len(suspicious)} 项可疑命名"
        report.flag("yellow", flag_msg)
    else:
        report.flag("green", flag_msg)
    print(f"  Done: model list ({len(models)} models)")
