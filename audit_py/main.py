"""
Token 中转站审计 v1.0

提供两个入口：
  - run_stdin()：读 stdin 单行 JSON 入参，按行向 stdout 输出 NDJSON 事件，
    供 server/src/audit/runner.ts spawn 后逐行解析、经 SSE 推前端；
  - main()：CLI 入口，输出 Markdown 报告。

  python audit_py/main.py --key YOUR_KEY --url https://relay.example.com/v1 --model claude-opus-4-6

审计语义分布在 audit_py/step_NN_*.py 各步骤模块，统一由 step_registry.run_registered_steps() 调度。
"""
import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse


# ============================================================
# NDJSON 事件流集成（本项目适配器）
# ============================================================
# run_stdin() 把它改造成「读 stdin JSON → 用 EventReporter 把 report.h2/h3/p/flag 实时映射成 NDJSON AuditEvent → stdout 流式输出」，
# 供 server/src/audit/runner.ts spawn 后逐行解析经 SSE 推前端。
from event_reporter import EventReporter
import protocol
from protocol import build_done, build_error, build_report, build_start, emit
from step_registry import run_registered_steps

# ============================================================
# 透明取证日志
# ============================================================

"""只追加的 JSONL 取证日志

记录审计运行期间发出的每一次 API 请求，含时间戳、URL、请求/响应字节的SHA-256、状态码、响应头以及传输元数据。
**仅哈希，不含正文**——使每条记录 <=1.5 KB，并规避凭据落盘风险。

TLS 元数据采集推迟到后续提交；``tls_version`` 和 ``tls_cipher`` 字段，当前恒为 ``null``。
"""


def redact_error(error):
    """安全脱敏：对 ``HTTP `` / ``curl failed`` 前缀的错误，仅保留到首个冒号之前
    （错误类型 + HTTP 状态），丢弃冒号后的响应正文（可能含泄露的 API key / 上游 URL）。
    其他错误（异常消息、超时）原样透传；``None`` 返回 ``None``。"""
    if error is None:
        return None
    for prefix in ("HTTP ", "curl failed"):
        if error.startswith(prefix):
            colon = error.find(":")
            if colon != -1:
                return error[:colon]
            return error
    return error


def sha256hex(data):
    if data is None:
        return None
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class TransparentLogger:
    """只追加的 JSONL 取证日志写入器：每次 :meth:`log_entry` 写一行并立即 flush 以保崩溃安全。
    永不抛异常——I/O 错误打 stderr，避免磁盘写满或只读路径中断审计。"""

    def __init__(self, path: str):
        self._path = path
        # 父目录不存在时自动创建（MEDIUM 修复）。
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        self._f = open(path, "a", encoding="utf-8")

    def log_entry(self, entry: dict) -> None:
        try:
            self._f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self._f.flush()
        except Exception as e:
            print(f"  [transparent-log] write error: {e}", file=sys.stderr)

    def close(self) -> None:
        try:
            self._f.close()
        except Exception:
            pass


# ============================================================
# 流完整性信号与判定
# ============================================================

"""用于 Step 10 SSE 层中转篡改检测的流完整性信号。

本模块提供捕获 Anthropic 格式流式响应在 SSE 事件层样貌的数据结构。
真正的判定逻辑（:func:`analyze_stream`）将在后续提交（Sub-PR 2）中加入；
本次提交先交付 dataclass 及常量，使
:meth:`api_relay_audit.client.APIClient.stream_call` 有东西可填。

## 检测思路

一个重写或代理 Claude 流式响应的恶意中转站，即使最终用户看到的文本
看起来正确，也可在三个独立层面被捕获：

1. **SSE 事件白名单。** Anthropic 的流式 schema 恰好使用 7 种事件类型
   （见 :data:`KNOWN_SSE_EVENT_TYPES`）。流中出现未知事件类型是中转站
   注入或重写事件的强指纹。Sub-PR 2 的 ``analyze_stream`` 会对任何未知
   事件扣分。
2. **usage 字段单调性。** ``message_start`` 事件携带 ``input_tokens``
   计数；随后的 ``message_delta`` 事件携带增量 ``output_tokens`` 以及
   ``input_tokens`` 的重述。重写 usage（以少计费或掩盖模型降级）的中转站
   常违反这些不变量：``output_tokens`` 可能非单调，或 ``input_tokens``
   在事件间神秘漂移。
3. **thinking 块签名一致性。** Claude Opus/Sonnet 4.6 扩展思考响应发出
   ``signature_delta`` 事件，其 ``signature`` 字段必须非空。降级到非思考
   模型并伪造周边流事件的中转站可能留下空签名。
   :attr:`StreamSignals.empty_signature_delta_count` 计数这些。

## 归属

威胁模型及可观测信号的具体清单受 hvoy.ai 的 ``zzsting88/relayAPI``
``claude_detector.py`` ``StreamSignals`` dataclass 启发（已于 2026-04-11
对照源码核实）。上游仓库无 ``LICENSE`` 文件，故本模块为独立的净室重实现：

- 字段名（``event_types``、``message_start_model``、
  ``empty_signature_delta_count`` 等）与 hvoy.ai 重叠，是因为它们描述的
  是同一套 Anthropic SSE schema——schema 字段名与协议事件类型不受版权
  保护。
- 字段类型与默认工厂为我们自己的选择。
- Sub-PR 2 的评分/判定逻辑将是三态（``clean`` / ``anomaly`` /
  ``inconclusive``），而非 hvoy.ai 的加权 0-100 评分模型。

完整的核实记录以及我们选择**不**移植的清单（知识截止探针、Claude Code
CLI 头部冒充、``"null"`` 文本块请求体指纹）见 ``reference_hvoy_relayapi``
memory 文件。

参考：Liu, Shou, Wen, Chen, Fang, Feng，《Your Agent Is Mine:
Measuring Malicious Intermediary Attacks on the LLM Supply Chain》，
arXiv:2604.08407，§4.2。SSE 白名单 / usage 单调性 / 签名一致性属于传输
层的 AC-1 类检测。
"""


# Anthropic 已知的 7 种 SSE 事件类型。出现在 ``event_types`` 列表中的任何其他
# 类型都是「未知事件」——这是中转站注入或重写 SSE 事件的潜在信号。来源：
# 2026-04-11 阅读 ``zzsting88/relayAPI`` 的 ``claude_detector.py`` 第 369-377 行。
KNOWN_SSE_EVENT_TYPES = frozenset({
    "ping",
    "message_start",
    "content_block_start",
    "content_block_delta",
    "content_block_stop",
    "message_delta",
    "message_stop",
})


@dataclass
class StreamSignals:
    """捕获流式 Anthropic 响应在 SSE 事件层的样貌，由 :meth:`APIClient.stream_call` 填充。

    所有字段默认取「未观测到任何内容」的值，故流出错也能产出合法可序列化对象。
    **关键不变式**：下游消费者在判定 clean/anomaly 前必须先检查
    :attr:`transport_error`——带错误的空 signals 应报告为 *inconclusive*
    （无法判定），而非 *clean*（干净）。

    属性:
        event_types: 观测到的 SSE 事件类型有序列表（含未知类型），用于白名单检查。
        content_block_types: ``content_block_start`` 中观测到的内容块类型（如 ``"text"``/``"thinking"``）。
        delta_types: ``content_block_delta`` 中观测到的 delta 类型（如 ``"text_delta"``/``"thinking_delta"``/``"signature_delta"``）。
        has_message_start/content_block_start/content_block_delta/message_delta/message_stop/text_delta: 各事件是否观测到的布尔标志。
        thinking_start_seen: 观测到 ``content_block.type == "thinking"`` 的 ``content_block_start``。
        thinking_delta_seen: 在 delta 内观测到至少一个 ``thinking_delta``。
        message_start_model: 首个 ``message_start`` 的 ``message.model``，缺失为 ``None``——把 ``claude-*`` 路由到非 Claude 模型的中转站常在此露馅。
        input_tokens: 首个 ``message_start`` ``usage`` 块的 ``input_tokens``，或 ``None``。
        message_delta_input_tokens_samples: ``message_delta`` 中每个 ``input_tokens`` 值，应全等于 :attr:`input_tokens`，用于检测重写。
        output_tokens_samples: ``message_delta`` 中每个 ``output_tokens`` 值，按到达顺序，用于检查单调性。
        empty_signature_delta_count: 签名为空/纯空白的 ``signature_delta`` 数，> 0 是 thinking 块降级信号。
        transport_error: 流无法干净打开/解析时非 ``None``，下游必须视为 *inconclusive*。
        total_duration_seconds: 请求开始到流关闭的挂钟时间，可检测缓冲重写型中转站延迟整条响应。
        raw_event_count: 解析出的事件总数（含未知类型），0 表完全没收到数据，是 inconclusive 信号。
    """

    # 有序事件类型序列（用于白名单检查）
    event_types: List[str] = field(default_factory=list)
    # 在 content_block_start 事件中观测到的内容块类型
    content_block_types: List[str] = field(default_factory=list)
    # 在 content_block_delta 事件中观测到的 delta 类型
    delta_types: List[str] = field(default_factory=list)

    # 用于便捷查询的布尔存在标志
    has_message_start: bool = False
    has_content_block_start: bool = False
    has_content_block_delta: bool = False
    has_message_delta: bool = False
    has_message_stop: bool = False
    has_text_delta: bool = False
    thinking_start_seen: bool = False
    thinking_delta_seen: bool = False

    # 身份与 usage 信号
    message_start_model: Optional[str] = None
    input_tokens: Optional[int] = None
    message_delta_input_tokens_samples: List[int] = field(default_factory=list)
    output_tokens_samples: List[int] = field(default_factory=list)

    # thinking 块异常计数器
    empty_signature_delta_count: int = 0

    # 传输与计时
    transport_error: Optional[str] = None
    total_duration_seconds: Optional[float] = None
    raw_event_count: int = 0


# ---------------------------------------------------------------------------
# 判定分析（Sub-PR 2）
# ---------------------------------------------------------------------------

# findings 输出中报告的未知事件类型数量上限。
# hvoy.ai 的 claude_detector.py 用 -6 作为 SSE 形状评分的数值扣分上限；
# 我们不用数值评分，但把列表长度上限设为 6，以保持报告输出有界，即便在
# 病态中转站上也不会失控。
MAX_UNKNOWN_EVENTS_REPORTED = 6


# ============================================================
# 独立 curl 传输门面
# ============================================================

"""模块化 API 客户端的内部 HTTP 传输辅助函数。

这是一次刻意保留门面的内部抽取：APIClient 仍负责格式检测、日志和回退
策略。这些辅助函数仅集中低层的 httpx/curl 请求机制。
"""


LOOPBACK_NO_PROXY = "localhost,127.0.0.1,::1"
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def curl_loopback_no_proxy_args(url: str) -> list:
    if urlparse(url).hostname in LOOPBACK_HOSTS:
        return ["--noproxy", LOOPBACK_NO_PROXY]
    return []


def curl_post_json(url: str, headers: dict, body: dict, timeout: int,
                   subprocess_module=subprocess) -> dict:
    """通过 curl POST JSON。header 经 ``--config -`` 传入以避免凭据出现在进程列表；JSON 正文写
    临时文件经 ``--data-binary @file`` 发送，以规避超大 prompt 的命令行长度限制。"""
    body_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", delete=False, prefix="api-relay-body-", suffix=".json"
        ) as tmp:
            json.dump(body, tmp)
            body_path = tmp.name

        cmd = ["curl", "-sk", *curl_loopback_no_proxy_args(url), "-X", "POST", url,
               "--max-time", str(timeout), "--config", "-", "--data-binary", f"@{body_path}"]
        config = "\n".join(f'header = "{k}: {v}"' for k, v in headers.items())
        r = subprocess_module.run(cmd, capture_output=True, text=True, input=config,
                                  timeout=timeout + 10)
    finally:
        if body_path:
            try:
                os.unlink(body_path)
            except OSError:
                pass

    if r.returncode != 0:
        raise RuntimeError(f"curl failed: {r.stderr[:200]}")
    return json.loads(r.stdout)


def curl_get_json_data(url: str, headers: dict, timeout: int = 15,
                       subprocess_module=subprocess) -> list:
    cmd = ["curl", "-sk", *curl_loopback_no_proxy_args(url), url,
           "--max-time", str(timeout), "--config", "-"]
    config = "\n".join(f'header = "{k}: {v}"' for k, v in headers.items())
    r = subprocess_module.run(cmd, capture_output=True, text=True, input=config,
                              timeout=timeout + 10)
    if r.returncode != 0:
        return []
    return json.loads(r.stdout).get("data", [])


def curl_raw_request(method: str, url: str, headers: dict, body: bytes,
                     content_type: str, timeout: int, parser,
                     subprocess_module=subprocess) -> dict:
    all_headers = {**headers, "content-type": content_type}
    cmd = ["curl", "-sk", *curl_loopback_no_proxy_args(url), "-i", "-X", method, url,
           "--max-time", str(timeout), "--data-binary", "@-"]
    for k, v in all_headers.items():
        cmd.extend(["-H", f"{k}: {v}"])
    try:
        r = subprocess_module.run(cmd, capture_output=True, input=body,
                                  timeout=timeout + 10)
        if r.returncode != 0:
            err = r.stderr.decode("utf-8", errors="replace")[:200]
            return {"status": 0, "headers": {}, "body": "",
                    "error": f"curl failed: {err}"}
        output = r.stdout.decode("utf-8", errors="replace")
        return parser(output)
    except Exception as e:
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}

def httpx_get_json_data(url: str, headers: dict, timeout: int = 15):
    cmd = [
        "curl", "-sk", *curl_loopback_no_proxy_args(url),
        "-i", url, "--max-time", str(timeout), "--config", "-"
    ]
    config = "\n".join(f'header = "{k}: {v}"' for k, v in headers.items())
    r = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=config,
        timeout=timeout + 10,
    )
    if r.returncode != 0:
        return 0, [], "", {}
    parsed = _parse_curl_i_output(r.stdout)
    status = parsed.get("status", 0)
    text = parsed.get("body", "")
    data = []
    if status == 200:
        try:
            data = json.loads(text).get("data", [])
        except Exception:
            data = []
    return status, data, text, parsed.get("headers", {})


def httpx_raw_request(method: str, url: str, headers: dict, body: bytes,
                      content_type: str, timeout: int) -> dict:
    return curl_raw_request(
        method,
        url,
        headers,
        body,
        content_type,
        timeout,
        parser=_parse_curl_i_output,
    )


# ============================================================
# API 客户端
# ============================================================

"""
带自动检测（Anthropic / OpenAI）与 curl 回退的共享 API 客户端。

消除各脚本间重复的 API 调用逻辑。
"""


def _parse_curl_i_output(output: str) -> dict:
    """解析 ``curl -i`` stdout 为 ``{"status", "headers", "body", "error"}``。
    归一化 ``\\r\\n``、兼容 HTTP/1.x 与 HTTP/2 状态行、跳过 ``100 Continue`` 前缀。
    ``status == 0`` 表示解析失败（``error`` 为简短诊断）。"""
    if not output:
        return {"status": 0, "headers": {}, "body": "", "error": "empty curl output"}

    # 规范化换行，使 \n\n 分隔符可靠。
    text = output.replace("\r\n", "\n")

    # 在首个空行处切分为头部块 / 正文块。
    sep_idx = text.find("\n\n")
    if sep_idx == -1:
        return {"status": 0, "headers": {}, "body": text, "error": "no header/body separator"}
    headers_block = text[:sep_idx]
    body_block = text[sep_idx + 2:]

    # 跳过任何 ``HTTP/X 100 Continue`` 前缀及其后的空行。
    while headers_block.split("\n", 1)[0].find(" 100 ") != -1:
        next_sep = body_block.find("\n\n")
        if next_sep == -1:
            return {"status": 0, "headers": {}, "body": body_block,
                    "error": "unterminated 100 Continue preface"}
        headers_block = body_block[:next_sep]
        body_block = body_block[next_sep + 2:]

    lines = headers_block.split("\n")
    status_line = lines[0] if lines else ""
    # "HTTP/1.1 404 Not Found" 或 "HTTP/2 404"
    parts = status_line.split(" ", 2)
    status = 0
    if len(parts) >= 2:
        try:
            status = int(parts[1])
        except ValueError:
            status = 0

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()

    return {
        "status": status,
        "headers": headers,
        "body": body_block,
        "error": None,
    }


def _populate_stream_signals(event: dict, signals: StreamSignals) -> None:
    """将单个已解析 SSE 事件 dict 分发到 ``signals`` 中（原地修改，永不抛异常——格式错误的
    字段静默忽略，故一个坏事件不会中止其余解析）。放在模块作用域以便单元测试。"""
    signals.raw_event_count += 1
    event_type = event.get("type", "")
    if isinstance(event_type, str) and event_type:
        signals.event_types.append(event_type)

    if event_type == "message_start":
        signals.has_message_start = True
        message = event.get("message", {})
        if isinstance(message, dict):
            model_name = message.get("model")
            if isinstance(model_name, str):
                signals.message_start_model = model_name
            usage = message.get("usage", {})
            if isinstance(usage, dict):
                input_tokens = usage.get("input_tokens")
                if isinstance(input_tokens, int):
                    signals.input_tokens = input_tokens

    elif event_type == "content_block_start":
        signals.has_content_block_start = True
        block = event.get("content_block", {})
        if isinstance(block, dict):
            block_type = block.get("type", "")
            if isinstance(block_type, str) and block_type:
                signals.content_block_types.append(block_type)
            if block.get("type") == "thinking":
                signals.thinking_start_seen = True

    elif event_type == "content_block_delta":
        signals.has_content_block_delta = True
        delta = event.get("delta", {})
        if isinstance(delta, dict):
            delta_type = delta.get("type")
            if isinstance(delta_type, str) and delta_type:
                signals.delta_types.append(delta_type)

            if delta_type == "text_delta":
                signals.has_text_delta = True
            elif delta_type == "thinking_delta":
                signals.thinking_delta_seen = True
            elif delta_type == "signature_delta":
                signature = delta.get("signature")
                if isinstance(signature, str) and not signature.strip():
                    signals.empty_signature_delta_count += 1

    elif event_type == "message_delta":
        signals.has_message_delta = True
        usage = event.get("usage", {})
        if isinstance(usage, dict):
            input_tokens = usage.get("input_tokens")
            if isinstance(input_tokens, int):
                signals.message_delta_input_tokens_samples.append(input_tokens)
            output_tokens = usage.get("output_tokens")
            if isinstance(output_tokens, int):
                signals.output_tokens_samples.append(output_tokens)

    elif event_type == "message_stop":
        signals.has_message_stop = True


# v1.7.1 安全阀：为 SSE 解析器缓冲区设上限，使一个畸形/恶意中转站
# 发送无换行的超大块时无法让内存无限增长。1 MB 足以容纳任何真实的
# Anthropic 事件（最大的 thinking 块约 100 KB）。
MAX_STREAM_BUFFER_BYTES = 1024 * 1024
CURL_STATUS_SENTINEL = "__CODEX_HTTP_STATUS__:"


def _process_sse_line(line: str, signals: StreamSignals) -> bool:
    """解析单行 SSE 并更新 ``signals``。见到 ``data: [DONE]`` 哨兵返回 ``True``（调用方应停止）。
    跳过非 ``data: `` 开头的行与格式错误的 JSON（不中止流）。"""
    line = line.strip()
    if not line.startswith("data: "):
        return False
    data = line[6:]
    if data == "[DONE]":
        return True
    try:
        event = json.loads(data)
    except json.JSONDecodeError:
        return False
    if isinstance(event, dict):
        _populate_stream_signals(event, signals)
    return False


def _parse_sse_stream(byte_iterator, signals: StreamSignals,
                      hasher=None) -> None:
    """消费字节迭代器，用每个 SSE 事件填充 ``signals``（原地修改，永不抛异常）。

    健壮性处理：UTF-8 序列中间断裂的多字节块（``errors="ignore"``）、单块多事件、
    跨块单事件（缓冲到换行）、``[DONE]`` 哨兵、格式错误 JSON 静默跳过、不以换行结尾
    的流（耗尽后冲刷残留行）、>1 MB 无换行的对抗性流（设 ``transport_error`` 并中止）。

    ``hasher`` 非 None 时每个原始块喂给 ``hasher.update()``，用于透明日志的增量流 SHA-256。
    """
    buffer = ""
    for chunk in byte_iterator:
        # v1.7.7：为透明日志做增量流哈希。
        if hasher is not None:
            if isinstance(chunk, (bytes, bytearray)):
                hasher.update(chunk)
            else:
                hasher.update(chunk.encode("utf-8", errors="ignore"))

        if isinstance(chunk, (bytes, bytearray)):
            buffer += chunk.decode("utf-8", errors="ignore")
        else:
            buffer += chunk

        # v1.7.1：对抗性或损坏流的缓冲区无限增长安全阀。合规中转站
        # 在到达此检查前已通过换行分割排空缓冲区；只有未终止的行才会
        # 推过上限。
        if len(buffer) > MAX_STREAM_BUFFER_BYTES:
            signals.transport_error = (
                f"SSE stream buffer exceeded {MAX_STREAM_BUFFER_BYTES} bytes "
                "(unterminated line — possible malformed or malicious stream)"
            )
            return

        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            if _process_sse_line(line, signals):
                return  # [DONE] 哨兵

    # v1.7.1：若流在不以换行结尾的情况下结束（损坏或截断的中转站），
    # 冲刷任何残留的最后一行。
    if buffer:
        _process_sse_line(buffer, signals)


class APIClient:
    """自动检测 Anthropic 与 OpenAI 格式的统一 API 客户端。

    首次 ``call()`` 先试 Anthropic 原生消息格式，失败则回退到 OpenAI 兼容
    ``/chat/completions``。遇到 Python 层 SSL 错误时传输静默切换到 ``curl -sk``
    子进程，使审计能针对自签名中转站继续进行。
    """

    def __init__(self, base_url: str, api_key: str, model: str,
                 timeout: int = 120, verbose: bool = True):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.verbose = verbose
        self._format = None   # "anthropic" | "openai" | None（自动）
        self._use_curl = True
        self._transparent_logger = None  # Optional[TransparentLogger]

    @property
    def detected_format(self):
        return self._format

    def _log(self, msg: str):
        if self.verbose:
            print(msg)

    # -- 低层传输 -----------------------------------------------------------

    def _curl_post(self, url: str, headers: dict, body: dict) -> dict:
        return curl_post_json(
            url, headers, body, self.timeout, subprocess_module=subprocess)

    def _post(self, url: str, headers: dict, body: dict) -> dict:
        if self._use_curl:
            return self._curl_post(url, headers, body)
        return curl_post_json(
            url, headers, body, self.timeout)

    @staticmethod
    def _error_result(error, **extra):
        error_text = str(error)
        result = {
            "error": error_text,
            "diagnosis": diagnose_error(error_text),
        }
        result.update(extra)
        return result

    # -- Anthropic 原生格式 -------------------------------------------------

    def _call_anthropic(self, messages, system=None, max_tokens=512):
        url = self.base_url
        if url.endswith("/v1"):
            url = url[:-3]
        url += "/v1/messages"

        body = {"model": self.model, "max_tokens": max_tokens, "messages": messages}
        if system:
            body["system"] = system
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        data = self._post(url, headers, body)
        if "_http_error" in data:
            return self._error_result(data["_http_error"])
        text = _text_from_content(data.get("content"))
        usage = data.get("usage", {})
        return {
            "text": text,
            "input_tokens": usage.get("input_tokens", 0),
            "output_tokens": usage.get("output_tokens", 0),
            "raw": data,
        }

    # -- OpenAI 兼容格式 ----------------------------------------------------

    def _call_openai(self, messages, system=None, max_tokens=512):
        url = self.base_url
        if not url.endswith("/v1"):
            url += "/v1"
        url += "/chat/completions"

        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.extend(messages)
        body = {"model": self.model, "max_tokens": max_tokens, "messages": msgs}
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "content-type": "application/json",
        }

        data = self._post(url, headers, body)
        if "_http_error" in data:
            return self._error_result(data["_http_error"])
        choice = data.get("choices", [{}])[0]
        text = choice.get("message", {}).get("content", "")
        usage = data.get("usage", {})
        return {
            "text": text,
            "input_tokens": usage.get("prompt_tokens", 0),
            "output_tokens": usage.get("completion_tokens", 0),
            "raw": data,
        }

    # -- 公共 API -----------------------------------------------------------

    def ensure_format(self):
        """强制完成格式自动检测的预热调用。Step 12 延迟方差计时对检测代价敏感——对 OpenAI
        兼容中转站的首次 ``call()`` 会先发一次失败的 Anthropic 探针再发成功的 OpenAI 请求，
        使第一个样本实际是 2 个往返；计时前调本方法丢弃该代价，使每个被测样本都相同。
        至多一次 ``max_tokens=1`` 的 ``call()``，吞掉任何错误。"""
        if self._format is not None:
            return
        try:
            self.call(
                [{"role": "user", "content": "ok"}],
                max_tokens=1,
            )
        except Exception:
            pass

    def call(self, messages, system=None, max_tokens=512):
        """发送一次聊天补全请求，首次调用时自动检测格式。记录挂钟耗时并作为 ``"time"`` 键
        附加到返回 dict。成功时含 ``text``/``input_tokens``/``output_tokens``/``raw``/``time``；
        失败时含 ``error`` 与 ``time``。"""
        start = time.time()
        request_body = json.dumps({"model": self.model, "max_tokens": max_tokens,
                                   "messages": messages, "system": system or ""})
        try:
            result = self._call_with_detection(messages, system, max_tokens)
            result["time"] = time.time() - start
            # v1.7.7 透明日志
            self._log_transparent(
                "call", self._resolve_call_url(), "POST",
                request_body, json.dumps(result.get("raw", {})),
                200 if "error" not in result else 0,
                None, result["time"], result.get("error"))
            return result
        except Exception as e:
            elapsed = time.time() - start
            self._log_transparent(
                "call", self._resolve_call_url(), "POST",
                request_body, None, 0, None, elapsed, str(e))
            return self._error_result(e, time=elapsed)

    def _resolve_call_url(self) -> str:
        base = self.base_url
        if self._format == "openai":
            if not base.endswith("/v1"):
                base += "/v1"
            return base + "/chat/completions"
        # anthropic 或未知——默认走 anthropic 路径
        if base.endswith("/v1"):
            base = base[:-3]
        return base + "/v1/messages"

    def _call_with_detection(self, messages, system, max_tokens):
        # 已检测过——使用该格式
        if self._format == "openai":
            return self._call_openai(messages, system, max_tokens)
        if self._format == "anthropic":
            return self._call_anthropic(messages, system, max_tokens)

        # 自动检测：先试 Anthropic
        anthropic_result = None
        try:
            anthropic_result = self._call_anthropic(messages, system, max_tokens)
            if "error" not in anthropic_result and anthropic_result.get("text", "").strip():
                self._format = "anthropic"
                self._log("  [format] -> Anthropic native")
                return anthropic_result
        except Exception as e:
            if self._handle_ssl_error(e):
                # 回退到 OpenAI 前先用 curl 重试 Anthropic
                try:
                    anthropic_result = self._call_anthropic(messages, system, max_tokens)
                    if "error" not in anthropic_result and anthropic_result.get("text", "").strip():
                        self._format = "anthropic"
                        self._log("  [format] -> Anthropic native (curl)")
                        return anthropic_result
                except Exception:
                    pass  # 进入 OpenAI 探针

        # 回退到 OpenAI
        self._log("  [format] Anthropic failed/empty, trying OpenAI...")
        openai_result = None
        try:
            openai_result = self._call_openai(messages, system, max_tokens)
            if "error" not in openai_result and openai_result.get("text", "").strip():
                self._format = "openai"
                suffix = " (curl)" if self._use_curl else ""
                self._log(f"  [format] -> OpenAI compatible{suffix}")
                return openai_result
        except Exception as e:
            if self._handle_ssl_error(e):
                return self._call_with_detection(messages, system, max_tokens)

        # 两者都失败——返回信息更多的那个
        if anthropic_result and "error" not in anthropic_result:
            self._format = "anthropic"
            return anthropic_result
        if openai_result and "error" not in openai_result:
            self._format = "openai"
            return openai_result
        return anthropic_result or openai_result or self._error_result("Both formats failed")

    def _handle_ssl_error(self, e: Exception) -> bool:
        """在 SSL 错误时切换到 curl。返回是否值得重试。"""
        if not self._use_curl and ("SSL" in str(e) or "Connect" in type(e).__name__):
            self._use_curl = True
            self._log("  [transport] Python SSL error, switching to curl")
            return True
        return False

    # -- 透明取证日志（v1.7.7，arXiv §7.3）--------------------------------

    def set_transparent_logger(self, logger):
        self._transparent_logger = logger

    def _log_transparent(self, method_name: str, url: str,
                         http_method: str, request_body_bytes,
                         response_body_bytes, status_code: int,
                         response_headers, elapsed: float,
                         error=None):
        """若挂载了透明日志器则写一条 JSONL 记录。``response_body_bytes`` 可为原始数据
        （str/bytes，会被哈希），也可为来自增量流哈希的预计算 64 字符十六进制摘要串（原样透传）。"""
        if self._transparent_logger is None:
            return
        # 来自流哈希的预计算摘要是 64 字符十六进制串。
        if isinstance(response_body_bytes, str) and len(response_body_bytes) == 64:
            try:
                int(response_body_bytes, 16)
                resp_hash = response_body_bytes
            except ValueError:
                resp_hash = sha256hex(response_body_bytes)
        else:
            resp_hash = sha256hex(response_body_bytes)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": method_name,
            "url": url,
            "http_method": http_method,
            "request_body_sha256": sha256hex(request_body_bytes),
            "response_body_sha256": resp_hash,
            "status_code": status_code,
            "response_headers": response_headers,
            "tls_version": None,   # 推迟到后续提交
            "tls_cipher": None,    # 推迟到后续提交
            "elapsed_seconds": round(elapsed, 3),
            "transport": "curl" if self._use_curl else "httpx",
            "error": redact_error(error),
        }
        self._transparent_logger.log_entry(entry)

    def get_models(self):
        """从 ``/v1/models`` 拉取模型列表。两种鉴权风格（Bearer 与 x-api-key）都试，
        失败返回空列表。"""
        url = self.base_url
        if not url.endswith("/v1"):
            url += "/v1"
        url += "/models"

        # 两种鉴权风格都试：先 OpenAI Bearer，再 Anthropic x-api-key
        auth_variants = [
            {"Authorization": f"Bearer {self.api_key}"},
            {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
        ]
        # 若格式已检测到，先试匹配的鉴权
        if self._format == "anthropic":
            auth_variants.reverse()

        start = time.time()
        for headers in auth_variants:
            try:
                if self._use_curl:
                    data = curl_get_json_data(
                        url, headers, subprocess_module=subprocess)
                    if data:
                        self._log_transparent(
                            "get_models", url, "GET", None,
                            json.dumps(data), 200, None,
                            time.time() - start)
                        return data
                else:
                    status, data, text, response_headers = httpx_get_json_data(
                        url, headers)
                    if status == 200 and data:
                        self._log_transparent(
                            "get_models", url, "GET", None,
                            text, 200, response_headers,
                            time.time() - start)
                        return data
            except Exception:
                continue
        self._log_transparent(
            "get_models", url, "GET", None, None, 0, None,
            time.time() - start, "all auth variants failed")
        return []

    # -- 原始请求（Step 9 错误泄露探针）------------------------------------

    def raw_request(self, method: str, path: str, headers: dict,
                    body: bytes, content_type: str = "application/json",
                    timeout: int = 30) -> dict:
        """保留完整响应正文与头部的低层请求。绕过常规 ``_post`` 的状态码错误处理，使 Step 9
        错误泄露探针能逐字检查错误响应。永不抛异常；传输失败返回 ``status == 0`` 且带 ``error``
        的 ``{"status", "headers", "body", "error"}``。"""
        base = self.base_url
        if base.endswith("/v1") and path.startswith("/v1"):
            base = base[:-3]
        url = base + path

        start = time.time()
        if self._use_curl:
            result = self._curl_raw_request(method, url, headers, body, content_type, timeout)
            self._log_transparent(
                "raw_request", url, method, body, result.get("body"),
                result.get("status", 0), result.get("headers"),
                time.time() - start, result.get("error"))
            return result
        try:
            result = httpx_raw_request(
                method, url, headers, body, content_type, timeout)
            self._log_transparent(
                "raw_request", url, method, body, result.get("body"),
                result.get("status", 0), result.get("headers"),
                time.time() - start)
            return result
        except Exception as e:
            # SSL / 连接错误时透明回退到 curl，使审计即使在中转站使用
            # 自签名证书时也能检查其错误面。
            if self._handle_ssl_error(e):
                result = self._curl_raw_request(method, url, headers, body, content_type, timeout)
                self._log_transparent(
                    "raw_request", url, method, body, result.get("body"),
                    result.get("status", 0), result.get("headers"),
                    time.time() - start, result.get("error"))
                return result
            self._log_transparent(
                "raw_request", url, method, body, None,
                0, None, time.time() - start, str(e))
            return {"status": 0, "headers": {}, "body": "", "error": str(e)}

    def _curl_raw_request(self, method: str, url: str, headers: dict,
                          body: bytes, content_type: str, timeout: int) -> dict:
        """``raw_request`` 的 curl 回退：用 ``curl -sk -i -X <method>`` 在 stdout 同时捕获头部与正文（``-k`` 忽略自签名证书错误）。"""
        return curl_raw_request(
            method, url, headers, body, content_type, timeout,
            parser=_parse_curl_i_output, subprocess_module=subprocess)

    # -- 流式（Step 10 流完整性）------------------------------------------

    def stream_call(self, messages, system=None, max_tokens=512,
                    with_thinking: bool = True, timeout: int = 120) -> StreamSignals:
        """打开一个 Anthropic 格式流式请求并捕获 SSE 信号。**仅支持 Anthropic**（SSE schema 与
        OpenAI 不同，Step 10 白名单针对 Anthropic 事件形状）；纯 OpenAI 端点会返回非 200 或不符
        白名单的流，调用方应视为 *inconclusive*。永不抛异常——传输错误全写入
        :attr:`StreamSignals.transport_error`；零事件返回且 ``transport_error is None`` 是合法的
        （中转站干净打开流但未产数据）。"""
        url = self.base_url
        if url.endswith("/v1"):
            url = url[:-3]
        url += "/v1/messages"

        body = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": messages,
            "stream": True,
        }
        if system:
            body["system"] = system
        if with_thinking:
            # thinking.budget_tokens 必须严格小于 max_tokens
            body["thinking"] = {
                "type": "enabled",
                "budget_tokens": max(1, max_tokens - 1),
            }

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
            "accept": "text/event-stream",
        }

        signals = StreamSignals()
        # v1.7.7：为透明日志做流式 SHA-256 的增量哈希器。
        hasher = hashlib.sha256() if self._transparent_logger else None
        request_body_json = json.dumps(body)
        start = time.time()
        try:
            self._stream_via_curl(url, headers, body, timeout, signals, hasher)
        except Exception as e:
            if signals.transport_error is None:
                signals.transport_error = str(e)
        finally:
            signals.total_duration_seconds = time.time() - start
            self._log_transparent(
                "stream_call", url, "POST", request_body_json,
                hasher.hexdigest() if hasher else None,
                200 if signals.transport_error is None else 0,
                None, signals.total_duration_seconds,
                signals.transport_error)

        return signals

    def _stream_via_curl(self, url: str, headers: dict, body: dict,
                         timeout: int, signals: StreamSignals,
                         hasher=None) -> None:
        """:meth:`stream_call` 的 curl 分支：``curl -N --no-buffer`` 禁用 curl 输出缓冲使 SSE 事件一到就吐到 stdout，
        请求体经 stdin 管道传入。逐行读 stdout 使短帧在 curl flush 时即被产出（v1.8.2：``read(4096)`` 会
        阻塞到缓冲填满，使流退化为缓冲式抓取而非增量流）。"""
        cmd = [
            "curl", "-sk", *curl_loopback_no_proxy_args(url),
            "-N", "--no-buffer", "-X", "POST", url,
            "--max-time", str(timeout),
            "-w", f"\n{CURL_STATUS_SENTINEL}%{{http_code}}\n",
            "--data-binary", "@-",
        ]
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])

        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                proc.stdin.write(json.dumps(body).encode("utf-8"))
                proc.stdin.close()
            except (BrokenPipeError, OSError):
                # curl 已死（如 SSL 握手失败）；让下面的 wait() + stderr
                # 读取报告真实原因。
                pass

            def iter_stdout():
                status_prefix = CURL_STATUS_SENTINEL.encode("utf-8")
                while True:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    stripped = line.strip()
                    if stripped.startswith(status_prefix):
                        try:
                            http_status[0] = int(
                                stripped[len(status_prefix):].decode("ascii", errors="ignore")
                            )
                        except ValueError:
                            pass
                        continue
                    if not line.lstrip().startswith(b"data: "):
                        preview = line.decode("utf-8", errors="replace").strip()
                        if preview and len(non_sse_preview) < 4:
                            non_sse_preview.append(preview)
                        continue
                    yield line

            http_status = [None]
            non_sse_preview = []
            _parse_sse_stream(iter_stdout(), signals, hasher)
            proc.wait(timeout=timeout + 10)
            if signals.transport_error is None and http_status[0] is not None and http_status[0] >= 400:
                preview = " ".join(non_sse_preview)[:200]
                if preview:
                    signals.transport_error = (
                        f"HTTP {http_status[0]} on stream open (non-SSE body: {preview})"
                    )
                else:
                    signals.transport_error = f"HTTP {http_status[0]} on stream open"
            elif signals.transport_error is None and signals.raw_event_count == 0 and non_sse_preview:
                signals.transport_error = (
                    f"Non-SSE stream response: {' '.join(non_sse_preview)[:200]}"
                )
            if proc.returncode != 0:
                # v1.7.1 Codex 修复：任何非零 curl 退出都必须设置
                # transport_error，使 analyze_stream 返回 inconclusive。
                # 之前 ``and signals.raw_event_count == 0`` 的守卫静默吞掉了
                # 流中途失败，并把截断的流判定为 clean。已解析的 signals
                # 会保留以便调试。
                err = proc.stderr.read().decode("utf-8", errors="replace")[:200]
                if signals.transport_error is None:
                    signals.transport_error = f"curl failed: {err}"
        except subprocess.TimeoutExpired:
            if signals.transport_error is None:
                signals.transport_error = "curl stream timeout"
            try:
                proc.kill()
            except Exception:
                pass
        except Exception as e:
            if signals.transport_error is None:
                signals.transport_error = str(e)


# ============================================================
# Markdown \u62a5\u544a\u5668
# ============================================================

"""\u5ba1\u8ba1\u7ed3\u679c\u7684 Markdown \u62a5\u544a\u751f\u6210\u5668\u3002"""


class Reporter:
    """\u6784\u5efa\u5e26\u98ce\u9669\u6458\u8981\u5934\u7684\u7ed3\u6784\u5316 Markdown \u5ba1\u8ba1\u62a5\u544a\u3002\u5404\u5c0f\u8282\u7ecf\u8f85\u52a9\u65b9\u6cd5\uff08h1/h2/p/code/flag \u7b49\uff09
    \u7d2f\u79ef\uff0c\u7531 ``render()`` \u6e32\u67d3\u4e3a\u5355\u4e2a Markdown \u5b57\u7b26\u4e32\u3002"""

    def __init__(self):
        self.sections = []
        self.summary = []
        # 已开过 h2 的步骤编号（ensure_step 去重用，与 EventReporter._used_ids 对齐）。
        self._seen_step_no: set[int] = set()

    def h1(self, t):
        self.sections.append(f"\n# {t}\n")

    def h2(self, t):
        # 若是「N. label」形式，记下编号供 ensure_step 去重。
        m = re.match(r"^\s*(\d+)\.\s*(.+)$", t)
        if m:
            self._seen_step_no.add(int(m.group(1)))
        self.sections.append(f"\n## {t}\n")

    def ensure_step(self, step_no: int, label: str) -> None:
        """对漏发 h2 的步骤编号补一个 warn 占位终态（与 EventReporter 对齐）。

        run_registered_steps 末尾对每个步骤调用；正常发过 h2 的编号跳过。
        """
        if step_no in self._seen_step_no:
            return
        self._seen_step_no.add(step_no)
        self.h2(f"{step_no}. {label}")
        self.flag("yellow", "本步未产出结果（崩溃或被跳过）")

    def h3(self, t):
        self.sections.append(f"\n### {t}\n")

    def p(self, t):
        self.sections.append(f"{t}\n")

    def code(self, t, lang=""):
        self.sections.append(f"```{lang}\n{t}\n```\n")

    def flag(self, level, msg):
        """\u8bb0\u5f55\u4e00\u6761\u98ce\u9669\u53d1\u73b0\u5e76\u8ffd\u52a0\u4e00\u884c\u5e26\u8272\u6807\u8bb0\u3002``level``\uff08``"red"``/``"yellow"``/``"green"``\uff09\u51b3\u5b9a
        \u56fe\u6807\uff1b\u540c\u4e00\u53d1\u73b0\u540c\u65f6\u52a0\u5165 ``summary``\uff08\u62a5\u544a\u5934\u90e8\u98ce\u9669\u6458\u8981\uff09\u5e76\u4ee5\u5e26\u8272\u884c\u52a0\u5165\u6b63\u6587\u3002"""
        icon = {"red": "\U0001f534", "yellow": "\U0001f7e1", "green": "\U0001f7e2"}.get(level, "\u26aa")
        self.summary.append((level, msg))
        self.sections.append(f"{icon} **{msg}**\n")

    def render(self, target_url="", model=""):
        """\u6e32\u67d3\u5b8c\u6574 Markdown \u62a5\u544a\uff1a\u5148\u751f\u6210\u5934\u90e8\u5757\uff08\u6807\u9898\u3001\u5143\u6570\u636e\u3001\u98ce\u9669\u6458\u8981\uff09\uff0c\u540e\u63a5\u6240\u6709\u7d2f\u79ef\u5c0f\u8282\u4ee5\u6362\u884c\u62fc\u63a5\u3002"""
        header = (
            f"# API Relay Security Audit Report\n\n"
            f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
        )
        if target_url:
            header += f"**Target**: `{target_url}`\n"
        if model:
            header += f"**Model**: `{model}`\n"

        header += "\n## Risk Summary\n\n"
        for level, msg in self.summary:
            icon = {"red": "\U0001f534", "yellow": "\U0001f7e1", "green": "\U0001f7e2"}.get(level, "\u26aa")
            header += f"- {icon} {msg}\n"
        header += "\n---\n"
        return header + "\n".join(self.sections)


# ============================================================
# 连通性检查
# ============================================================

"""快速的 API 中转站连通性检查。

本模块有意比完整审计更窄。它发送一次低 token 的 Anthropic 风格聊天
请求和一次低 token 的 OpenAI 聊天请求，然后报告哪种格式可用。它不作
安全结论，也不喂给审计风险矩阵。
"""


CONNECTIVITY_PROMPT = "Reply with the single word: ok"
CONNECTIVITY_MAX_TOKENS = 8


@dataclass
class ConnectivityProbeResult:

    format_name: str
    endpoint: str
    auth_style: str
    status: int
    elapsed_seconds: float
    input_tokens: int | None
    output_tokens: int | None
    text_preview: str
    diagnostic: str
    success: bool


def _redact(text: str, api_key: str) -> str:
    if not text:
        return ""
    if api_key:
        text = text.replace(api_key, "[redacted-api-key]")
    return text


def _markdown_escape(text: str) -> str:
    text = _redact(str(text), "")
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\n", " ")
        .replace("\r", " ")
        .strip()
    )


def _text_from_content(content) -> str:
    """从响应 ``content`` 提取文本：纯字符串直返，列表则拼接每个块的 ``text`` 字段。
    Anthropic 的 ``thinking``/``tool_use`` 块用各自字段而非 ``text``，故只取 ``text`` 即天然跳过
    它们（无需显式判 ``type``）——这避免了旧 ``content[0].text`` 捷径在响应以 thinking 块开头时
    返回空、进而使自动检测误翻到 OpenAI 探针的问题。"""
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts = []
    for block in content:
        if isinstance(block, dict):
            text = block.get("text")
            if isinstance(text, str):
                parts.append(text)
    return "".join(parts)


def _parse_anthropic_response(data: dict) -> tuple[str, int | None, int | None]:
    usage = data.get("usage", {}) if isinstance(data, dict) else {}
    if not isinstance(usage, dict):
        usage = {}
    return (
        _text_from_content(data.get("content")),
        usage.get("input_tokens") if isinstance(usage.get("input_tokens"), int) else None,
        usage.get("output_tokens") if isinstance(usage.get("output_tokens"), int) else None,
    )


def _parse_openai_response(data: dict) -> tuple[str, int | None, int | None]:
    usage = data.get("usage", {}) if isinstance(data, dict) else {}
    if not isinstance(usage, dict):
        usage = {}
    choices = data.get("choices", []) if isinstance(data, dict) else []
    first_choice = choices[0] if choices and isinstance(choices[0], dict) else {}
    message = first_choice.get("message", {})
    text = ""
    if isinstance(message, dict):
        text = _text_from_content(message.get("content"))
    if not text:
        text = _text_from_content(first_choice.get("text"))
    return (
        text,
        usage.get("prompt_tokens") if isinstance(usage.get("prompt_tokens"), int) else None,
        usage.get("completion_tokens") if isinstance(usage.get("completion_tokens"), int) else None,
    )


def _headers_summary(headers: dict) -> str:
    if not headers:
        return "no response headers"
    lowered = {str(k).lower(): str(v) for k, v in headers.items()}
    parts = []
    content_type = lowered.get("content-type")
    if content_type:
        parts.append(f"content-type {content_type.split(';', 1)[0]}")
    request_headers = [
        name for name in ("request-id", "x-request-id", "x-openai-request-id")
        if name in lowered
    ]
    if request_headers:
        parts.append("request id present")
    return ", ".join(parts) if parts else f"{len(headers)} response headers"


def _status_diagnostic(status: int, error: str | None) -> str:
    if status == 0:
        return f"Transport failure: {error or 'request did not complete'}"
    if status in (401, 403):
        return "Authentication or authorization failed; check key, model access, balance, and auth style."
    if status == 404:
        return "Endpoint not found; check the base URL and whether this relay supports the format."
    if status == 429:
        return "Rate limited or quota exhausted; check relay quota or retry later."
    if status == 400:
        return "Bad request; the relay may not support this format or model."
    if status >= 500:
        return "Relay or upstream server error."
    if 200 <= status < 300:
        return "HTTP 2xx received but no usable text was parsed."
    return f"HTTP {status} received; inspect relay configuration and model access."


def _probe(client, format_name: str, endpoint: str, auth_style: str,
           headers: dict, body: dict, parser) -> ConnectivityProbeResult:
    start = time.time()
    response = client.raw_request(
        "POST",
        endpoint,
        headers,
        json.dumps(body).encode("utf-8"),
        content_type="application/json",
        timeout=client.timeout,
    )
    elapsed = time.time() - start
    status = int(response.get("status", 0) or 0)
    response_error = _redact(str(response.get("error") or ""), client.api_key)
    diagnostic = _status_diagnostic(status, response_error)
    text = ""
    input_tokens = None
    output_tokens = None
    success = False

    if 200 <= status < 300:
        try:
            data = json.loads(response.get("body") or "")
        except json.JSONDecodeError:
            diagnostic = "HTTP 2xx received but response was not valid JSON."
        else:
            text, input_tokens, output_tokens = parser(data)
            text = _redact(text.strip(), client.api_key)
            if text:
                success = True
                diagnostic = f"OK: parsed non-empty text; {_headers_summary(response.get('headers', {}))}."
            else:
                diagnostic = "HTTP 2xx received but response JSON did not contain parsed text."

    return ConnectivityProbeResult(
        format_name=format_name,
        endpoint=endpoint,
        auth_style=auth_style,
        status=status,
        elapsed_seconds=elapsed,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        text_preview=text[:80],
        diagnostic=_redact(diagnostic, client.api_key),
        success=success,
    )


def _render_token_count(value: int | None) -> str:
    return str(value) if isinstance(value, int) else "-"


def _render_status(status: int) -> str:
    return str(status) if status else "transport"


def _next_step(verdict: str, client) -> str:
    url = shlex.quote(client.base_url)
    model = shlex.quote(client.model)
    if verdict in ("OK", "WARNING"):
        return (
            "Connectivity reached at least one chat format. For the full security audit, run:\n\n"
            "```bash\n"
            "export API_RELAY_AUDIT_KEY=sk-...\n"
            f"python3 audit.py --key \"$API_RELAY_AUDIT_KEY\" --url {url} --model {model} --output report.md\n"
            "```"
        )
    return (
        "Connectivity failed for both chat formats. Check the base URL, API key, "
        "model name, relay balance/quota, and whether the relay supports Anthropic "
        "or OpenAI Chat endpoints before running the full audit."
    )


def render_connectivity_report(result: dict) -> str:
    client = result["client"]
    verdict = result["verdict"]
    lines = [
        "# API Relay Connectivity Report",
        "",
        f"**Target**: `{client.base_url}`",
        f"**Model**: `{client.model}`",
        f"**Timeout**: `{client.timeout}s`",
        f"**Connectivity Verdict**: **{verdict}**",
        "",
        "This is a quick connectivity check, not a security audit. It does not produce a LOW/MEDIUM/HIGH risk rating.",
        "",
        "## Probe Results",
        "",
        "| Format | Endpoint | Auth style | HTTP status | Elapsed | Tokens | Text preview | Diagnostic |",
        "|---|---|---|---:|---:|---:|---|---|",
    ]
    for probe in result["probes"]:
        tokens = (
            f"{_render_token_count(probe.input_tokens)}/"
            f"{_render_token_count(probe.output_tokens)}"
        )
        lines.append(
            "| "
            f"{_markdown_escape(probe.format_name)} | "
            f"`{_markdown_escape(probe.endpoint)}` | "
            f"{_markdown_escape(probe.auth_style)} | "
            f"{_render_status(probe.status)} | "
            f"{probe.elapsed_seconds:.3f}s | "
            f"{tokens} | "
            f"{_markdown_escape(probe.text_preview) or '-'} | "
            f"{_markdown_escape(probe.diagnostic)} |"
        )
    lines.extend([
        "",
        "## Next Step",
        "",
        _next_step(verdict, client),
        "",
    ])
    return "\n".join(lines)


def run_connectivity_check(client) -> dict:
    common_messages = [{"role": "user", "content": CONNECTIVITY_PROMPT}]
    probes = [
        _probe(
            client,
            "Anthropic Chat",
            "/v1/messages",
            "x-api-key",
            {
                "x-api-key": client.api_key,
                "anthropic-version": "2023-06-01",
            },
            {
                "model": client.model,
                "max_tokens": CONNECTIVITY_MAX_TOKENS,
                "messages": common_messages,
            },
            _parse_anthropic_response,
        ),
        _probe(
            client,
            "OpenAI Chat",
            "/v1/chat/completions",
            "Authorization: Bearer",
            {
                "Authorization": f"Bearer {client.api_key}",
            },
            {
                "model": client.model,
                "max_tokens": CONNECTIVITY_MAX_TOKENS,
                "messages": common_messages,
            },
            _parse_openai_response,
        ),
    ]
    success_count = sum(1 for probe in probes if probe.success)
    if success_count == len(probes):
        verdict = "OK"
    elif success_count:
        verdict = "WARNING"
    else:
        verdict = "FAILED"
    result = {
        "client": client,
        "probes": probes,
        "verdict": verdict,
        "success": success_count > 0,
        "successful_formats": [probe.format_name for probe in probes if probe.success],
    }
    result["markdown"] = render_connectivity_report(result)
    return result


# ============================================================
# 上下文长度扫描
# ============================================================

"""共享的上下文长度测试逻辑（金丝雀标记 + 二分查找）。"""


# ============================================================
# 错误诊断辅助函数
# ============================================================

"""面向用户的中转站/API 错误诊断辅助函数。

本模块把简短的传输或 HTTP 错误转换为稳定、可报告的解释。它有意只作信息
性用途：诊断帮助用户修复连通性/配置问题，但不改变任何检测器判定或整体
风险矩阵分支。
"""


_HTTP_STATUS_RE = re.compile(r"\bHTTP\s+(\d{3})\b", re.IGNORECASE)


def _coerce_status(status):
    if status is None:
        return None
    try:
        value = int(status)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def _status_from_error(error):
    match = _HTTP_STATUS_RE.search(str(error or ""))
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _diagnosis(category, summary, likely_cause, suggested_action):
    return {
        "category": category,
        "summary": summary,
        "likely_cause": likely_cause,
        "suggested_action": suggested_action,
    }


def diagnose_error(error=None, status=None):
    """返回针对 HTTP/传输错误的结构化诊断（含 ``category``/``summary``/``likely_cause``/``suggested_action``）。
    ``status`` 参数优先于从 ``error`` 文本解析出的状态。**永不抛异常，也永不把任何错误视为安全**——
    仅解释最可能的运维原因，不改变任何检测器判定或风险矩阵分支。"""
    text = str(error or "").strip()
    text_lower = text.lower()
    status_code = _coerce_status(status) or _status_from_error(text)

    if status_code == 400:
        return _diagnosis(
            "bad-request",
            "Request shape rejected by the relay.",
            "The selected API format, model name, message schema, or content-type may not match this relay.",
            "Verify the base URL, model id, and whether the relay expects Anthropic messages or OpenAI chat completions.",
        )
    if status_code == 401:
        return _diagnosis(
            "auth",
            "Authentication failed.",
            "The API key is invalid, expired, copied with extra whitespace, or not accepted by this relay.",
            "Check the key in the provider dashboard and retry with a freshly copied key.",
        )
    if status_code == 403:
        return _diagnosis(
            "permission",
            "The relay rejected an authenticated request.",
            "The account may lack model access, have billing/credit problems, or be blocked from this API format.",
            "Check account balance, model permissions, regional restrictions, and relay-side allowlists.",
        )
    if status_code == 404:
        return _diagnosis(
            "endpoint",
            "Endpoint not found.",
            "The base URL may be missing or duplicating a /v1 prefix, or the relay may not expose this route.",
            "Try the relay's documented base URL and avoid appending /messages or /chat/completions manually.",
        )
    if status_code == 408:
        return _diagnosis(
            "timeout",
            "The relay timed out the request.",
            "The relay or upstream provider did not answer before the HTTP timeout.",
            "Retry once, then increase --timeout or run with slower steps skipped to isolate the failing probe.",
        )
    if status_code == 413:
        return _diagnosis(
            "payload-too-large",
            "Request body is too large for the relay.",
            "The relay may enforce a smaller payload/context limit than the advertised model.",
            "Retry with --fast-context or --skip-context, then run the full context test only if the relay supports it.",
        )
    if status_code == 422:
        return _diagnosis(
            "unprocessable",
            "Request schema was understood but rejected.",
            "Common causes are unsupported system prompts, unsupported model ids, or a relay-specific schema restriction.",
            "Verify model access and whether this relay accepts custom system prompts for the selected format.",
        )
    if status_code == 429:
        return _diagnosis(
            "rate-limit",
            "Rate limit or quota was hit.",
            "The relay or upstream provider is throttling this key, account, or model.",
            "Wait and retry with --skip-context or a lower --latency-probe-count, or upgrade the relay/provider quota.",
        )
    if status_code in (500, 502, 503, 504):
        return _diagnosis(
            "upstream-or-relay",
            "Relay or upstream provider error.",
            "The relay backend, gateway, or upstream model provider failed while handling the request.",
            "Retry later; if it repeats, share the redacted report with the relay operator and inspect Step 9 for leakage.",
        )
    if status_code is not None and status_code >= 400:
        return _diagnosis(
            "http-error",
            f"HTTP {status_code} error from the relay.",
            "The relay returned a non-success status that is not mapped to a more specific diagnosis.",
            "Check the raw response, relay documentation, selected model, and account state.",
        )

    if "both formats failed" in text_lower:
        return _diagnosis(
            "format-detection",
            "Neither Anthropic nor OpenAI chat format produced a usable response.",
            "The base URL may be wrong, the key may be invalid, or the relay may require a different API family.",
            "Run a minimal vendor curl command from the relay docs, then retry with the documented base URL and model id.",
        )
    if "cors" in text_lower or "failed to fetch" in text_lower:
        return _diagnosis(
            "browser-cors",
            "Browser access was blocked before a normal API response was available.",
            "The relay likely does not allow browser-origin requests or hides responses from frontend JavaScript.",
            "Run the generated curl command in a terminal; terminal requests are not subject to browser CORS.",
        )
    if "ssl" in text_lower or "certificate" in text_lower or "tls" in text_lower:
        return _diagnosis(
            "tls",
            "TLS/SSL connection failed.",
            "The relay certificate may be self-signed, expired, misconfigured, or blocked by the local trust store.",
            "Retry once; the audit client may fall back to curl, but treat persistent TLS failures as operator-quality evidence.",
        )
    if "timed out" in text_lower or "timeout" in text_lower:
        return _diagnosis(
            "timeout",
            "Request timed out before a response was received.",
            "The relay, upstream model, or local network path is too slow for the current timeout.",
            "Retry with --timeout increased, or skip long-running probes to determine whether only one step is slow.",
        )
    if (
        "connecterror" in text_lower
        or "connection refused" in text_lower
        or "connection reset" in text_lower
        or "name or service not known" in text_lower
        or "nodename nor servname" in text_lower
        or "could not resolve" in text_lower
        or "temporary failure in name resolution" in text_lower
    ):
        return _diagnosis(
            "network",
            "Network connection to the relay failed.",
            "DNS, firewall, proxy, VPN, or relay availability may be preventing any HTTP response.",
            "Check the base URL in a browser or with curl -I, then retry from the same network path.",
        )
    if "expecting value" in text_lower or "jsondecodeerror" in text_lower:
        return _diagnosis(
            "non-json",
            "Relay returned a non-JSON response where API JSON was expected.",
            "The endpoint may be an HTML landing page, reverse-proxy error page, or non-API route.",
            "Check the base URL and inspect the raw response with curl before running the full audit.",
        )
    if "empty curl output" in text_lower or "no header/body separator" in text_lower:
        return _diagnosis(
            "curl-output",
            "curl did not receive a parseable HTTP response.",
            "The relay closed the connection, returned malformed output, or an intermediary stripped the response.",
            "Retry with curl -i against the same URL and inspect whether any HTTP status line is present.",
        )
    if "curl failed" in text_lower:
        return _diagnosis(
            "curl",
            "curl transport failed.",
            "The fallback transport could not complete the request, often due to network, TLS, DNS, or proxy issues.",
            "Run curl --version and a minimal curl request to the relay, then retry the audit.",
        )

    return _diagnosis(
        "unknown",
        "Unmapped relay/API error.",
        "The audit received an error string that does not match a known operational bucket.",
        "Inspect the raw error, verify the key/base URL/model, and include the redacted report when asking the relay operator.",
    )


def format_diagnosis(diagnosis):
    return (
        f"**Diagnosis**: {diagnosis['summary']} "
        f"Likely cause: {diagnosis['likely_cause']} "
        f"Next step: {diagnosis['suggested_action']}"
    )


# ============================================================
# 错误响应泄露检测器
# ============================================================

"""错误响应头泄露测试（AC-2 邻接，Step 9）。

检测免费中转站上最常见的 AC-2 凭据外泄失败模式：中转站把自身的错误
输出代理回客户端，而该错误正文（或响应头）回显了我们发送的 Authorization
头、API key 的前 8 位前缀、一个上游供应商 URL、一个环境变量名、一个
文件系统路径，或一段堆栈跟踪。

Liu 等人《Your Agent Is Mine》（arXiv:2604.08407）图 3 报告，在 400 个
免费路由器中有 4.25% 存在凭据滥用——是代码注入重写（2%）的两倍多。
本模块是 AC-2 错误正文子类的客户端审计：如果中转站在错误响应里把我们
给它的东西又泄露回给我们，那么在其他条件下它几乎肯定也在向其他方泄露。

本测试发射六个确定性的「破坏我」请求（畸形 JSON、无效模型、错误的
content-type、缺失 messages 字段、未知端点，以及可选的 256 KB 超大
正文），通过 ``APIClient.raw_request`` 捕获完整响应正文与响应头，并按
严重程度排序扫描凭据 / PII 指标。

参考：Liu, Shou, Wen, Chen, Fang, Feng，《Your Agent Is Mine: Measuring
Malicious Intermediary Attacks on the LLM Supply Chain》，arXiv:2604.08407，
图 3 与 §4.2。
"""


# ============================================================
# 基础设施指纹
# ============================================================

"""基础设施指纹（Step 11，v1.8）。

从响应头与响应正文识别中转站框架家族（one-api / new-api / lobechat /
nginx / caddy / cloudflare …）。纯被动检测——v1.8 不作欺诈推断；该
发现仅为信息性，不喂入 6D 风险矩阵。

依据：Zhang 等人，《Real Money, Fake Models: Deceptive Model Claims in
Shadow APIs》，arXiv:2603.01919，§3.2 报告，17 个已识别的影子 API 中有
11 个构建于 OneAPI 及其衍生 NewAPI 开源后端之上。知道框架可让用户
(a) 评估运营者专业度，(b) 交叉比对已知框架级 CVE，(c) 区分一方中转站
与纯反向代理。本节与 Step 12 延迟方差配对，构成 v1.8 的「基础设施审计
层」。

检测面:
    - ``GET /``                          -- 落地页（通常为 HTML）
    - ``GET /v1/models``                 -- 401/200 正文、auth 头回显、
                                           ``x-powered-by``
    - ``GET /nonexistent-abc12345xyz``   -- 404 信封

信号与一份手工整理的框架专属子串小清单（位于头部与正文中）匹配。
某框架在 3 个探针中命中 >=2 为「confirmed」，命中 1 为「tentative」，
命中 0 为「unknown」。
"""


# ----------------------------------------------------------------------
# 框架签名数据库
# ----------------------------------------------------------------------


# ============================================================
# 延迟方差指纹
# ============================================================

"""延迟方差指纹（Step 12，v1.8）。

用 N 个相同的最小请求探测中转站，测量每次请求的端到端延迟。计算描述性
统计量（min、median、max、stdev、变异系数）与一个简单的双峰启发式。

依据：合法、直连上游供应商的连接在相同的低输出请求间表现出相对稳定的
延迟。一个静默 A/B 测试的中转站（把部分请求路由到宣传的 Claude、部分
路由到更便宜的量化模型或无关供应商）会产生**双峰**延迟：两个截然不同的
响应时间簇。类似地，通过共享批处理队列多路复用请求的中转站会呈现多峰
模式。

在 v1.8 中这是一个**弱信号**——仅信息性，不喂入 6D 风险矩阵。合法的
网络抖动、供应商侧预热以及区域性故障转移都可能在诚实的中转站上产生高
方差。但清晰的双峰分布仍值得向运营者标记，以提示深入调查（例如重跑
Step 11、捕获正文哈希、diff 模型声明）。

本节与 Step 11 基础设施指纹配对，构成 v1.8 的「基础设施审计层」。

## 分类规则

给定 ``count`` 个成功样本：

  count < 3                 -> "inconclusive"
  检测到双峰                -> "bimodal"
  CV < 0.25                 -> "stable"
  0.25 <= CV < 0.5          -> "variable"
  CV >= 0.5                 -> "high-variance"

双峰启发式：将样本排序后，寻找相邻值之间*能把样本分成每簇至少 2 个的*
最大间隙。若该间隙除以中位数大于 ``BIMODAL_GAP_THRESHOLD``（默认 0.5），
则分布存在可见簇断裂并标记为双峰。每簇 >=2 的规则可防止单个离群点被
误判为双峰。
"""


# ============================================================
# 审计编排
# ============================================================

"""
Token 中转站审计 v1.0

完整 14 步审计：基础实施侦察、模型列表、token 注入、prompt 提取、指令
冲突 + 身份、越狱、上下文长度、工具调用替换（AC-1.a）、错误响应泄露
（AC-2）、流完整性（AC-1 SSE）、
基础实施指纹、延迟方差、上游通道分类器。威胁分类法遵循 Liu 等人，
《Your Agent Is Mine》，arXiv:2604.08407（AC-1, AC-1.a, AC-1.b, AC-2）。
Step 11-13 源自 Zhang 等人，《Real Money, Fake Models》，arXiv:2603.01919。
Step 13 为 LLMprobe-engine `channel-signature.ts` 技术的净室重实现
（Bazaarlinkorg/LLMprobe-engine，AGPL-3.0）。

用法:
  python audit_py/main.py --key YOUR_KEY --url https://relay.example.com/v1 --model claude-opus-4-6
"""


# ============================================================
# CLI
# ============================================================

# Step 12 延迟探针数量校验范围（双峰检测需 ≥4 个样本才有意义）。
LATENCY_PROBE_MIN = 4
LATENCY_PROBE_MAX = 100


def validate_probe_count(value):
    """argparse type 钩子：校验 ``--latency-probe-count``。下限为 4 因双峰检测在样本 < 4 时无意义
    （``detect_bimodality`` 直接返回 False）；上限防止一次审计发射过多请求。"""
    n = int(value)
    if n < LATENCY_PROBE_MIN:
        raise argparse.ArgumentTypeError(
            f"--latency-probe-count 至少 {LATENCY_PROBE_MIN}"
            f"（双峰检测需 ≥4 个样本）；当前 {n}"
        )
    if n > LATENCY_PROBE_MAX:
        raise argparse.ArgumentTypeError(
            f"--latency-probe-count 至多 {LATENCY_PROBE_MAX}；当前 {n}"
        )
    return n


def run_warmup(client, warmup_n):
    """发送 ``warmup_n`` 次无害请求，缓解 AC-1.b request-count gate——某些恶意中转会设
    "前 N 次请求放行、之后才注入"的后门，审计前先把计数推过阈值才能观察到真实行为。
    单次失败静默跳过（不因网络抖动中断审计）。"""
    for i in range(warmup_n):
        try:
            client.call(
                [{"role": "user", "content": "Reply with the single word: ok"}],
                max_tokens=8,
            )
        except Exception:
            pass
        if i < warmup_n - 1:
            time.sleep(0.2)


def parse_args():
    p = argparse.ArgumentParser(description="API Relay Security Audit Tool")
    p.add_argument("--key", required=True, help="API Key")
    p.add_argument("--url", required=True, help="Base URL (e.g. https://xxx.com/v1)")
    p.add_argument("--model", default="claude-opus-4-6", help="Model name")
    p.add_argument("--connectivity", action="store_true",
                   help="Run a quick Anthropic/OpenAI Chat connectivity check "
                        "and exit without running the full 14-step audit.")
    p.add_argument("--skip-infra", action="store_true", help="Skip infrastructure recon")
    p.add_argument("--skip-context", action="store_true", help="Skip context length test")
    p.add_argument("--fast-context", action="store_true",
                   help="Use a reduced Step 7 context scan ladder "
                        "(10K/50K/100K/200K chars) to lower token cost. "
                        "Default is the full scan.")
    p.add_argument("--skip-tool-substitution", action="store_true",
                   help="Skip tool-call package substitution test (AC-1.a)")
    p.add_argument("--skip-error-leakage", action="store_true",
                   help="Skip error response header leakage test (Step 9, AC-2 adjacent)")
    p.add_argument("--aggressive-error-probes", action="store_true",
                   help="Enable the 256 KB oversized-context error probe in Step 9. "
                        "Warning: may incur metered billing on pay-as-you-go relays.")
    p.add_argument("--skip-stream-integrity", action="store_true",
                   help="Skip stream integrity test (Step 10). Useful if the "
                        "relay does not support Anthropic streaming.")
    p.add_argument("--skip-infra-fingerprint", action="store_true",
                   help="Skip Step 11 infrastructure fingerprinting "
                        "(framework family detection via header + body "
                        "signatures).")
    p.add_argument("--skip-latency-variance", action="store_true",
                   help="Skip Step 12 latency variance fingerprinting "
                        "(bimodality heuristic over N identical probes).")
    p.add_argument("--skip-channel-classifier", action="store_true",
                   help="Skip Step 13 upstream channel classifier "
                        "(one /v1/messages probe; classifies upstream as "
                        "AWS Bedrock / Vertex / Anthropic-official / "
                        "OpenRouter / CF-AI-Gateway / transparent relay).")
    p.add_argument("--skip-long-task", action="store_true",
                   help="Skip Step 14 long-task / multi-request integrity "
                        "(structured tool_use tampering, multi-turn "
                        "conditional injection, history tampering, "
                        "prompt-cache fidelity).")
    p.add_argument("--skip-billing", action="store_true",
                   help="Skip Step 15 billing / usage integrity "
                        "(output_tokens inflation, cache double-counting, "
                        "input under-report sanity).")
    p.add_argument("--skip-api-consistency", action="store_true",
                   help="Skip Step 16 API conformance / silent downgrade "
                        "(beta-feature honoring, tool-schema fidelity, "
                        "max_tokens/stop_reason, mid-stream injection).")
    p.add_argument("--skip-model-fingerprint", action="store_true",
                   help="Skip Step 17 model-substitution fingerprint "
                        "(capability probes, knowledge-cutoff, refusal "
                        "profile). YELLOW-grade, no official baseline.")
    p.add_argument("--skip-tls", action="store_true",
                   help="Skip Step 18 transport-layer security "
                        "(TLS version/cipher, cert chain, HTTP downgrade).")
    p.add_argument("--skip-probe-randomization", action="store_true",
                   help="Skip Step 19 audit-evasion countermeasures "
                        "(probe diversification, audit-detection "
                        "differential probe).")
    p.add_argument("--latency-probe-count", type=validate_probe_count,
                   default=10, metavar="N",
                   help=f"Number of identical probes fired in Step 12. "
                        f"Range: {LATENCY_PROBE_MIN}-{LATENCY_PROBE_MAX}. "
                        f"Minimum 4 to enable bimodality detection. "
                        f"Default: 10.")
    p.add_argument("--warmup", type=int, default=0, metavar="N",
                   help="Send N benign requests before the audit to mitigate "
                        "request-count-gated backdoors (AC-1.b). Default: 0")
    p.add_argument("--timeout", type=int, default=120, help="Request timeout in seconds")
    p.add_argument("--output", default=None, help="Report output path (markdown)")
    p.add_argument("--transparent-log", default=None, metavar="PATH",
                   help="Path to an append-only JSONL forensic log (arXiv §7.3). "
                        "Every API request is recorded with timestamp, URL, "
                        "SHA-256 of request/response, and status code.")
    return p.parse_args()


# ============================================================
# Main
# ============================================================


def emit_overall_rating(report, bindings, step_crashes):
    """算风险矩阵并经 report 输出总体评级（HIGH/MEDIUM/LOW + 理由）。

    CLI main() 与 stdin run_stdin() 共用。评级结论用 report.p 输出（不用 flag，
    避免污染 passed/warned/failed 计数）；标题用 p 而非 h2，避免触发额外
    step 事件（保持 totalSteps 与注册步骤数对齐）。
    """
    injection = bindings.get("injection")
    leaked = bindings.get("leaked", False)
    overridden = bindings.get("overridden")
    substitution_detected, substitution_inconclusive = bindings.get(
        "substitution_detected", False
    ), bindings.get("substitution_inconclusive", True)
    err_severity, err_inconclusive = bindings.get(
        "err_severity", "none"
    ), bindings.get("err_inconclusive", True)
    stream_verdict, stream_inconclusive = bindings.get(
        "stream_verdict", "clean"
    ), bindings.get("stream_inconclusive", True)

    # Steps 15-20 的 summary 由 step_registry.run_registered_steps() 统一调
    # 度并写入 bindings，键名见 step_registry._bind() 的 summary 分支。
    long_task_summary = bindings.get("long_task_summary")
    billing_summary = bindings.get("billing_summary")
    api_consistency_summary = bindings.get("api_consistency_summary")
    model_fingerprint_summary = bindings.get("model_fingerprint_summary")
    tls_summary = bindings.get("tls_summary")
    probe_randomization_summary = bindings.get("probe_randomization_summary")

    # 总体评级
    # 维度（v3，post-v1.7.5）：
    #   D1  = 隐藏的系统 prompt 注入 > 100 tokens        (Step 3)
    #   D1i = Step 3 崩溃 / inconclusive                  (Step 3)
    #   D2  = 用户指令被覆盖                             (Step 5)
    #   D2i = Step 5 崩溃 / inconclusive                  (Step 5)
    #   D3  = 检测到工具调用包替换                        (Step 8)
    #   D3i = Step 8 inconclusive（所有探针出错）         (Step 8)
    #   D4  = 错误响应泄露（critical 或 high）            (Step 9)
    #   D4m = 错误响应泄露（仅 medium）                   (Step 9)
    #   D4i = Step 9 inconclusive                         (Step 9)
    #   D5  = 检测到流完整性异常                          (Step 10)
    #   D5i = Step 10 inconclusive（非 Anthropic / 损坏） (Step 10)
    # 扩展维度（Step 14-20，伴生模块）：
    #   EXT1  = 结构化 tool_use 载荷篡改                  (Step 14a，AC-1.a 真实面)
    #   EXT2  = 多轮条件式注入                            (Step 14b，AC-1.b 深度)
    #   EXT3  = 历史 / tool_result 篡改                   (Step 14c)
    #   EXT4  = 流中途文本注入                            (Step 16d)
    #   EXT5  = tool-schema 被破坏                        (Step 16b)
    #   EXT6  = 弱 TLS / 证书异常                         (Step 18)
    #   EXT7  = 审计检测分歧（指纹）                      (Step 19b)
    #   EXTm* = YELLOW 级：beta 降级、output 膨胀、
    #           cache 重复计费、假模型嫌疑、cache
    #           未被遵守、max_tokens 被忽略（-> MEDIUM）
    # 规则（首个命中生效）：
    #   d3 or d4 or d5 or EXT1..EXT7                 -> HIGH
    #   d1 and d2                                          -> HIGH
    #   d1                                                 -> MEDIUM
    #   d2                                                 -> MEDIUM
    #   d1i or d2i or d3i or d4i or d4m or d5i or any_crashed or EXTm* -> MEDIUM
    #   else                                               -> LOW
    report.p("## 14. Overall Rating\n")
    any_step_crashed = bool(step_crashes)
    d1 = injection is not None and injection > 100
    d1i = injection is None
    d2 = overridden is not None and overridden
    d2i = overridden is None
    d3 = substitution_detected
    d3i = substitution_inconclusive
    d4 = err_severity in ("critical", "high")
    d4m = err_severity == "medium"
    d4i = err_inconclusive
    d5 = stream_verdict == "anomaly"
    d5i = stream_inconclusive

    # --- 扩展维度（Step 14-20）---
    # 安全访问器：每个步骤可能被跳过/崩溃（summary 为 None）。
    def _ext_get(summary, *path, default=None):
        cur = summary
        for k in path:
            if isinstance(cur, dict):
                cur = cur.get(k)
            else:
                return default
        return cur if cur is not None else default

    lt = long_task_summary or {}
    ext_tooluse = bool(_ext_get(lt, "tool_use", "detected", default=False))
    ext_tooluse_i = bool(_ext_get(lt, "tool_use", "inconclusive", default=True))
    ext_multiturn = bool(_ext_get(lt, "multiturn", "detected", default=False))
    ext_multiturn_i = bool(_ext_get(lt, "multiturn", "inconclusive", default=True))
    ext_history = bool(_ext_get(lt, "history", "detected", default=False))
    ext_history_i = bool(_ext_get(lt, "history", "inconclusive", default=True))
    _cache_cf = _ext_get(lt, "cache", default={}) or {}
    ext_cache_downgrade = (not _cache_cf.get("honoured", True)) and (not _cache_cf.get("inconclusive", True))

    bl = billing_summary or {}
    ext_output_inflate = bool(_ext_get(bl, "output_inflation", "detected", default=False))
    ext_double_bill = bool(_ext_get(bl, "cache_double_count", "detected", default=False))

    ac = api_consistency_summary or {}
    ext_beta_downgrade = bool(_ext_get(ac, "beta_thinking", "detected_downgrade", default=False))
    ext_toolschema = bool(_ext_get(ac, "tool_schema", "detected", default=False))
    _mt = _ext_get(ac, "max_tokens", default={}) or {}
    ext_maxtokens_ignored = (not _mt.get("honored", True)) and (not _mt.get("inconclusive", True))
    ext_midstream = bool(_ext_get(ac, "midstream", "detected", default=False))

    mf = model_fingerprint_summary or {}
    ext_fakemodel = (bool(_ext_get(mf, "capability", "detected", default=False))
                     or bool(_ext_get(mf, "cutoff", "detected", default=False))
                     or bool(_ext_get(mf, "refusal", "detected", default=False)))

    tls = tls_summary or {}
    _tls_cls = _ext_get(tls, "tls", default={}) or {}
    _tls_cert = _ext_get(tls, "cert", default={}) or {}
    ext_weak_tls = (_tls_cls.get("verdict") == "weak") or (_tls_cert.get("verdict") == "weak")

    pr = probe_randomization_summary or {}
    ext_audit_evasion = bool(_ext_get(pr, "audit_detection", "divergent", default=False))

    # 仅在伴生步骤实际跑过时才考虑 ext 的 inconclusive 标志。
    # step_registry 总是尝试调度 Step 14-19 步；只有当某个 summary 是非 None dict
    # 时才算"实际跑过"。_ext_ran = 至少一个 15-20 summary 存在。
    _ext_ran = bool(
        long_task_summary
        or billing_summary
        or api_consistency_summary
        or model_fingerprint_summary
        or tls_summary
        or probe_randomization_summary
    )
    ext_any_i = (_ext_ran and (ext_tooluse_i or ext_multiturn_i or ext_history_i))
    _ext_high = (ext_tooluse or ext_multiturn or ext_history
               or ext_midstream or ext_toolschema or ext_weak_tls
               or ext_audit_evasion)
    _ext_medium = (_ext_ran and (ext_beta_downgrade or ext_output_inflate
                    or ext_double_bill or ext_fakemodel or ext_cache_downgrade
                    or ext_maxtokens_ignored or ext_any_i))
    # HIGH 级理由表：(触发条件, 理由文本)。顺序即输出顺序；逐条 if 判断。
    # err_severity 的 critical/high 互斥，故两条都入表，最多触发一条。
    high_reasons_table = [
        (d3, "**Tool-call package substitution detected (AC-1.a).** "
             "A malicious middleware is rewriting package-install commands "
             "on the return path -- a code-execution-level finding."),
        (ext_tooluse, "**Structured tool_use payload tampering detected (Step 14a).** "
             "The relay rewrites the JSON arguments of a tool_use block on the "
             "return path -- the real AC-1.a surface that the Step 8 text-echo "
             "surrogate cannot see. This is a direct code-execution hazard for "
             "any agentic client."),
        (ext_multiturn, "**Multi-turn conditional injection detected (Step 14b, AC-1.b).** "
             "The relay injects only on/after a specific turn, evading single-"
             "request audits. Do not use for multi-turn agentic workflows."),
        (ext_history, "**History / tool_result tampering detected (Step 14c).** "
             "The relay rewrites a prior tool_result between turns, corrupting "
             "the conversation state the agent reasons over."),
        (ext_midstream, "**Mid-stream text injection detected (Step 16d).** "
             "The relay splices unrequested content into the streaming delta "
             "path (promotional / branding markers). The response itself is "
             "not faithful."),
        (ext_toolschema, "**Tool schema not faithfully passed through (Step 16b).** "
             "The relay mangles the tools definition, which breaks agentic "
             "tool-use loops silently."),
        (ext_weak_tls, "**Weak transport-layer security (Step 18).** "
             "The relay negotiates a weak TLS version/cipher or serves an "
             "invalid/expired/self-signed certificate. On-path tampering is "
             "feasible."),
        (ext_audit_evasion, "**Audit-detection divergence (Step 19b).** "
             "The relay responds differently to audit-shaped vs normal-shaped "
             "requests -- it is fingerprinting audit traffic, which is itself "
             "a strong indicator of a malicious intermediary."),
        (err_severity == "critical", "**Full API key echoed in error response (AC-2 direct leak).** "
             "The relay returns your credential verbatim when handed a broken "
             "request. Other parties almost certainly see it under other conditions."),
        (err_severity == "high", "**Partial credential / upstream URL / environment variable leaked "
             "in error response.** The relay is exposing internal plumbing that "
             "maps onto the attacker's credential-collection surface."),
        (d5, "**Stream integrity anomaly detected (AC-1 SSE-level).** "
             "The relay's streaming response fails one or more structural "
             "invariants: unknown SSE event types, non-monotonic usage fields, "
             "rewritten input_tokens, empty thinking signatures, or a "
             "non-Claude stream model name."),
    ]

    if d3 or d4 or d5 or _ext_high:
        report.p("### HIGH RISK\n")
        reasons = [text for flag, text in high_reasons_table if flag]
        report.p(" ".join(reasons) + " **Do not use.**")
        return "HIGH"
    elif d1 and d2:
        report.p("### HIGH RISK\n")
        report.p("Hidden injection detected AND user instructions overridden. "
                 "Not suitable for any use case requiring custom behavior.")
        return "HIGH"
    elif d1:
        report.p("### MEDIUM RISK\n")
        report.p("Hidden injection detected but instructions may partially work. "
                 "OK for simple Q&A, not recommended for complex applications.")
        return "MEDIUM"
    elif d2:
        report.p("### MEDIUM RISK\n")
        report.p("No significant injection but instruction override detected.")
        return "MEDIUM"
    elif d1i or d2i or d3i or d4i or d4m or d5i or any_step_crashed or _ext_medium:
        report.p("### MEDIUM RISK\n")
        # MEDIUM 级理由表：(触发条件, 理由文本)。顺序即输出顺序。
        medium_reasons_table = [
            (d1i, "Token injection test (Step 3) **crashed or was inconclusive**: "
             "the relay's injection behavior could not be verified."),
            (d2i, "Instruction override test (Step 5) **crashed or was inconclusive**: "
             "whether the relay respects user system prompts could not be verified."),
            (d3i, "Tool-call substitution test (Step 8) was **inconclusive**: "
             "every probe errored, so the relay's AC-1.a behavior could not "
             "be verified -- a relay that blocks plaintext echo is itself a red flag."),
            (d4m, "Error response leaks filesystem paths or stack traces. "
             "Information disclosure is present but not directly credential-exposing."),
            (d4i, "Error leakage test (Step 9) was **inconclusive**: every probe "
             "returned HTTP 200 or failed with a transport error, so no error "
             "surface could be inspected."),
            (d5i, "Stream integrity test (Step 10) was **inconclusive**: the relay "
             "did not speak Anthropic SSE cleanly, so the event-layer invariants "
             "could not be verified. A relay that cannot return a standard "
             "Anthropic stream is itself a suspicious signal."),
            (ext_beta_downgrade, "Extended thinking was NOT returned (Step 16a): the "
             "anthropic-beta header appears stripped -- a silent feature "
             "downgrade."),
            (ext_output_inflate, "output_tokens inflation detected (Step 15a): reported tokens "
             "far exceed the returned text length -- possible billing fraud."),
            (ext_double_bill, "Cached-input double billing suspected (Step 15b): cached content "
             "appears billed at full price alongside the cache-read discount."),
            (ext_fakemodel, "Model-substitution fingerprint deviation (Step 17): capability, "
             "knowledge-cutoff, or refusal profile is inconsistent with the "
             "advertised model. YELLOW-grade (no official baseline)."),
            (ext_cache_downgrade, "Prompt caching NOT honoured (Step 14d): cache_control appears "
             "stripped -- the caching feature is silently downgraded."),
            (ext_maxtokens_ignored, "max_tokens / stop_reason NOT honoured (Step 16c): the relay "
             "ignores the token limit -- a correctness and billing hazard."),
            (ext_any_i, "One or more long-task sub-checks (Step 14) were **inconclusive**: "
             "multi-request behavior could not be fully verified; re-run for a "
             "definitive verdict."),
        ]
        medium_reasons = []
        # crashed 那条含步骤名插值，单独处理（保持最先输出）。
        if any_step_crashed:
            crashed_names = ", ".join(step_crashes)
            medium_reasons.append(
                f"One or more audit steps **crashed** ({crashed_names}): "
                "the audit is incomplete and should be re-run to get "
                "a definitive verdict."
            )
        medium_reasons.extend(text for flag, text in medium_reasons_table if flag)
        report.p(" ".join(medium_reasons))
        return "MEDIUM"
    else:
        report.p("### LOW RISK\n")
        report.p("No significant injection, instruction override, tool-call "
                 "substitution, error response leakage, stream integrity "
                 "anomaly, long-task tampering, billing "
                 "inflation, API-conformance downgrade, model-substitution "
                 "deviation, transport-layer weakness, or audit-evasion "
                 "divergence detected.")
    return "LOW"


def main():
    args = parse_args()
    client = APIClient(args.url, args.key, args.model, timeout=args.timeout)

    # v1.7.7：透明取证日志（arXiv §7.3）
    _transparent_logger = None
    if args.transparent_log:
        _transparent_logger = TransparentLogger(args.transparent_log)
        client.set_transparent_logger(_transparent_logger)

    if args.connectivity:
        print(f"\n{'=' * 60}")
        print("  API Relay Connectivity Check")
        print(f"  Target: {client.base_url}")
        print(f"  Model:  {args.model}")
        print(f"{'=' * 60}\n")

        result = run_connectivity_check(client)
        md = result["markdown"]
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(md, encoding="utf-8")
            print(f"  Connectivity report saved: {args.output}")
        else:
            print(md)

        if _transparent_logger is not None:
            _transparent_logger.close()
            print(f"\n  Transparent log: {args.transparent_log}")
        return 0 if result["success"] else 1

    report = Reporter()

    print(f"\n{'=' * 60}")
    print(f"  API Relay Security Audit")
    print(f"  Target: {client.base_url}")
    print(f"  Model:  {args.model}")
    print(f"{'=' * 60}\n")

    report.p(f"**Target**: `{client.base_url}`")
    report.p(f"**Model**: `{args.model}`")
    report.p(
        "Threat model follows the AC-1 / AC-1.a / AC-1.b / AC-2 taxonomy from "
        "Liu et al., *Your Agent Is Mine: Measuring Malicious Intermediary "
        "Attacks on the LLM Supply Chain*, arXiv:2604.08407."
    )
    report.p("---")

    step_crashes = []  # 崩溃的步骤名（喂给 MEDIUM 兜底）

    # 预热（部分 AC-1.b 缓解）
    if args.warmup > 0:
        print(f"[warmup] Sending {args.warmup} benign requests...")
        run_warmup(client, args.warmup)
        report.flag(
            "green",
            f"Warm-up: {args.warmup} benign calls sent before audit "
            "(partial AC-1.b request-count-gate mitigation)",
        )

    # Steps 1-14 通过注册表调度（见 step_registry.py）。
    bindings = run_registered_steps(
        args=args, client=client, report=report, step_crashes=step_crashes,
    )
    rating = emit_overall_rating(report, bindings, step_crashes)

    # 输出
    md = report.render(target_url=client.base_url, model=args.model)

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(md, encoding="utf-8")
        print(f"\n  Report saved: {args.output}")
    else:
        print(f"\n{'=' * 60}")
        print(md)

    # 关闭透明日志
    if _transparent_logger is not None:
        _transparent_logger.close()
        print(f"\n  Transparent log: {args.transparent_log}")

    print(f"\n{'=' * 60}")
    print("  Audit complete")
    print(f"{'=' * 60}\n")
    return 0


class _StubArgs:
    """stdin 模式下替代 argparse args 的替身对象。

    test_error_leakage(client, args, report) 与若干 _run_step 调用会访问
    args 的属性（见 engine.py 顶部 grep 的全集）。stdin 模式不走 argparse，
    用本对象补齐所有属性默认值；skip 控制项从 stdin JSON 的 "skip" dict 读。
    漏补的属性会被 _run_step 的 fail-open 兜成 warn，不致命但丢项。
    """

    def __init__(self, base_url, api_key, model, skip=None,
                 fast_context=False, warmup=0, timeout=120,
                 latency_probe_count=12):
        self.url = base_url
        self.key = api_key
        self.model = model
        self.timeout = timeout
        self.fast_context = fast_context
        self.warmup = warmup
        self.latency_probe_count = latency_probe_count
        self.aggressive_error_probes = False
        # CLI-only 选项，stdin 模式不用：
        self.connectivity = False
        self.output = None
        self.transparent_log = None
        # skip 控制（默认全跑 = 全 False）：
        skip = skip or {}
        self.skip_infra = bool(skip.get("infra", False))
        self.skip_context = bool(skip.get("context", False))
        self.skip_tool_substitution = bool(skip.get("toolSubstitution", False))
        self.skip_error_leakage = bool(skip.get("errorLeakage", False))
        self.skip_stream_integrity = bool(skip.get("streamIntegrity", False))
        self.skip_infra_fingerprint = bool(skip.get("infraFingerprint", False))
        self.skip_latency_variance = bool(skip.get("latencyVariance", False))
        self.skip_channel_classifier = bool(skip.get("channelClassifier", False))
        self.skip_long_task = bool(skip.get("longTask", False))
        self.skip_billing = bool(skip.get("billing", False))
        self.skip_api_consistency = bool(skip.get("apiConsistency", False))
        self.skip_model_fingerprint = bool(skip.get("modelFingerprint", False))
        self.skip_tls = bool(skip.get("tls", False))
        self.skip_probe_randomization = bool(skip.get("probeRandomization", False))


def run_stdin():
    """stdin 模式入口：读 JSON 入参 → EventReporter → 跑 20 项 → 发 NDJSON。

    与 main() 的区别：
      - 入参从 stdin JSON 读，不走 argparse；
      - report 用 EventReporter（把 h2/h3/p/flag 映射成 AuditEvent）；
      - 不输出 print（避免污染 NDJSON stdout）；
      - 不跑风险矩阵 markdown 汇总（事件流的汇总靠 done 事件）；
      - 末尾 flush + 发 done 事件。

    返回退出码：0 正常；2 入参非法。
    """
    import time as _time

    # 把 emit 绑到真实 stdout（NDJSON 输出通道），再把 sys.stdout 重定向到 stderr —— 业务代码（test_* / APIClient）里的 print() 会进 stderr；
    # 被 TS runner.ts 收集到 stderrBuf 不转发前端，不污染 NDJSON 流。
    # sys.stdin 不受影响（只重定向了 stdout），仍从真实 stdin 读入参。
    protocol.bind_stdout(sys.stdout)
    sys.stdout = sys.stderr

    line = sys.stdin.readline()
    if not line or not line.strip():
        emit(build_error("stdin 输入为空"))
        return 2
    try:
        data = json.loads(line)
    except json.JSONDecodeError as e:
        emit(build_error(f"输入 JSON 解析失败：{e}"))
        return 2
    if not isinstance(data, dict):
        emit(build_error("stdin 输入不是 JSON 对象"))
        return 2

    base_url = data.get("baseUrl")
    api_key = data.get("apiKey")
    model = data.get("modelId")
    if not isinstance(base_url, str) or not base_url.strip():
        emit(build_error("baseUrl 不能为空")); return 2
    if not isinstance(api_key, str) or not api_key.strip():
        emit(build_error("apiKey 不能为空")); return 2
    if not isinstance(model, str) or not model.strip():
        emit(build_error("modelId 不能为空")); return 2
    base_url = base_url.strip()
    api_key = api_key.strip()
    model = model.strip()

    skip = data.get("skip") or {}
    fast_context = bool(data.get("fastContext", False))
    warmup = int(data.get("warmup", 0) or 0)
    timeout = int(data.get("timeout", 120) or 120)

    client = APIClient(base_url, api_key, model, timeout=timeout, verbose=False)
    report = EventReporter(total_steps=19)
    args = _StubArgs(base_url, api_key, model, skip=skip,
                     fast_context=fast_context, warmup=warmup, timeout=timeout)
    step_crashes = []

    emit(build_start(f"BaseURL： {base_url}", 19))
    started = _time.time()

    # Warm-up（可选，部分 AC-1.b 缓解）。
    if warmup > 0:
        try:
            run_warmup(client, warmup)
            report.flag("green", f"Warm-up: {warmup} benign calls sent before audit")
        except Exception:
            pass

    # Step 1-19（通过 step_registry.run_registered_steps() 统一调度）。
    bindings = run_registered_steps(
        args=args, client=client, report=report, step_crashes=step_crashes,
    )

    passed, warned, failed = report.flush()

    # 总体评级（HIGH/MEDIUM/LOW + 理由）：用 report.p 输出，累积进报告 Markdown
    # 的 _md_sections（不发新 step 事件、不污染计数）。在 render_markdown 前调用，
    # 使报告末尾含「## Overall Rating」节。
    emit_overall_rating(report, bindings, step_crashes)

    # 生成整体 Markdown 报告并落盘到 reports/，发 report 事件通知前端路径。
    # 报告生成失败不阻断 done（审计结果已流式送达，报告只是附属产物）。
    try:
        md = report.render_markdown(
            base_url, model, int((_time.time() - started) * 1000),
            passed, warned, failed,
        )
        host = urlparse(base_url).hostname or base_url
        parts = host.split(".")
        primary = parts[-2] if len(parts) >= 2 else host
        # 文件名安全化：非字母数字一律转下划线，避免 host 含特殊字符。
        primary = re.sub(r"[^A-Za-z0-9]+", "_", primary).strip("_") or "relay"
        stamp = _time.strftime("%Y%m%d%H%M")
        reports_dir = Path(__file__).resolve().parent.parent / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        out_path = reports_dir / f"report_{primary}_{stamp}.md"
        out_path.write_text(md, encoding="utf-8")
        emit(build_report(out_path.name))
    except Exception as e:
        protocol.log_stderr(f"报告生成失败: {e}")

    emit(build_done(passed, warned, failed, int((_time.time() - started) * 1000)))
    return 0


if __name__ == "__main__":
    try:
        code = run_stdin()
    except BrokenPipeError:
        # 消费端提前关闭 stdout（用户断连）：重定向到 DEVNULL 静默退出。
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        raise SystemExit(0)
    except BaseException as e:  # noqa: BLE001 —— 顶层兜底，确保发 error 事件
        emit(build_error(f"审计执行异常：{type(e).__name__}: {str(e)[:200]}"))
        import traceback
        protocol.log_stderr(traceback.format_exc())
        raise SystemExit(1)
    raise SystemExit(code)
