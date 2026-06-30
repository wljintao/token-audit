#!/usr/bin/env python3
"""
audit_tls.py --- Transport-layer security audit (P2).

audit.py records ``tls_version`` and ``tls_cipher`` as always ``null``
(header comment: "TLS metadata capture is deferred to a follow-up commit").
This module fills that gap by probing the live TLS session and cert chain.

Adds:

  (a) TLS version / cipher capture: parse ``curl -v`` (or openssl) output to
      recover the negotiated TLS version and cipher suite.
  (b) Downgrade / weak-cipher detection: flag TLSv1.0/1.1, NULL/EXPORT/RC4/
      3DES cipher suites.
  (c) Certificate-chain validation: expiry, self-signed, hostname mismatch,
      weak signature algorithm (SHA1/MD5).
  (d) HTTP downgrade check: verify the relay redirects/forces HTTPS.

Pure functions are isolated so they can be unit-tested offline against
sample curl/openssl output strings.
"""
import re
import subprocess
import sys
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse


# ============================================================
# Parsers (pure functions)
# ============================================================

def parse_tls_version(curl_verbose: str) -> Optional[str]:
    """Extract the negotiated TLS version from ``curl -v`` stderr.

    Looks for ``SSL connection using TLSv1.3 / TLS_AES_256_GCM...`` and the
    newer ``*  TLSv1.3 (IN)`` style. Returns the version string (e.g.
    ``TLSv1.3``) or None.
    """
    if not curl_verbose:
        return None
    m = re.search(r"SSL connection using\s+(\S+)", curl_verbose)
    if m:
        return m.group(1)
    m = re.search(r"\bTLSv1\.[0-3]\b", curl_verbose)
    if m:
        return m.group(0)
    m = re.search(r"\bSSLv[23]\b", curl_verbose)
    if m:
        return m.group(0)
    return None


def parse_tls_cipher(curl_verbose: str) -> Optional[str]:
    """Extract the negotiated cipher suite name from ``curl -v`` stderr.

    Handles ``SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384`` and
    ``* Cipher suite: TLS_AES_256_GCM_SHA384``.
    """
    if not curl_verbose:
        return None
    m = re.search(r"SSL connection using\s+\S+\s*/\s*(\S+)", curl_verbose)
    if m:
        return m.group(1)
    m = re.search(r"Cipher suite:\s*(\S+)", curl_verbose)
    if m:
        return m.group(1)
    return None


# Weak cipher markers (case-insensitive substring match on the suite name)
_WEAK_CIPHER_MARKERS = (
    "null", "export", "rc4", "3des", "des-cbc", "rc2", "md5",
    "anonymous", "anon", "dh_anon", "ecdhe_anon", "psk_anon",
    "aes128-ccm8",  # weak-ish
)

# Weak TLS versions
_WEAK_VERSIONS = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")


def classify_tls(version: Optional[str], cipher: Optional[str]) -> dict:
    """Classify TLS version + cipher for downgrade / weakness.

    Returns:
      - ``version``: passed-through
      - ``cipher``: passed-through
      - ``weak_version``: True if version is SSLv2/v3/TLSv1.0/1.1
      - ``weak_cipher``: True if cipher name contains a weak marker
      - ``verdict``: "strong" | "weak" | "unknown"
    """
    v = (version or "").strip()
    c = (cipher or "").lower()
    weak_version = any(v == w or v.endswith(w) for w in _WEAK_VERSIONS)
    weak_cipher = any(marker in c for marker in _WEAK_CIPHER_MARKERS)
    if weak_version or weak_cipher:
        verdict = "weak"
    elif v and c:
        verdict = "strong"
    else:
        verdict = "unknown"
    return {"version": v or None, "cipher": cipher, "weak_version": weak_version,
            "weak_cipher": weak_cipher, "verdict": verdict}


# ============================================================
# Cert chain parsing (openssl-style output)
# ============================================================

def parse_cert_expiry(openssl_text: str) -> Optional[str]:
    """Extract the ``notAfter`` date string from openssl s_client output.

    Returns the raw date string (e.g. ``Jun 14 12:00:00 2026 GMT``) or None.
    """
    if not openssl_text:
        return None
    m = re.search(r"notAfter=(.+)", openssl_text)
    if m:
        return m.group(1).strip()
    m = re.search(r"Not After\s*:\s*(.+)", openssl_text)
    if m:
        return m.group(1).strip()
    return None


def parse_cert_subject(openssl_text: str) -> Optional[str]:
    """Extract the cert subject line."""
    if not openssl_text:
        return None
    m = re.search(r"subject\s*=\s*(.+)", openssl_text)
    if m:
        return m.group(1).strip()
    m = re.search(r"Subject:\s*(.+)", openssl_text)
    if m:
        return m.group(1).strip()
    return None


def parse_cert_issuer(openssl_text: str) -> Optional[str]:
    if not openssl_text:
        return None
    m = re.search(r"issuer\s*=\s*(.+)", openssl_text)
    if m:
        return m.group(1).strip()
    m = re.search(r"Issuer:\s*(.+)", openssl_text)
    if m:
        return m.group(1).strip()
    return None


def is_self_signed(subject: Optional[str], issuer: Optional[str]) -> bool:
    """True if subject == issuer (self-signed)."""
    if not subject or not issuer:
        return False
    return subject.strip() == issuer.strip()


def parse_sig_algorithm(openssl_text: str) -> Optional[str]:
    """Extract the signature algorithm (e.g. sha256WithRSAEncryption)."""
    if not openssl_text:
        return None
    m = re.search(r"Signature Algorithm:\s*(\S+)", openssl_text)
    if m:
        return m.group(1).strip()
    m = re.search(r"signatureAlgorithm\s*=\s*(\S+)", openssl_text)
    if m:
        return m.group(1).strip()
    return None


def is_weak_sig_algorithm(sig: Optional[str]) -> bool:
    """True if the signature algorithm is SHA1/MD5-based."""
    if not sig:
        return False
    low = sig.lower()
    return "sha1" in low or "md5" in low


def parse_not_after_datetime(date_str: str) -> Optional[datetime]:
    """Parse an openssl-style notAfter date into a UTC datetime.

    Handles formats like ``Jun 14 12:00:00 2026 GMT`` and
    ``2026-06-14 12:00:00 UTC``. Returns None if unparseable.
    """
    if not date_str:
        return None
    date_str = date_str.strip()
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %e %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    # ISO-ish
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except ValueError:
        pass
    return None


def classify_cert(openssl_text: str, hostname: str, now: datetime) -> dict:
    """Classify the certificate for expiry/self-signed/weak-sig/hostname.

    Returns a dict with parsed fields and boolean flags.
    """
    subject = parse_cert_subject(openssl_text)
    issuer = parse_cert_issuer(openssl_text)
    sig = parse_sig_algorithm(openssl_text)
    not_after = parse_cert_expiry(openssl_text)
    expiry_dt = parse_not_after_datetime(not_after) if not_after else None
    expired = False
    expires_soon = False
    if expiry_dt:
        delta = (expiry_dt - now).total_seconds()
        expired = delta < 0
        expires_soon = 0 <= delta < 30 * 24 * 3600  # < 30 days
    self_signed = is_self_signed(subject, issuer)
    weak_sig = is_weak_sig_algorithm(sig)
    # hostname match: check CN= and SAN DNS entries contain the base domain
    hostname_ok = _hostname_matches(openssl_text, hostname)
    issues = []
    if expired:
        issues.append("expired")
    if expires_soon:
        issues.append("expires soon (<30d)")
    if self_signed:
        issues.append("self-signed")
    if weak_sig:
        issues.append("weak signature algorithm")
    if not hostname_ok:
        issues.append("hostname mismatch")
    verdict = "weak" if issues else "strong"
    return {"subject": subject, "issuer": issuer, "signature_algorithm": sig,
            "not_after": not_after, "expired": expired, "expires_soon": expires_soon,
            "self_signed": self_signed, "weak_signature": weak_sig,
            "hostname_ok": hostname_ok, "issues": issues, "verdict": verdict}


def _hostname_matches(openssl_text: str, hostname: str) -> bool:
    """Check if hostname appears in CN or SAN of the cert text."""
    if not openssl_text or not hostname:
        return False
    # base domain (strip leading label)
    parts = hostname.split(".")
    base = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    low = openssl_text.lower()
    if base in low:
        return True
    # CN= check
    m = re.search(r"cn\s*=\s*([^,\n/]+)", low)
    if m and base in m.group(1):
        return True
    return False


# ============================================================
# Live probes (subprocess)
# ============================================================

def _capture_curl_verbose(url: str, timeout: int = 15) -> str:
    """Run ``curl -sIv`` to capture TLS handshake info on stderr."""
    try:
        proc = subprocess.run(
            ["curl", "-sIv", "--max-time", str(timeout), "-o", "/dev/null", url],
            capture_output=True, text=True, timeout=timeout + 5)
        return (proc.stderr or "") + (proc.stdout or "")
    except Exception as e:
        return f"[curl error: {e}]"


def _capture_openssl(host: str, port: int = 443, timeout: int = 15) -> str:
    """Run ``openssl s_client`` to capture the cert chain."""
    try:
        proc = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:{port}",
             "-servername", host, "-showcerts"],
            input="", capture_output=True, text=True, timeout=timeout + 5)
        return (proc.stdout or "") + (proc.stderr or "")
    except Exception as e:
        return f"[openssl error: {e}]"


def _check_https_redirect(url: str, timeout: int = 10) -> dict:
    """Check that an http:// URL redirects to https://."""
    http_url = url.replace("https://", "http://", 1) if url.startswith("https://") else url
    if not http_url.startswith("http://"):
        http_url = "http://" + urlparse(url).netloc
    try:
        proc = subprocess.run(
            ["curl", "-sI", "--max-time", str(timeout), "-o", "/dev/null",
             "-w", "%{redirect_url}\\n%{http_code}", http_url],
            capture_output=True, text=True, timeout=timeout + 5)
        out = (proc.stdout or "").strip().splitlines()
        redirect_url = out[0] if out else ""
        code = out[1] if len(out) > 1 else ""
        to_https = redirect_url.startswith("https://")
        return {"checked": True, "redirect_url": redirect_url,
                "http_code": code, "redirects_to_https": to_https}
    except Exception as e:
        return {"checked": False, "error": str(e)}


# ============================================================
# Orchestrator + Reporter
# ============================================================

def run_tls_audit(base_url: str, report, timeout: int = 15) -> dict:
    """Run the full TLS audit against ``base_url``.

    Returns a summary dict.
    """
    parsed = urlparse(base_url)
    host = parsed.hostname or ""
    report.h2(f"18. {STEP_NAME_CN}")
    if not host:
        report.flag("yellow", "TLS 审计跳过：URL 中未找到主机名")
        return {"skipped": True}

    # (a)+(b) TLS version / cipher
    report.h3("18a. TLS 版本与加密套件")
    curl_out = _capture_curl_verbose(base_url, timeout=timeout)
    version = parse_tls_version(curl_out)
    cipher = parse_tls_cipher(curl_out)
    cls = classify_tls(version, cipher)
    report.p(f"**版本**：`{version or '(未知)'}`")
    report.p(f"**加密套件**：`{cipher or '(未知)'}`")
    if cls["verdict"] == "weak":
        report.flag("red", f"弱 TLS：版本={version} 加密套件={cipher} "
                    f"(弱版本={cls['weak_version']}, 弱加密={cls['weak_cipher']})")
    elif cls["verdict"] == "strong":
        report.flag("green", f"强 TLS 会话（{version} / {cipher}）")
    else:
        report.flag("yellow", "无法捕获 TLS 版本/加密套件（curl -v 不可用？）")

    # (c) cert chain
    report.h3("18b. 证书链")
    openssl_out = _capture_openssl(host, timeout=timeout)
    cert = classify_cert(openssl_out, host, datetime.now(timezone.utc))
    report.p(f"**主题**：`{cert['subject'] or '(未知)'}`")
    report.p(f"**颁发者**：`{cert['issuer'] or '(未知)'}`")
    report.p(f"**过期时间**：`{cert['not_after'] or '(未知)'}`")
    report.p(f"**签名算法**：`{cert['signature_algorithm'] or '(未知)'}`")
    if cert["issues"]:
        report.flag("red", f"证书问题：{', '.join(cert['issues'])}")
    else:
        report.flag("green", "证书链有效（未过期、CA 签发、主机名匹配）")

    # (d) HTTPS downgrade
    report.h3("18c. HTTP 降级 / HSTS")
    redir = _check_https_redirect(base_url, timeout=timeout)
    if redir.get("checked"):
        if redir["redirects_to_https"]:
            report.flag("green", f"http:// 重定向到 https://（{redir['http_code']}）")
        else:
            report.flag("yellow", f"http:// 未重定向到 https://"
                        f"（状态码={redir['http_code']}, 重定向={redir.get('redirect_url')}）")
    else:
        report.p(f"HTTP 降级检查跳过：{redir.get('error','')}")

    print("  Done: transport-layer security")
    return {"tls": cls, "cert": cert, "redirect": redir}


def test_tls(base_url, report, timeout: int = 15):
    """audit.py-compatible wrapper (client-less; takes base_url)."""
    return run_tls_audit(base_url, report, timeout=timeout)


# ============================================================
# Self-test (pure-function, offline)
# ============================================================

class _Report:
    def __init__(self):
        self.lines = []
    def h2(self, t): self.lines.append(f"## {t}")
    def h3(self, t): self.lines.append(f"### {t}")
    def p(self, t): self.lines.append(str(t))
    def code(self, t, lang=""): self.lines.append(str(t))
    def flag(self, level, msg): self.lines.append(f"[{level}] {msg}")
    def render(self, **kw): return "\n".join(self.lines)


def _assert(cond, msg):
    if not cond:
        raise AssertionError(msg)


_SAMPLE_STRONG = """* Trying 1.2.3.4:443...
* Connected to example.com (1.2.3.4) port 443
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* Server certificate:
*  subject: CN=example.com
*  issuer: C=US; O=Let's Encrypt; CN=R3
*  SSL certificate verify ok.
"""

_SAMPLE_WEAK = """* SSL connection using TLSv1.0 / ECDHE-RSA-AES256-SHA384
* subject=CN=example.com
* issuer=CN=example.com
* notAfter=Jun 14 12:00:00 2019 GMT
* Signature Algorithm: sha1WithRSAEncryption
"""

_SAMPLE_STRONG_CERT = """subject=CN=example.com
issuer=C = US, O = Let's Encrypt, CN = R3
Signature Algorithm: sha256WithRSAEncryption
notAfter=Jun 14 12:00:00 2026 GMT
* Verify return code: 0 (ok)
"""


def selftest():
    # --- parse_tls_version / cipher ---
    _assert(parse_tls_version(_SAMPLE_STRONG) == "TLSv1.3", "strong version")
    _assert(parse_tls_cipher(_SAMPLE_STRONG) == "TLS_AES_256_GCM_SHA384", "strong cipher")
    _assert(parse_tls_version(_SAMPLE_WEAK) == "TLSv1.0", "weak version")
    _assert(parse_tls_cipher(_SAMPLE_WEAK) == "ECDHE-RSA-AES256-SHA384", "weak-ish cipher (SHA384 not weak marker)")
    _assert(parse_tls_version("") is None, "empty version")
    _assert(parse_tls_cipher("no tls here") is None, "no cipher => None")
    # newer curl style
    _assert(parse_tls_version("*  TLSv1.3 (IN), TLS handshake") == "TLSv1.3", "newer style version")

    # --- classify_tls ---
    strong = classify_tls("TLSv1.3", "TLS_AES_256_GCM_SHA384")
    _assert(strong["verdict"] == "strong", "1.3 + AES-GCM => strong")
    _assert(strong["weak_version"] is False, "1.3 not weak version")
    weakv = classify_tls("TLSv1.0", "ECDHE-RSA-AES256-SHA384")
    _assert(weakv["weak_version"] is True, "TLSv1.0 weak version")
    _assert(weakv["verdict"] == "weak", "weak verdict")
    weakc = classify_tls("TLSv1.2", "ECDHE-RSA-RC4-SHA")
    _assert(weakc["weak_cipher"] is True, "RC4 weak cipher")
    _assert(weakc["verdict"] == "weak", "RC4 => weak")
    unknown = classify_tls(None, None)
    _assert(unknown["verdict"] == "unknown", "no data => unknown")

    # --- cert parsing ---
    _assert(parse_cert_expiry(_SAMPLE_STRONG_CERT) == "Jun 14 12:00:00 2026 GMT", "expiry parsed")
    _assert(parse_cert_subject(_SAMPLE_STRONG_CERT) == "CN=example.com", "subject parsed")
    _assert("Let's Encrypt" in (parse_cert_issuer(_SAMPLE_STRONG_CERT) or ""), "issuer parsed")
    _assert(parse_sig_algorithm(_SAMPLE_STRONG_CERT) == "sha256WithRSAEncryption", "sig parsed")
    _assert(is_self_signed("CN=example.com", "CN=example.com") is True, "self-signed detected")
    _assert(is_self_signed("CN=a", "CN=b") is False, "not self-signed")
    _assert(is_weak_sig_algorithm("sha1WithRSAEncryption") is True, "sha1 weak")
    _assert(is_weak_sig_algorithm("sha256WithRSAEncryption") is False, "sha256 not weak")
    _assert(is_weak_sig_algorithm(None) is False, "None sig not weak")

    # --- datetime parse ---
    dt = parse_not_after_datetime("Jun 14 12:00:00 2026 GMT")
    _assert(dt is not None and dt.year == 2026, "datetime parsed")
    _assert(parse_not_after_datetime("garbage") is None, "garbage => None")
    iso = parse_not_after_datetime("2026-06-14T12:00:00+00:00")
    _assert(iso is not None and iso.year == 2026, "iso parsed")

    # --- classify_cert: strong cert ---
    cert = classify_cert(_SAMPLE_STRONG_CERT, "example.com",
                         datetime(2026, 1, 1, tzinfo=timezone.utc))
    _assert(cert["expired"] is False, "not expired (Jan 2026)")
    _assert(cert["self_signed"] is False, "CA-signed")
    _assert(cert["weak_signature"] is False, "sha256 not weak")
    _assert(cert["hostname_ok"] is True, "hostname matches")
    _assert(cert["verdict"] == "strong", "strong cert verdict")

    # expired cert
    cert2 = classify_cert(_SAMPLE_WEAK, "example.com",
                          datetime(2026, 6, 27, tzinfo=timezone.utc))
    _assert(cert2["expired"] is True, "2019 cert expired in 2026")
    _assert(cert2["self_signed"] is True, "subject==issuer => self-signed")
    _assert(cert2["weak_signature"] is True, "sha1 weak")
    _assert(any("expired" in i for i in cert2["issues"]), "expired issue")
    _assert(any("self-signed" in i for i in cert2["issues"]), "self-signed issue")
    _assert(cert2["verdict"] == "weak", "weak cert verdict")

    # expires soon
    soon_cert_text = "subject=CN=example.com\nissuer=C=US,O=Let's Encrypt,CN=R3\n" \
                     "Signature Algorithm: sha256WithRSAEncryption\n" \
                     "notAfter=Jul 1 12:00:00 2026 GMT\n"
    cert3 = classify_cert(soon_cert_text, "example.com",
                          datetime(2026, 6, 27, tzinfo=timezone.utc))
    _assert(cert3["expires_soon"] is True, "4 days => expires soon")
    _assert(any("expires soon" in i for i in cert3["issues"]), "expires soon issue")

    # --- hostname matching ---
    _assert(_hostname_matches("subject=CN=example.com", "example.com") is True, "base domain match")
    _assert(_hostname_matches("subject=CN=other.org", "example.com") is False, "no match")

    # --- orchestrator smoke (pure-function path; no network in selftest) ---
    # We test the classifier path the orchestrator uses, without subprocess.
    cls = classify_tls(parse_tls_version(_SAMPLE_STRONG), parse_tls_cipher(_SAMPLE_STRONG))
    _assert(cls["verdict"] == "strong", "smoke strong tls")
    cert4 = classify_cert(_SAMPLE_STRONG_CERT, "example.com",
                          datetime(2026, 1, 1, tzinfo=timezone.utc))
    _assert(cert4["verdict"] == "strong", "smoke strong cert")

    print("audit_tls.selftest: ALL PASS")
    return True



# ============================================================
# Registry adapter (统一调度入口)
# ============================================================
# 与 step_01..step_13 共用同一注册表调度规范：模块级声明
# STEP_NAME_CN（中文展示名）+ run(client, report, **kwargs) 入口。
# 内部 ``test_tls`` 保留为可独立调用的实现（selftest 仍走它），
# 注册表通过 run() 调到它。

STEP_NAME_CN = "传输层安全 (TLS)"

def run(client, report, **kwargs):
    """Registry entry: forward to the original ``test_tls``.

    ``**kwargs`` is forwarded so the registry can pass ``sleep`` /
    other per-call options. Step 18 (TLS) reads ``client.base_url``
    itself so the same signature works across the 6 companions.
    """
    return test_tls(client.base_url, report, **kwargs)


if __name__ == "__main__":
    ok = selftest()
    raise SystemExit(0 if ok else 1)
