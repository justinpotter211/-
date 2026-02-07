from __future__ import annotations

import argparse
import dataclasses
import getpass
import hashlib
import json
import logging
import os
import re
import shutil
import socket
import base64
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

import ctypes
from ctypes import wintypes
import winreg


APP_NAME = "CSUAutoNet"
APP_VERSION = "0.0.2"
DEFAULT_SSID = "CSU-WIFI"
PORTAL_HOST = "portal.csu.edu.cn"


def _is_frozen() -> bool:
    """判断当前进程是否为打包后的可执行文件（PyInstaller 等）。"""

    return bool(getattr(sys, "frozen", False))


def _app_data_dir() -> Path:
    """返回当前用户的应用数据目录（Roaming），用于存放配置与凭据。"""

    base = os.environ.get("APPDATA")
    if not base:
        base = str(Path.home() / "AppData" / "Roaming")
    return Path(base) / APP_NAME


def _config_path() -> Path:
    """返回配置文件路径。"""

    return _app_data_dir() / "config.json"


def _cred_path() -> Path:
    """返回凭据文件路径（DPAPI 加密后的二进制）。"""

    return _app_data_dir() / "credentials.dat"


def _ensure_dirs() -> None:
    """确保应用数据目录存在。"""

    _app_data_dir().mkdir(parents=True, exist_ok=True)


def _default_log_path() -> Path:
    """返回默认日志文件路径。"""

    return _app_data_dir() / "csu_autonet.log"


def _setup_logging(log_path: Optional[Path], quiet: bool) -> None:
    """初始化日志系统，避免输出敏感信息。"""

    handlers: list[logging.Handler] = []
    if log_path is not None:
        _ensure_dirs()
        handlers.append(logging.FileHandler(str(log_path), encoding="utf-8"))
    if not quiet:
        handlers.append(logging.StreamHandler(sys.stdout))

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=handlers or [logging.NullHandler()],
    )


@dataclass(frozen=True)
class AppConfig:
    """运行配置。"""

    ssid: str = DEFAULT_SSID
    check_interval_seconds: int = 15
    login_interval_seconds: int = 10
    service_type_id: str = "1"
    edge_path: str = ""
    browser_headless: bool = True
    auto_open_portal_page: bool = False
    portal_host: str = PORTAL_HOST
    portal_login_port: int = 801
    portal_login_path: str = "/eportal/?c=ACSetting&a=Login"
    portal_probe_url: str = "https://portal.csu.edu.cn/"


def load_config() -> AppConfig:
    """从磁盘加载配置；不存在时返回默认配置。"""

    path = _config_path()
    if not path.exists():
        return AppConfig()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return AppConfig()

    def _get_str(key: str, default: str) -> str:
        val = raw.get(key, default)
        return val if isinstance(val, str) and val else default

    def _get_int(key: str, default: int) -> int:
        val = raw.get(key, default)
        if isinstance(val, int) and val > 0:
            return val
        if isinstance(val, str) and val.isdigit() and int(val) > 0:
            return int(val)
        return default

    def _get_bool(key: str, default: bool) -> bool:
        val = raw.get(key, default)
        if isinstance(val, bool):
            return val
        if isinstance(val, int):
            return bool(val)
        if isinstance(val, str):
            v = val.strip().lower()
            if v in {"1", "true", "yes", "y", "on"}:
                return True
            if v in {"0", "false", "no", "n", "off"}:
                return False
        return default

    return AppConfig(
        ssid=_get_str("ssid", DEFAULT_SSID),
        check_interval_seconds=_get_int("check_interval_seconds", 15),
        login_interval_seconds=_get_int("login_interval_seconds", 10),
        service_type_id=_get_str("service_type_id", "1"),
        edge_path=_get_str("edge_path", ""),
        browser_headless=_get_bool("browser_headless", True),
        auto_open_portal_page=_get_bool("auto_open_portal_page", False),
        portal_host=_get_str("portal_host", PORTAL_HOST),
        portal_login_port=_get_int("portal_login_port", 801),
        portal_login_path=_get_str("portal_login_path", "/eportal/?c=ACSetting&a=Login"),
        portal_probe_url=_get_str("portal_probe_url", "https://portal.csu.edu.cn/"),
    )


def save_config(config: AppConfig) -> None:
    """将配置写入磁盘。"""

    _ensure_dirs()
    data = dataclasses.asdict(config)
    _config_path().write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


_crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

_crypt32.CryptProtectData.argtypes = [
    ctypes.POINTER(_DATA_BLOB),
    wintypes.LPCWSTR,
    ctypes.POINTER(_DATA_BLOB),
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(_DATA_BLOB),
]
_crypt32.CryptProtectData.restype = wintypes.BOOL

_crypt32.CryptUnprotectData.argtypes = [
    ctypes.POINTER(_DATA_BLOB),
    ctypes.POINTER(wintypes.LPWSTR),
    ctypes.POINTER(_DATA_BLOB),
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(_DATA_BLOB),
]
_crypt32.CryptUnprotectData.restype = wintypes.BOOL

_kernel32.LocalFree.argtypes = [ctypes.c_void_p]
_kernel32.LocalFree.restype = ctypes.c_void_p


def _dpapi_encrypt(plaintext: bytes) -> bytes:
    """使用 Windows DPAPI（当前用户作用域）加密明文。"""

    if not plaintext:
        raise ValueError("plaintext is empty")

    in_blob = _DATA_BLOB(cbData=len(plaintext), pbData=(ctypes.c_byte * len(plaintext)).from_buffer_copy(plaintext))
    out_blob = _DATA_BLOB()

    if not _crypt32.CryptProtectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        _kernel32.LocalFree(out_blob.pbData)


def _dpapi_decrypt(ciphertext: bytes) -> bytes:
    """使用 Windows DPAPI（当前用户作用域）解密密文。"""

    if not ciphertext:
        raise ValueError("ciphertext is empty")

    in_blob = _DATA_BLOB(cbData=len(ciphertext), pbData=(ctypes.c_byte * len(ciphertext)).from_buffer_copy(ciphertext))
    out_blob = _DATA_BLOB()
    desc = wintypes.LPWSTR()

    if not _crypt32.CryptUnprotectData(ctypes.byref(in_blob), ctypes.byref(desc), None, None, None, 0, ctypes.byref(out_blob)):
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        if desc:
            _kernel32.LocalFree(desc)
        _kernel32.LocalFree(out_blob.pbData)


@dataclass(frozen=True)
class Credentials:
    """登录所需的账号与密码。"""

    username: str
    password: str


def save_credentials(creds: Credentials) -> None:
    """安全保存凭据（DPAPI 加密），避免明文落盘。"""

    _ensure_dirs()
    payload = json.dumps({"username": creds.username, "password": creds.password}, ensure_ascii=False).encode("utf-8")
    encrypted = _dpapi_encrypt(payload)
    _cred_path().write_bytes(encrypted)


def load_credentials() -> Optional[Credentials]:
    """读取并解密凭据；若不存在或失败则返回 None。"""

    path = _cred_path()
    if not path.exists():
        return None
    try:
        decrypted = _dpapi_decrypt(path.read_bytes())
        obj = json.loads(decrypted.decode("utf-8"))
        username = obj.get("username")
        password = obj.get("password")
        if isinstance(username, str) and isinstance(password, str) and username and password:
            return Credentials(username=username, password=password)
        return None
    except Exception:
        return None


def _run_netsh(args: list[str]) -> str:
    """调用 netsh 并返回输出文本。"""

    creationflags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
    completed = subprocess.run(
        ["netsh", *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=creationflags,
    )
    return completed.stdout


def get_current_ssid() -> Optional[str]:
    """获取当前连接的 Wi-Fi SSID；未连接时返回 None。"""

    out = _run_netsh(["wlan", "show", "interfaces"])
    for line in out.splitlines():
        m = re.match(r"^\s*SSID\s*:\s*(.+?)\s*$", line)
        if m:
            ssid = m.group(1).strip()
            if ssid and ssid.lower() != "":  # 兼容部分本地化输出
                return ssid
    return None


def connect_wifi(ssid: str) -> bool:
    """尝试连接指定 SSID（需要系统已保存该网络配置）。"""

    current = get_current_ssid()
    if current == ssid:
        return True
    out = _run_netsh(["wlan", "connect", f"name={ssid}"])
    if "已成功完成" in out or "successfully completed" in out.lower():
        return True
    time.sleep(2)
    return get_current_ssid() == ssid


def _tcp_connect(host: str, port: int, timeout_seconds: float) -> bool:
    """通过 TCP 连接测试网络可达性。"""

    try:
        with socket.create_connection((host, port), timeout=timeout_seconds):
            return True
    except OSError:
        return False


def _http_get(url: str, timeout_seconds: float) -> tuple[bool, Optional[int], str]:
    """发起 HTTP GET 请求并返回（成功、状态码、响应前 4KB 文本）。"""

    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "User-Agent": f"{APP_NAME}/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            status = getattr(resp, "status", None)
            data = resp.read(4096)
            text = data.decode("utf-8", errors="ignore")
            return True, status, text
    except urllib.error.HTTPError as e:
        try:
            data = e.read(4096)
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            text = ""
        return False, int(getattr(e, "code", 0) or 0), text
    except Exception:
        return False, None, ""


def _http_get_full(url: str, timeout_seconds: float) -> tuple[bool, Optional[int], str, str]:
    """发起 HTTP GET 请求并返回（成功、状态码、响应前 64KB 文本、最终 URL）。"""

    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "User-Agent": f"{APP_NAME}/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            status = getattr(resp, "status", None)
            final_url = str(getattr(resp, "geturl", lambda: url)() or url)
            data = resp.read(65536)
            text = data.decode("utf-8", errors="ignore")
            return True, status, text, final_url
    except urllib.error.HTTPError as e:
        try:
            final_url = str(getattr(e, "geturl", lambda: url)() or url)
        except Exception:
            final_url = url
        try:
            data = e.read(65536)
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            text = ""
        return False, int(getattr(e, "code", 0) or 0), text, final_url
    except Exception:
        return False, None, "", url


def is_internet_available() -> bool:
    """检测是否可以访问互联网（多策略，任一成功则认为可用）。"""

    if _tcp_connect("114.114.114.114", 53, timeout_seconds=2.0):
        return True

    ok, status, _ = _http_get("http://connectivitycheck.gstatic.com/generate_204", timeout_seconds=4.0)
    if ok and status == 204:
        return True

    ok, _, text = _http_get("http://www.msftconnecttest.com/connecttest.txt", timeout_seconds=4.0)
    if ok and "Microsoft Connect Test" in text:
        return True

    return False


def _extract_portal_login_params(html: str) -> tuple[Optional[int], Optional[str]]:
    """从门户页面脚本变量中提取登录端口与路径（提取失败返回 None）。"""

    port: Optional[int] = None
    path: Optional[str] = None

    m_port = re.search(r"\bauthloginport\s*=\s*(\d+)\s*;", html)
    if m_port:
        try:
            port = int(m_port.group(1))
        except ValueError:
            port = None

    m_path = re.search(r"\bauthloginpath\s*=\s*'([^']+)'\s*;", html)
    if m_path:
        path = m_path.group(1)

    return port, path


def _extract_portal_login_param_kv(html: str) -> dict[str, str]:
    """从门户页面脚本变量中提取 authloginparam（形如 url=drappall），返回键值对。"""

    if not html:
        return {}
    m = re.search(r"\bauthloginparam\s*=\s*'([^']*)'\s*;", html)
    raw = (m.group(1) if m else "").strip()
    if not raw:
        return {}
    try:
        qs = urllib.parse.parse_qs(raw, keep_blank_values=True, strict_parsing=False)
        out: dict[str, str] = {}
        for k, v in qs.items():
            if not k:
                continue
            if not v:
                out[k] = ""
            else:
                out[k] = str(v[-1])
        return out
    except Exception:
        return {}


def _drcom_account_suffix(service_type_id: str) -> str:
    """将服务类型ID映射为 Dr.COM 账号后缀（无后缀返回空字符串）。"""

    sid = (service_type_id or "").strip()
    if sid == "2":
        return "@dx"
    if sid == "3":
        return "@lt"
    return ""


def _extract_pid_calg(text: str) -> tuple[Optional[str], Optional[str]]:
    """从页面文本中提取 PID/CALG（用于 MD5 认证），提取失败返回 (None, None)。"""

    if not text:
        return None, None

    pid: Optional[str] = None
    calg: Optional[str] = None

    for pat in [
        r"\bPID\s*=\s*'([^']+)'",
        r'\bPID\s*=\s*"([^"]+)"',
        r"\bPID\s*=\s*([0-9A-Za-z]+)\b",
    ]:
        m = re.search(pat, text)
        if m:
            pid = m.group(1).strip()
            break

    for pat in [
        r"\bCALG\s*=\s*'([^']+)'",
        r'\bCALG\s*=\s*"([^"]+)"',
        r"\bCALG\s*=\s*([0-9A-Za-z]+)\b",
    ]:
        m = re.search(pat, text)
        if m:
            calg = m.group(1).strip()
            break

    if pid and calg:
        return pid, calg
    return None, None


def _js_calc_md5_ascii(text: str) -> str:
    """按 Dr.COM 前端常用逻辑计算 MD5（按 8-bit 字符序列）。"""

    if any(ord(ch) > 255 for ch in text):
        raise ValueError("MD5 输入包含非 8-bit 字符")
    b = text.encode("latin-1", errors="strict")
    return hashlib.md5(b).hexdigest()


def _drcom_md5_password(password: str, pid: str, calg: str) -> str:
    """按 Dr.COM 前端逻辑构造 MD5 认证口令：md5(PID+pwd+CALG)+CALG+PID。"""

    s = f"{pid}{password}{calg}"
    return f"{_js_calc_md5_ascii(s)}{calg}{pid}"


def _decode_portal_bytes(data: bytes) -> str:
    """将门户返回字节串解码为字符串（优先 UTF-8，其次 GBK）。"""

    if not data:
        return ""
    try:
        return data.decode("utf-8")
    except Exception:
        try:
            return data.decode("gbk", errors="replace")
        except Exception:
            return data.decode("latin-1", errors="replace")


def _redact_sensitive_text(text: str) -> str:
    """脱敏可能包含密码的文本，避免日志中出现明文或可复原口令。"""

    if not text:
        return ""
    t = text
    t = re.sub(r'(?i)\b(upass|user_password|password)\b\s*=\s*([^&\s]+)', r"\1=***", t)
    t = re.sub(r'(?i)"(upass|user_password|password)"\s*:\s*"[^"]*"', r'"\1":"***"', t)
    t = re.sub(r"(?i)'(upass|user_password|password)'\s*:\s*'[^']*'", r"'\1':'***'", t)
    return t


def _parse_json_or_jsonp(text: str) -> Optional[dict]:
    """解析 JSON 或 JSONP 文本，成功返回 dict，否则返回 None。"""

    if not text:
        return None
    t = text.strip().lstrip("\ufeff")
    try:
        obj = json.loads(t)
        return obj if isinstance(obj, dict) else None
    except Exception:
        pass

    l = t.find("(")
    r = t.rfind(")")
    if l != -1 and r != -1 and r > l:
        inner = t[l + 1 : r].strip()
        try:
            obj = json.loads(inner)
            return obj if isinstance(obj, dict) else None
        except Exception:
            return None
    return None


def _portal_url_base(config: AppConfig) -> str:
    """从配置的门户探测 URL 推导基础域名（用于拼接 drcom 接口）。"""

    raw = (config.portal_probe_url or "https://portal.csu.edu.cn/").strip() or "https://portal.csu.edu.cn/"
    try:
        u = urllib.parse.urlsplit(raw)
        scheme = u.scheme or "https"
        host = u.hostname or PORTAL_HOST
        return f"{scheme}://{host}"
    except Exception:
        return f"https://{PORTAL_HOST}"


def _eportal_port_for_scheme(scheme: str) -> int:
    """根据协议选择 eportal 端口（与门户前端一致）。"""

    s = (scheme or "").lower()
    return 801 if s == "http" else 802


def _portal_api_base(config: AppConfig, base: str) -> str:
    """构造 /eportal/portal/ 接口基础地址。"""

    raw = (config.portal_probe_url or "https://portal.csu.edu.cn/").strip() or "https://portal.csu.edu.cn/"
    try:
        u = urllib.parse.urlsplit(raw)
        scheme = u.scheme or "https"
        host = u.hostname or PORTAL_HOST
    except Exception:
        scheme = "https"
        host = PORTAL_HOST

    port = _eportal_port_for_scheme(scheme)
    return f"{scheme}://{host}:{port}/eportal/portal/"


def _b64encode_ascii(text: str) -> str:
    """按门户前端 base64encode 语义对字符串编码（UTF-8 字节序列）。"""

    s = text if text is not None else ""
    return base64.b64encode(s.encode("utf-8", errors="ignore")).decode("ascii", errors="ignore")


def _portal_load_config(config: AppConfig, terminal: dict[str, str]) -> dict[str, str]:
    """调用 page/loadConfig 获取登录相关策略参数（失败返回空 dict）。"""

    api = _portal_api_base(config, _portal_url_base(config))
    url = api + "page/loadConfig"

    data = {
        "program_index": "",
        "wlan_vlan_id": terminal.get("wlan_vlan_id", ""),
        "wlan_user_ip": _b64encode_ascii(terminal.get("wlan_user_ip", "")),
        "wlan_user_ipv6": _b64encode_ascii(terminal.get("wlan_user_ipv6", "")),
        "wlan_user_ssid": terminal.get("wlan_user_ssid", ""),
        "wlan_user_areaid": terminal.get("wlan_user_areaid", ""),
        "wlan_ac_ip": _b64encode_ascii(terminal.get("wlan_ac_ip", "")),
        "wlan_ap_mac": terminal.get("wlan_ap_mac", ""),
        "gw_id": terminal.get("gw_id", ""),
        "jsVersion": terminal.get("jsVersion", "4.1.3"),
        "callback": "dr1000",
        "_": str(int(time.time() * 1000)),
    }

    qs = urllib.parse.urlencode(data, doseq=False)
    req = urllib.request.Request(
        f"{url}?{qs}",
        method="GET",
        headers={
            "User-Agent": f"{APP_NAME}/1.0",
            "Accept": "*/*",
            "Referer": config.portal_probe_url,
            "Connection": "close",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=8.0) as resp:
            body = _decode_portal_bytes(resp.read(32768))
    except Exception:
        return {}

    obj = _parse_json_or_jsonp(body)
    if not isinstance(obj, dict):
        return {}

    data_obj = obj.get("data")
    if not isinstance(data_obj, dict):
        return {}

    def _get_int_str(key: str) -> str:
        v = data_obj.get(key)
        if isinstance(v, int):
            return str(v)
        if isinstance(v, str) and v.strip():
            return v.strip()
        return ""

    def _get_str(key: str) -> str:
        v = data_obj.get(key)
        return v.strip() if isinstance(v, str) and v.strip() else ""

    out: dict[str, str] = {}
    out["login_method"] = _get_int_str("login_method")
    out["en_md5"] = _get_int_str("en_md5")
    out["account_suffix"] = _get_str("account_suffix")
    out["custom_perceive"] = _get_int_str("custom_perceive")
    out["account_prefix"] = _get_int_str("account_prefix")
    out["io_mode"] = _get_int_str("io_mode")
    return out


def _compute_account_prefix(account_prefix_enabled: str, custom_perceive: str) -> str:
    """按门户前端逻辑计算账号前缀（Windows 端默认按 PC 类型）。"""

    if str(account_prefix_enabled).strip() not in {"1", "true", "True"}:
        return ""
    if str(custom_perceive).strip() in {"1", "true", "True"}:
        return ",b,"
    return ",0,"


def _normalize_mac(mac: str) -> str:
    """规范化 MAC：提取十六进制字符并转为 12 位大写（无法规范化则返回空串）。"""

    if not mac:
        return ""
    s = re.sub(r"[^0-9A-Fa-f]", "", mac)
    s = s.upper()
    if len(s) != 12:
        return ""
    return s


def _get_wifi_mac_from_netsh() -> str:
    """从 netsh wlan show interfaces 输出中提取当前 Wi-Fi 物理地址（失败返回空串）。"""

    out = _run_netsh(["wlan", "show", "interfaces"])
    for line in out.splitlines():
        m = re.match(r"^\s*(Physical address|物理地址)\s*:\s*(.+?)\s*$", line, flags=re.IGNORECASE)
        if m:
            return _normalize_mac(m.group(2).strip())
    return ""


def _drcom_chkstatus(base: str) -> Optional[dict]:
    """调用 /drcom/chkstatus 获取在线状态与部分终端信息（返回 dict 或 None）。"""

    url = f"{base}/drcom/chkstatus"
    qs = urllib.parse.urlencode({"callback": "dr1000", "_": str(int(time.time() * 1000))})
    req = urllib.request.Request(
        f"{url}?{qs}",
        method="GET",
        headers={
            "User-Agent": f"{APP_NAME}/1.0",
            "Accept": "*/*",
            "Referer": base + "/",
            "Connection": "close",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=6.0) as resp:
            body = _decode_portal_bytes(resp.read(16384))
    except Exception:
        return None
    return _parse_json_or_jsonp(body)


def _extract_isp_suffix_map(html: str) -> dict[str, str]:
    """从门户登录页 HTML 解析运营商后缀选项，返回 service_type_id -> suffix 的映射。"""

    out: dict[str, str] = {}
    if not html:
        return out

    try:
        options = re.findall(
            r"<option\b[^>]*\bvalue\s*=\s*['\"]([^'\"]*)['\"][^>]*>(.*?)</option>",
            html,
            flags=re.IGNORECASE | re.DOTALL,
        )
        for value, raw_text in options:
            v = (value or "").strip()
            if not v or v == "-1":
                continue
            t = re.sub(r"<[^>]+>", "", raw_text or "")
            t = re.sub(r"\s+", " ", t).strip()
            if not t:
                continue
            if "移动" in t and "1" not in out:
                out["1"] = v
            elif "电信" in t and "2" not in out:
                out["2"] = v
            elif "联通" in t and "3" not in out:
                out["3"] = v
    except Exception:
        pass

    return out


def _get_terminal_info(config: AppConfig, base: str) -> dict[str, str]:
    """从门户页面、跳转 URL 与 chkstatus 提取终端关键字段（缺失则为空）。"""

    info: dict[str, str] = {}

    ok, _, html, final_url = _http_get_full(config.portal_probe_url, timeout_seconds=6.0)
    if ok and html:
        isp_map = _extract_isp_suffix_map(html)
        for sid, suf in isp_map.items():
            if sid and suf:
                info[f"isp_suffix_{sid}"] = suf

        m = re.search(r"\bv4ip\s*=\s*'([\d.]+)'\s*;", html)
        if m:
            info["wlan_user_ip"] = m.group(1).strip()

        m6 = re.search(r"\bv6ip\s*=\s*'([^']*)'\s*;", html)
        if m6:
            v6 = (m6.group(1) or "").strip()
            if v6 and v6 != "0000:0000:0000:0000:0000:0000:0000:0000":
                info["wlan_user_ipv6"] = v6

        m_mac = re.search(r"\bwlan_user_mac\s*=\s*'([0-9A-Fa-f:-]+)'\s*;", html)
        if m_mac:
            n = _normalize_mac(m_mac.group(1))
            if n:
                info["wlan_user_mac"] = n

        m_acip = re.search(r"\bwlan_ac_ip\s*=\s*'([\d.]+)'\s*;", html)
        if m_acip:
            info["wlan_ac_ip"] = m_acip.group(1).strip()

        m_acname = re.search(r"\bwlan_ac_name\s*=\s*'([^']*)'\s*;", html)
        if m_acname:
            val = (m_acname.group(1) or "").strip()
            if val:
                info["wlan_ac_name"] = val

        m_gw_id = re.search(r"\bgw_id\s*=\s*'([^']*)'\s*;", html)
        if m_gw_id:
            val = (m_gw_id.group(1) or "").strip()
            if val:
                info["gw_id"] = val

        m_gw_addr = re.search(r"\bgw_address\s*=\s*'([^']*)'\s*;", html)
        if m_gw_addr:
            val = (m_gw_addr.group(1) or "").strip()
            if val:
                info["gw_address"] = val

        m_gw_port = re.search(r"\bgw_port\s*=\s*'([^']*)'\s*;", html)
        if m_gw_port:
            val = (m_gw_port.group(1) or "").strip()
            if val:
                info["gw_port"] = val

    try:
        u = urllib.parse.urlsplit(final_url or config.portal_probe_url)
        if u.scheme and u.netloc:
            info["portal_base"] = f"{u.scheme}://{u.netloc}"
        q = urllib.parse.parse_qs(u.query or "", keep_blank_values=True)
        def _q1(key: str) -> str:
            v = q.get(key)
            if not v:
                return ""
            return str(v[-1] or "").strip()

        acip = _q1("wlanacip") or _q1("wlan_ac_ip")
        if acip and "wlan_ac_ip" not in info:
            info["wlan_ac_ip"] = acip

        acname = _q1("wlanacname") or _q1("wlan_ac_name")
        if acname and "wlan_ac_name" not in info:
            info["wlan_ac_name"] = acname

        gw_id = _q1("gw_id")
        if gw_id and "gw_id" not in info:
            info["gw_id"] = gw_id

        gw_address = _q1("gw_address")
        if gw_address and "gw_address" not in info:
            info["gw_address"] = gw_address

        gw_port = _q1("gw_port")
        if gw_port and "gw_port" not in info:
            info["gw_port"] = gw_port

        ip = _q1("wlan_user_ip") or _q1("ip")
        if ip and "wlan_user_ip" not in info:
            info["wlan_user_ip"] = ip

        mac = _q1("wlan_user_mac") or _q1("mac") or _q1("client_mac")
        if mac and "wlan_user_mac" not in info:
            n = _normalize_mac(mac)
            if n:
                info["wlan_user_mac"] = n
    except Exception:
        pass

    st = _drcom_chkstatus(base)
    if isinstance(st, dict):
        mac = st.get("ss4")
        if isinstance(mac, str) and "wlan_user_mac" not in info:
            n = _normalize_mac(mac)
            if n:
                info["wlan_user_mac"] = n

        ip = st.get("v4ip") or st.get("uip")
        if isinstance(ip, str) and "wlan_user_ip" not in info:
            ip = ip.strip()
            if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip or ""):
                info["wlan_user_ip"] = ip

    if "wlan_user_mac" not in info:
        mac2 = _get_wifi_mac_from_netsh()
        if mac2:
            info["wlan_user_mac"] = mac2

    info.setdefault("wlan_user_ip", "")
    info.setdefault("wlan_user_ipv6", "")
    info.setdefault("wlan_user_mac", "")
    info.setdefault("wlan_ac_ip", "")
    info.setdefault("wlan_ac_name", "")
    info.setdefault("gw_port", "")
    info.setdefault("gw_address", "")
    info.setdefault("gw_id", "")
    info.setdefault("jsVersion", "4.1.3")
    info.setdefault("portal_base", base)
    return info


def _portal_login_drcom(config: AppConfig, creds: Credentials) -> bool:
    """通过 /drcom/login 接口执行一次登录（含必要时的 MD5 变体）。"""

    base = _portal_url_base(config)
    terminal = _get_terminal_info(config, base)
    base = (terminal.get("portal_base") or base).strip() or base

    pid: Optional[str] = None
    calg: Optional[str] = None
    for probe in [f"{base}/drcom/", f"{base}/", config.portal_probe_url]:
        try:
            req = urllib.request.Request(str(probe), method="GET", headers={"User-Agent": f"{APP_NAME}/1.0"})
            with urllib.request.urlopen(req, timeout=6.0) as resp:
                html = _decode_portal_bytes(resp.read(65536))
            pid, calg = _extract_pid_calg(html)
            if pid and calg:
                break
        except Exception:
            continue

    sid = (config.service_type_id or "1").strip() or "1"
    cfg = _portal_load_config(config, terminal)
    login_method = (cfg.get("login_method") or "0").strip() or "0"
    en_md5 = (cfg.get("en_md5") or "0").strip() or "0"
    prefix = _compute_account_prefix(cfg.get("account_prefix", ""), cfg.get("custom_perceive", ""))

    username = (creds.username or "").strip()
    suffix_source = "none"
    if "@" in username:
        account = username
        prefix_account = f"{prefix}{username}"
        suffix = ""
        suffix_source = "username"
    else:
        suffix = (terminal.get(f"isp_suffix_{sid}") or "").strip()
        if suffix:
            suffix_source = "portal_html"
        else:
            suffix = (cfg.get("account_suffix") or "").strip()
            if suffix:
                suffix_source = "load_config"
            else:
                suffix = _drcom_account_suffix(sid)
                if suffix:
                    suffix_source = "legacy"
        account = f"{username}{suffix}"
        prefix_account = f"{prefix}{username}{suffix}"

    logging.info(
        "快速登录参数：login_method=%s service_type_id=%s suffix=%s source=%s",
        login_method,
        sid,
        suffix or "(none)",
        suffix_source,
    )

    if login_method == "0":
        login_url = f"{base}/drcom/login"
    else:
        login_url = _portal_api_base(config, base) + "login"

    base_payload: dict[str, str] = {
        "0MKKey": "123456",
        "R1": sid,
        "R2": "",
        "R3": "",
        "R6": "0",
        "para": "00",
        "v6ip": terminal.get("wlan_user_ipv6", ""),
        "login_method": login_method,
        "DDDDD": account,
        "user_account": prefix_account,
        "wlan_user_ip": terminal.get("wlan_user_ip", ""),
        "wlan_user_ipv6": terminal.get("wlan_user_ipv6", ""),
        "wlan_user_mac": terminal.get("wlan_user_mac", ""),
        "wlan_ac_ip": terminal.get("wlan_ac_ip", ""),
        "wlan_ac_name": terminal.get("wlan_ac_name", ""),
        "gw_port": terminal.get("gw_port", ""),
        "gw_address": terminal.get("gw_address", ""),
        "gw_id": terminal.get("gw_id", ""),
        "jsVersion": terminal.get("jsVersion", "4.1.3"),
    }

    variants: list[tuple[str, dict[str, str]]] = []
    p_plain = dict(base_payload)
    p_plain.update({"upass": creds.password, "user_password": creds.password})
    variants.append(("plain", p_plain))

    if str(en_md5).strip() in {"1", "true", "True"} and pid and calg:
        try:
            md5_pass = _drcom_md5_password(creds.password, pid, calg)
            p_md5 = dict(base_payload)
            p_md5.update({"R2": "1", "upass": md5_pass, "user_password": md5_pass})
            variants.append(("md5", p_md5))
        except Exception:
            pass

    for idx, (variant_name, payload) in enumerate(variants, start=1):
        for callback in ["", "dr1000"]:
            q = dict(payload)
            if callback:
                q["callback"] = callback
            qs = urllib.parse.urlencode(q, doseq=False)
            url = f"{login_url}?{qs}"
            try:
                req = urllib.request.Request(
                    url,
                    method="GET",
                    headers={
                        "User-Agent": f"{APP_NAME}/1.0",
                        "Accept": "*/*",
                        "Referer": base + "/",
                        "Connection": "close",
                    },
                )
                with urllib.request.urlopen(req, timeout=8.0) as resp:
                    body = _decode_portal_bytes(resp.read(16384))
            except Exception as e:
                if isinstance(e, urllib.error.HTTPError):
                    try:
                        err_body = _decode_portal_bytes(e.read(2048))
                    except Exception:
                        err_body = ""
                    logging.info(
                        "快速登录请求失败（drcom，%s，第 %d 轮）：HTTP %s %s %s",
                        variant_name,
                        idx,
                        str(getattr(e, "code", "")),
                        str(getattr(e, "reason", "")),
                        _redact_sensitive_text(err_body)[:160],
                    )
                else:
                    logging.info("快速登录请求失败（drcom，%s，第 %d 轮）：%s", variant_name, idx, type(e).__name__)
                continue

            obj = _parse_json_or_jsonp(body)
            if obj is None:
                logging.info(
                    "快速登录返回非 JSON（drcom，%s，第 %d 轮）：%s",
                    variant_name,
                    idx,
                    _redact_sensitive_text(body or "")[:160],
                )
                continue

            result = obj.get("result")
            if result == 1 or result == "1" or str(result).lower() == "ok":
                return True

            ret_code = obj.get("ret_code")
            msg = obj.get("msg") or obj.get("message") or ""
            if isinstance(msg, str) and msg:
                msg = msg.strip().replace("\r", " ").replace("\n", " ")
            logging.info("快速登录未成功（drcom，%s，第 %d 轮）：ret_code=%s msg=%s", variant_name, idx, str(ret_code), str(msg)[:160])

    return False


def is_portal_logged_in(config: AppConfig) -> Optional[bool]:
    """访问门户探测页判断是否已登录；返回 True/False，失败返回 None。"""

    ok, _, html = _http_get(config.portal_probe_url, timeout_seconds=6.0)
    if not ok or not html:
        return None
    m = re.search(r"<title>\s*(.*?)\s*</title>", html, flags=re.IGNORECASE | re.DOTALL)
    title = (m.group(1).strip() if m else "").replace("\n", " ").replace("\r", " ")
    if "注销页" in title:
        return True
    if "登录" in title or "认证" in title:
        return False
    return None


def _build_login_url(config: AppConfig, portal_html_hint: Optional[str]) -> str:
    """基于配置与门户页面提示构造登录 URL。"""

    port = config.portal_login_port
    path = config.portal_login_path

    if portal_html_hint:
        p2, path2 = _extract_portal_login_params(portal_html_hint)
        if p2:
            port = p2
        if path2:
            path = path2

    host = config.portal_host or PORTAL_HOST
    url = f"http://{host}:{port}{path}"
    if portal_html_hint:
        extra = _extract_portal_login_param_kv(portal_html_hint)
        if extra:
            sep = "&" if "?" in url else "?"
            url = url + sep + urllib.parse.urlencode(extra, doseq=False)
    return url


def _login_payload_variants(username: str, password: str, service_type_id: str) -> Iterable[dict[str, str]]:
    """生成多种 Dr.COM 常见登录参数组合，提升兼容性。"""

    base = {
        "DDDDD": username,
        "upass": password,
        "R6": "0",
        "para": "00",
        "0MKKey": "123456",
        "buttonClicked": "",
        "redirect_url": "",
        "err_flag": "0",
        "username": "",
        "password": "",
        "user": "",
        "cmd": "",
        "Login": "",
    }

    sid = service_type_id if service_type_id else "1"

    v1 = dict(base)
    v1.update({"R1": sid, "R2": "0", "R3": "0"})
    yield v1

    v2 = dict(base)
    v2.update({"R1": "0", "R2": sid, "R3": "0"})
    yield v2

    v3 = dict(base)
    v3.update({"R1": "0", "R2": "0", "R3": sid})
    yield v3


def portal_login(config: AppConfig, creds: Credentials) -> bool:
    """执行一次门户登录；成功返回 True，失败返回 False。"""

    try:
        if _portal_login_drcom(config, creds):
            return True
    except Exception as e:
        logging.info("快速登录异常（drcom）：%s", type(e).__name__)

    ok, _, portal_html = _http_get(config.portal_probe_url, timeout_seconds=6.0)
    login_url = _build_login_url(config, portal_html if ok else None)

    for idx, payload in enumerate(_login_payload_variants(creds.username, creds.password, config.service_type_id), start=1):
        data = urllib.parse.urlencode(payload).encode("utf-8")
        req = urllib.request.Request(
            login_url,
            data=data,
            method="POST",
            headers={
                "User-Agent": f"{APP_NAME}/1.0",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "*/*",
                "Connection": "close",
                "Referer": config.portal_probe_url,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                body = _decode_portal_bytes(resp.read(8192))
        except Exception as e:
            if isinstance(e, urllib.error.HTTPError):
                try:
                    err_body = _decode_portal_bytes(e.read(2048))
                except Exception:
                    err_body = ""
                logging.info(
                    "登录请求失败（第 %d 种参数）：HTTP %s %s %s",
                    idx,
                    str(getattr(e, "code", "")),
                    str(getattr(e, "reason", "")),
                    _redact_sensitive_text(err_body)[:160],
                )
            else:
                logging.info("登录请求失败（第 %d 种参数）：%s", idx, type(e).__name__)
            continue

        if _is_login_success_response(body):
            return True
        logging.info("登录未成功（第 %d 种参数）：%s", idx, _redact_sensitive_text(body)[:160])

        time.sleep(1)

    return False


def _is_login_success_response(body: str) -> bool:
    """判断登录响应是否表示成功（不依赖具体字段，采用多重判定）。"""

    b = (body or "").strip()
    if not b:
        return False

    if re.search(r"\b(result|ret_code)\b\s*[:=]\s*\"?1\"?", b, flags=re.IGNORECASE):
        return True
    if "Dr.COMWebLoginID_3" in b or "login_ok" in b.lower():
        return True
    if re.search(r"\"success\"\s*:\s*true", b, flags=re.IGNORECASE):
        return True
    return False


def portal_login_via_browser(config: AppConfig, creds: Credentials) -> bool:
    """打开门户页面，在浏览器中自动填充账号密码并自动点击登录。"""

    try:
        from selenium import webdriver
        from selenium.common.exceptions import WebDriverException
        from selenium.webdriver.common.by import By
        from selenium.webdriver.edge.options import Options as EdgeOptions
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.webdriver.support.ui import WebDriverWait
    except Exception:
        return False

    def _looks_logged_in(title: str, html: str) -> bool:
        """根据页面标题与内容判断是否可能登录成功。"""

        t = (title or "").strip()
        if "注销" in t:
            return True
        if "Dr.COMWebLoginID_3" in (html or ""):
            return True
        return False

    def _find_first(wait: WebDriverWait, selectors: list[tuple[str, str]]):
        """按顺序查找首个可用元素（找不到则抛出）。"""

        last = None
        for by, value in selectors:
            try:
                return wait.until(EC.presence_of_element_located((by, value)))
            except Exception as e:
                last = e
                continue
        if last:
            raise last
        raise RuntimeError("element not found")

    url = (config.portal_probe_url or "https://portal.csu.edu.cn/").strip() or "https://portal.csu.edu.cn/"
    sid = (config.service_type_id or "1").strip() or "1"

    options = EdgeOptions()
    options.add_argument("--no-first-run")
    options.add_argument("--no-default-browser-check")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-popup-blocking")
    options.add_argument("--disable-gpu")
    if bool(getattr(config, "browser_headless", True)):
        options.add_argument("--headless=new")
        options.add_argument("--window-size=1280,720")
    edge_path = (config.edge_path or "").strip()
    if edge_path and Path(edge_path).exists():
        try:
            options.binary_location = edge_path
        except Exception:
            pass

    driver = webdriver.Edge(options=options)
    try:
        driver.set_page_load_timeout(20)

        def _attempt_one(field: str) -> bool:
            """尝试一次指定运营商字段组合的页面自动登录。"""

            driver.get(url)
            wait = WebDriverWait(driver, 15)
            try:
                suffix_map = _extract_isp_suffix_map(driver.page_source)
            except Exception:
                suffix_map = {}
            isp_suffix = (suffix_map.get(sid) or _drcom_account_suffix(sid) or "").strip()

            user_el = _find_first(
                wait,
                [
                    (By.NAME, "DDDDD"),
                    (By.CSS_SELECTOR, 'input[name="DDDDD"]'),
                    (By.ID, "DDDDD"),
                    (By.CSS_SELECTOR, 'input[type="text"]'),
                ],
            )
            pass_el = _find_first(
                wait,
                [
                    (By.NAME, "upass"),
                    (By.CSS_SELECTOR, 'input[name="upass"]'),
                    (By.ID, "upass"),
                    (By.CSS_SELECTOR, 'input[type="password"]'),
                ],
            )

            try:
                user_el.clear()
            except Exception:
                pass
            user_el.send_keys(creds.username)

            try:
                pass_el.clear()
            except Exception:
                pass
            pass_el.send_keys(creds.password)

            try:
                driver.execute_script(
                    """
const sid = arguments[0];
const field = arguments[1];
const isp_suffix = arguments[2];
const set = (name, value) => {
  const el = document.querySelector(`[name="${name}"]`);
  if (!el) return;
  el.value = value;
  try { el.dispatchEvent(new Event('change', { bubbles: true })); } catch (e) {}
  try { el.dispatchEvent(new Event('input', { bubbles: true })); } catch (e) {}
};
set('R1', '0'); set('R2', '0'); set('R3', '0');
set(field, sid);

const pickIspSelect = (suffix) => {
  const sel = document.querySelector('select[name="ISP_select"]');
  if (!sel) return false;
  let target = null;
  const opts = Array.from(sel.options || []);
  if (suffix !== null && suffix !== undefined) {
    target = opts.find(o => (o && o.value) === suffix) || null;
  }
  if (!target && sid === '1') {
    target = opts.find(o => o && o.value !== '-1') || null;
  }
  if (!target) return false;
  sel.value = target.value;
  try { sel.dispatchEvent(new Event('change', { bubbles: true })); } catch (e) {}
  try { sel.dispatchEvent(new Event('input', { bubbles: true })); } catch (e) {}
  return true;
};

const pickIspRadio = (suffix) => {
  const box = document.querySelector('div[name="ISP_radio"]');
  if (!box) return false;
  const inputs = Array.from(box.querySelectorAll('input[name="network"]') || []);
  let target = null;
  if (suffix !== null && suffix !== undefined) {
    target = inputs.find(i => i && i.value === suffix) || null;
  }
  if (!target && sid === '1') {
    target = inputs.find(i => i && i.value !== '-1') || null;
  }
  if (!target) return false;
  try { target.click(); } catch (e) {}
  return true;
};

pickIspSelect(isp_suffix);
pickIspRadio(isp_suffix);
""",
                    sid,
                    field,
                    isp_suffix,
                )
            except Exception:
                pass

            for by, value in [
                (By.NAME, "C1"),
                (By.ID, "C1"),
                (By.CSS_SELECTOR, 'input[name="C1"]'),
                (By.CSS_SELECTOR, 'input[id="C1"]'),
            ]:
                try:
                    cb = driver.find_element(by, value)
                    if cb and cb.is_displayed() and not cb.is_selected():
                        try:
                            cb.click()
                        except Exception:
                            try:
                                driver.execute_script("arguments[0].click();", cb)
                            except Exception:
                                pass
                    break
                except Exception:
                    continue

            btn = None
            for by, value in [
                (By.NAME, "0MKKey"),
                (By.NAME, "0MKKey11"),
                (By.ID, "0MKKey"),
                (By.CSS_SELECTOR, 'input[name="0MKKey"]'),
                (By.CSS_SELECTOR, 'input[name="0MKKey11"]'),
                (By.CSS_SELECTOR, 'button[type="submit"]'),
                (By.CSS_SELECTOR, 'input[type="submit"]'),
                (By.CSS_SELECTOR, 'input[type="button"][value*="登录"]'),
                (By.CSS_SELECTOR, 'input[type="submit"][value*="登录"]'),
            ]:
                try:
                    btn = driver.find_element(by, value)
                    break
                except Exception:
                    continue
            if btn is None:
                try:
                    pass_el.submit()
                except Exception:
                    return False
            else:
                try:
                    btn.click()
                except Exception:
                    try:
                        driver.execute_script("arguments[0].click();", btn)
                    except Exception:
                        return False

            end = time.monotonic() + 8.0
            while time.monotonic() < end:
                try:
                    if _looks_logged_in(driver.title, driver.page_source):
                        return True
                except Exception:
                    pass
                time.sleep(0.25)

            return False

        for field in ("R1", "R2", "R3"):
            if _attempt_one(field):
                return True
        return False
    except WebDriverException as e:
        try:
            cur = ""
            title = ""
            try:
                cur = driver.current_url
            except Exception:
                cur = ""
            try:
                title = driver.title
            except Exception:
                title = ""
            logging.info("浏览器自动登录 WebDriver 异常：%s url=%s title=%s", repr(e), cur, title)
        except Exception:
            logging.info("浏览器自动登录 WebDriver 异常：%s", repr(e))
        return False
    except Exception as e:
        logging.info("浏览器自动登录异常：%s", repr(e))
        return False
    finally:
        try:
            driver.quit()
        except Exception:
            pass


def _autorun_target_exe_path() -> Path:
    """返回用于开机自启的稳定 EXE 路径（仅打包模式有效）。"""

    return _app_data_dir() / f"{APP_NAME}.exe"


def _ensure_autorun_executable() -> str:
    """确保自启使用的可执行文件存在于稳定路径，并返回应写入注册表的 EXE 路径。"""

    if not _is_frozen():
        return sys.executable
    _ensure_dirs()
    src = Path(sys.executable)
    dst = _autorun_target_exe_path()
    try:
        if src.exists():
            try:
                if src.resolve() != dst.resolve():
                    shutil.copy2(str(src), str(dst))
            except Exception:
                if not dst.exists():
                    shutil.copy2(str(src), str(dst))
    except Exception:
        return str(src)
    return str(dst if dst.exists() else src)


def portal_auto_login(config: AppConfig, creds: Credentials) -> bool:
    """执行一次自动登录（优先 HTTP，失败后回退到浏览器自动填充）。"""

    try:
        if portal_login(config, creds):
            time.sleep(2.0)
            if is_internet_available():
                logging.info("快速登录成功，互联网已可用。")
                return True
            logging.info("快速登录已提交，但检测到互联网仍不可用，将继续尝试。")
    except Exception as e:
        logging.info("快速登录异常：%s", type(e).__name__)

    try:
        if portal_login_via_browser(config, creds):
            time.sleep(2.0)
            if is_internet_available():
                logging.info("浏览器自动登录成功，互联网已可用。")
                return True
            logging.info("浏览器自动登录已完成，但检测到互联网仍不可用。")
            return False
        return False
    except Exception as e:
        logging.info("浏览器自动登录异常：%s", type(e).__name__)
        return False


def _pythonw_path() -> str:
    """返回 pythonw.exe 路径（若不可用则退回当前解释器）。"""

    exe = sys.executable
    if exe.lower().endswith("python.exe"):
        candidate = exe[:-10] + "pythonw.exe"
        if Path(candidate).exists():
            return candidate
    return exe


def _startup_command_line() -> str:
    """构造自启动时执行的命令行（GUI 模式）。"""

    if _is_frozen():
        exe = _ensure_autorun_executable()
        return f"\"{exe}\" gui --start-minimized --auto-start"
    script_path = str(Path(__file__).resolve())
    pythonw = _pythonw_path()
    return f"\"{pythonw}\" \"{script_path}\" gui --start-minimized --auto-start"


def _get_run_key(name: str) -> Optional[str]:
    """读取当前用户 Run 注册表键条目；不存在时返回 None。"""

    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, name)
            if isinstance(val, str) and val:
                return val
            return None
    except FileNotFoundError:
        return None
    except OSError:
        return None


def set_autorun_enabled(enabled: bool) -> None:
    """启用/关闭“开机自动运行”（当前用户登录自启动）。"""

    if enabled:
        _set_run_key(APP_NAME, _startup_command_line())
        return
    _delete_run_key(APP_NAME)


def is_autorun_enabled() -> bool:
    """判断是否已启用“开机自动运行”（当前用户登录自启动）。"""

    return _get_run_key(APP_NAME) is not None


def _set_run_key(name: str, command: str) -> None:
    """写入当前用户 Run 注册表键，实现登录自启动。"""

    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, command)


def _delete_run_key(name: str) -> None:
    """删除当前用户 Run 注册表键条目。"""

    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)
    except FileNotFoundError:
        return
    except OSError:
        return


def configure_interactive() -> None:
    """交互式配置：写入账号密码（DPAPI 加密）与基础配置。"""

    _ensure_dirs()
    config = load_config()

    print(f"当前 SSID：{config.ssid}")
    ssid = input("请输入要自动连接的 Wi-Fi SSID（直接回车保持不变）：").strip()
    if ssid:
        config = dataclasses.replace(config, ssid=ssid)

    service_type_id = input(f"请输入服务类型ID（默认 {config.service_type_id}，直接回车保持不变）：").strip()
    if service_type_id:
        config = dataclasses.replace(config, service_type_id=service_type_id)

    username = input("请输入账号：").strip()
    password = getpass.getpass("请输入密码（输入不可见）：").strip()
    if not username or not password:
        raise ValueError("账号或密码为空")

    save_config(config)
    save_credentials(Credentials(username=username, password=password))
    print("配置已保存（密码已加密存储）。")


def run_daemon(config: AppConfig) -> None:
    """后台循环：自动连接 Wi-Fi、检测网络、断网时尝试自动登录并在必要时打开门户页。"""

    logging.info("启动：SSID=%s，检查间隔=%ss", config.ssid, config.check_interval_seconds)

    last_login_attempt = 0.0
    opened_for_current_outage = False
    login_failures = 0

    while True:
        try:
            connect_wifi(config.ssid)
        except Exception as e:
            logging.info("连接 Wi-Fi 异常：%s", type(e).__name__)

        if is_internet_available():
            opened_for_current_outage = False
            login_failures = 0
            time.sleep(max(1, config.check_interval_seconds))
            continue

        now = time.time()
        if now - last_login_attempt < max(1, config.login_interval_seconds):
            time.sleep(1)
            continue

        last_login_attempt = now

        logged_in = is_portal_logged_in(config)
        if logged_in is True and is_internet_available():
            time.sleep(max(1, config.check_interval_seconds))
            continue

        creds = load_credentials()
        if creds:
            logging.info("检测到无法联网，正在尝试自动登录。")
            ok = portal_auto_login(config, creds)
            if ok:
                login_failures = 0
                time.sleep(2)
                if is_internet_available():
                    opened_for_current_outage = False
                    time.sleep(max(1, config.check_interval_seconds))
                    continue
                logging.info("已提交自动登录请求，但仍未连通互联网，将继续检测。")
            else:
                login_failures += 1
                logging.info("自动登录失败，将在下次检测时重试。")

            if login_failures >= 3 and not opened_for_current_outage:
                if config.auto_open_portal_page:
                    logging.info("自动登录多次失败，将打开门户页面以便手动登录。")
                    if not open_portal_page(config):
                        logging.info("打开门户页面失败。")
                    opened_for_current_outage = True
                else:
                    logging.info("自动登录多次失败，但已关闭自动打开门户页面。")
        else:
            if not opened_for_current_outage:
                if config.auto_open_portal_page:
                    logging.info("未检测到已保存的账号密码，将打开门户页面；也可在界面中保存后自动登录。")
                    if not open_portal_page(config):
                        logging.info("打开门户页面失败。")
                    opened_for_current_outage = True
                else:
                    logging.info("未检测到已保存的账号密码，且已关闭自动打开门户页面。")

        time.sleep(max(1, config.check_interval_seconds))


def run_daemon_until_stopped(config: AppConfig, stop_event: threading.Event) -> None:
    """后台循环（可停止）：自动连接 Wi-Fi、检测网络、断网时尝试自动登录并在必要时打开门户页。"""

    logging.info("启动：SSID=%s，检查间隔=%ss", config.ssid, config.check_interval_seconds)

    last_login_attempt = 0.0
    opened_for_current_outage = False
    login_failures = 0

    while not stop_event.is_set():
        try:
            connect_wifi(config.ssid)
        except Exception as e:
            logging.info("连接 Wi-Fi 异常：%s", type(e).__name__)

        if is_internet_available():
            opened_for_current_outage = False
            login_failures = 0
            stop_event.wait(timeout=max(1, config.check_interval_seconds))
            continue

        now = time.time()
        if now - last_login_attempt < max(1, config.login_interval_seconds):
            stop_event.wait(timeout=1)
            continue

        last_login_attempt = now

        logged_in = is_portal_logged_in(config)
        if logged_in is True and is_internet_available():
            stop_event.wait(timeout=max(1, config.check_interval_seconds))
            continue

        creds = load_credentials()
        if creds:
            logging.info("检测到无法联网，正在尝试自动登录。")
            ok = portal_auto_login(config, creds)
            if ok:
                login_failures = 0
                stop_event.wait(timeout=2)
                if is_internet_available():
                    opened_for_current_outage = False
                    stop_event.wait(timeout=max(1, config.check_interval_seconds))
                    continue
                logging.info("已提交自动登录请求，但仍未连通互联网，将继续检测。")
            else:
                login_failures += 1
                logging.info("自动登录失败，将在下次检测时重试。")

            if login_failures >= 3 and not opened_for_current_outage:
                if config.auto_open_portal_page:
                    logging.info("自动登录多次失败，将打开门户页面以便手动登录。")
                    if not open_portal_page(config):
                        logging.info("打开门户页面失败。")
                    opened_for_current_outage = True
                else:
                    logging.info("自动登录多次失败，但已关闭自动打开门户页面。")
        else:
            if not opened_for_current_outage:
                if config.auto_open_portal_page:
                    logging.info("未检测到已保存的账号密码，将打开门户页面；也可在界面中保存后自动登录。")
                    if not open_portal_page(config):
                        logging.info("打开门户页面失败。")
                    opened_for_current_outage = True
                else:
                    logging.info("未检测到已保存的账号密码，且已关闭自动打开门户页面。")

        stop_event.wait(timeout=max(1, config.check_interval_seconds))


def _read_log_tail(log_path: Path, max_lines: int) -> str:
    """读取日志文件末尾若干行用于展示。"""

    if max_lines <= 0:
        return ""
    if not log_path.exists():
        return ""
    try:
        text = log_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""
    lines = text.splitlines()
    return "\n".join(lines[-max_lines:])


def _read_log_since(log_path: Path, offset: int) -> tuple[str, int]:
    """从日志文件指定偏移读取新增内容，返回（文本，新的偏移）。"""

    if offset < 0:
        offset = 0
    try:
        if not log_path.exists():
            return "", 0
        size = int(log_path.stat().st_size)
        if offset > size:
            offset = 0
        with log_path.open("rb") as f:
            f.seek(offset)
            data = f.read()
            new_pos = int(f.tell())
        if not data:
            return "", new_pos
        text = data.decode("utf-8", errors="replace")
        return text, new_pos
    except Exception:
        return "", offset


def _find_edge_executable() -> Optional[str]:
    """查找本机 Edge 可执行文件路径，找不到返回 None。"""

    reg_locations: list[tuple[int, str]] = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe"),
    ]

    for hive, subkey in reg_locations:
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                val, _ = winreg.QueryValueEx(key, "")
                if isinstance(val, str) and val and Path(val).exists():
                    return str(Path(val))
        except Exception:
            continue

    env_candidates: list[str] = []
    for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
        if base:
            env_candidates.append(str(Path(base) / "Microsoft" / "Edge" / "Application" / "msedge.exe"))
    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        env_candidates.append(str(Path(local_appdata) / "Microsoft" / "Edge" / "Application" / "msedge.exe"))

    for p in env_candidates:
        try:
            if p and Path(p).exists():
                return str(Path(p))
        except Exception:
            continue

    return None


def open_portal_page(config: AppConfig) -> bool:
    """在浏览器中打开门户页面，便于手动输入账号密码登录。"""

    url = (config.portal_probe_url or "https://portal.csu.edu.cn/").strip() or "https://portal.csu.edu.cn/"
    edge_path = (config.edge_path or "").strip()
    creationflags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        if edge_path and Path(edge_path).exists():
            subprocess.Popen(
                [edge_path, url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
            )
            return True
    except Exception:
        pass

    try:
        os.startfile(url)  # type: ignore[attr-defined]
        return True
    except Exception:
        return False


def run_gui(log_path: Optional[Path], *, start_minimized: bool, auto_start: bool) -> None:
    """启动可视化界面：支持启停检测、断网时打开门户页面并支持开机自动运行。"""

    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    try:
        import pystray
        from PIL import Image, ImageDraw
    except Exception:
        pystray = None
        Image = None
        ImageDraw = None

    config = load_config()
    creds = load_credentials()
    resolved_log_path = log_path if log_path is not None else _default_log_path()
    try:
        resolved_log_path.parent.mkdir(parents=True, exist_ok=True)
        resolved_log_path.write_text("", encoding="utf-8")
    except Exception:
        pass
    _setup_logging(log_path=resolved_log_path, quiet=True)

    stop_event = threading.Event()
    worker: dict[str, Optional[threading.Thread]] = {"thread": None}
    tray_icon: dict[str, object] = {"icon": None}

    root = tk.Tk()
    root.title(APP_NAME)

    root.columnconfigure(0, weight=0)
    root.columnconfigure(1, weight=1)
    root.rowconfigure(0, weight=1)

    frm_left = ttk.Frame(root)
    frm_left.grid(row=0, column=0, sticky="nsw", padx=10, pady=10)
    frm_right = ttk.Frame(root)
    frm_right.grid(row=0, column=1, sticky="nsew", padx=(0, 10), pady=10)
    frm_right.columnconfigure(0, weight=1)
    frm_right.rowconfigure(1, weight=1)

    frm_account = ttk.LabelFrame(frm_left, text="账号信息")
    frm_account.grid(row=0, column=0, sticky="ew")
    frm_account.columnconfigure(1, weight=1)

    frm_edge = ttk.LabelFrame(frm_left, text="Edge 路径")
    frm_edge.grid(row=1, column=0, sticky="ew", pady=(10, 0))
    frm_edge.columnconfigure(0, weight=1)

    frm_monitor = ttk.LabelFrame(frm_left, text="监控设置")
    frm_monitor.grid(row=2, column=0, sticky="ew", pady=(10, 0))
    frm_monitor.columnconfigure(1, weight=1)

    frm_actions = ttk.LabelFrame(frm_left, text="运行控制")
    frm_actions.grid(row=3, column=0, sticky="ew", pady=(10, 0))
    for i in range(2):
        frm_actions.columnconfigure(i, weight=1)

    var_ssid = tk.StringVar(value=config.ssid)
    var_service = tk.StringVar(value=config.service_type_id)
    var_user = tk.StringVar(value=(creds.username if creds else ""))
    var_pass = tk.StringVar(value=(creds.password if creds else ""))
    var_edge_path = tk.StringVar(value=config.edge_path)
    var_check_interval = tk.StringVar(value=str(config.check_interval_seconds))
    var_login_interval = tk.StringVar(value=str(config.login_interval_seconds))
    var_autorun = tk.BooleanVar(value=is_autorun_enabled())
    var_browser_headless = tk.BooleanVar(value=bool(getattr(config, "browser_headless", True)))
    var_auto_open_portal = tk.BooleanVar(value=bool(getattr(config, "auto_open_portal_page", False)))

    try:
        if bool(var_autorun.get()):
            desired = _startup_command_line()
            current = _get_run_key(APP_NAME) or ""
            if current.strip() != desired.strip():
                _set_run_key(APP_NAME, desired)
    except Exception:
        pass

    carrier_to_sid: dict[str, str] = {"中国移动": "1", "中国电信": "2", "中国联通": "3"}
    sid_to_carrier: dict[str, str] = {v: k for k, v in carrier_to_sid.items()}
    initial_carrier = sid_to_carrier.get((config.service_type_id or "").strip(), "自定义")
    var_carrier = tk.StringVar(value=initial_carrier)

    ttk.Label(frm_account, text="Wi-Fi SSID").grid(row=0, column=0, sticky="w", padx=8, pady=6)
    cmb_ssid = ttk.Combobox(frm_account, textvariable=var_ssid, values=["CSU-WIFI", "CSU-Student"], state="readonly", width=21)
    cmb_ssid.grid(row=0, column=1, sticky="ew", padx=8, pady=6)

    lbl_carrier = ttk.Label(frm_account, text="运营商")
    lbl_carrier.grid(row=1, column=0, sticky="w", padx=8, pady=6)
    cmb_carrier = ttk.Combobox(frm_account, textvariable=var_carrier, values=["中国移动", "中国电信", "中国联通", "自定义"], state="readonly", width=21)
    cmb_carrier.grid(row=1, column=1, sticky="ew", padx=8, pady=6)

    ttk.Label(frm_account, text="账号").grid(row=2, column=0, sticky="w", padx=8, pady=6)
    ent_user = ttk.Entry(frm_account, textvariable=var_user, width=24)
    ent_user.grid(row=2, column=1, sticky="ew", padx=8, pady=6)

    ttk.Label(frm_account, text="密码").grid(row=3, column=0, sticky="w", padx=8, pady=6)
    ent_pass = ttk.Entry(frm_account, textvariable=var_pass, show="*", width=24)
    ent_pass.grid(row=3, column=1, sticky="ew", padx=8, pady=6)

    lbl_service = ttk.Label(frm_account, text="服务类型ID")
    lbl_service.grid(row=4, column=0, sticky="w", padx=8, pady=6)
    ent_service = ttk.Entry(frm_account, textvariable=var_service, width=24)
    ent_service.grid(row=4, column=1, sticky="ew", padx=8, pady=6)

    def _sync_service_by_carrier() -> None:
        """根据运营商下拉同步服务类型ID。"""

        carrier = var_carrier.get().strip()
        if carrier in carrier_to_sid:
            var_service.set(carrier_to_sid[carrier])
            ent_service.configure(state="disabled")
        else:
            ent_service.configure(state="normal")

    cmb_carrier.bind("<<ComboboxSelected>>", lambda _evt: _sync_service_by_carrier())

    def _update_fields_by_ssid() -> None:
        """按 SSID 决定是否显示运营商下拉。"""

        ssid = var_ssid.get().strip().lower()
        if ssid == "csu-student":
            lbl_carrier.grid()
            cmb_carrier.grid()
            lbl_service.grid()
            ent_service.grid()
            if var_carrier.get().strip() not in {"中国移动", "中国电信", "中国联通", "自定义"}:
                var_carrier.set("中国移动")
            _sync_service_by_carrier()
            if var_carrier.get().strip() == "中国移动" and not (var_service.get().strip().isdigit() and int(var_service.get().strip()) > 0):
                var_service.set("1")
        else:
            lbl_carrier.grid_remove()
            cmb_carrier.grid_remove()
            lbl_service.grid_remove()
            ent_service.grid_remove()
            if var_service.get().strip() != "1":
                var_service.set("1")
            ent_service.configure(state="disabled")

    cmb_ssid.bind("<<ComboboxSelected>>", lambda _evt: _update_fields_by_ssid())
    _update_fields_by_ssid()

    ent_edge = ttk.Entry(frm_edge, textvariable=var_edge_path, width=36)
    ent_edge.grid(row=0, column=0, sticky="ew", padx=8, pady=6)
    btn_edge_auto = ttk.Button(frm_edge, text="自动查找")
    btn_edge_pick = ttk.Button(frm_edge, text="选择")
    btn_edge_auto.grid(row=0, column=1, sticky="ew", padx=(0, 8), pady=6)
    btn_edge_pick.grid(row=0, column=2, sticky="ew", padx=(0, 8), pady=6)

    ttk.Label(frm_monitor, text="检测间隔(秒)").grid(row=0, column=0, sticky="w", padx=8, pady=6)
    ent_check = ttk.Entry(frm_monitor, textvariable=var_check_interval, width=10)
    ent_check.grid(row=0, column=1, sticky="w", padx=8, pady=6)

    ttk.Label(frm_monitor, text="重登间隔(秒)").grid(row=1, column=0, sticky="w", padx=8, pady=6)
    ent_login = ttk.Entry(frm_monitor, textvariable=var_login_interval, width=10)
    ent_login.grid(row=1, column=1, sticky="w", padx=8, pady=6)

    chk_headless = ttk.Checkbutton(frm_monitor, text="浏览器无界面", variable=var_browser_headless)
    chk_open_portal = ttk.Checkbutton(frm_monitor, text="失败自动打开门户", variable=var_auto_open_portal)
    chk_headless.grid(row=2, column=0, columnspan=2, sticky="w", padx=8, pady=(2, 2))
    chk_open_portal.grid(row=3, column=0, columnspan=2, sticky="w", padx=8, pady=(2, 6))

    btn_save = ttk.Button(frm_actions, text="保存配置")
    btn_start = ttk.Button(frm_actions, text="开始运行")
    btn_stop = ttk.Button(frm_actions, text="停止运行", state="disabled")
    btn_open_dir = ttk.Button(frm_actions, text="打开配置目录")
    btn_exit = ttk.Button(frm_actions, text="退出程序")
    btn_about = ttk.Button(frm_actions, text="关于")
    chk_autorun = ttk.Checkbutton(frm_actions, text="开机自动运行", variable=var_autorun)

    btn_save.grid(row=0, column=0, sticky="ew", padx=6, pady=6)
    btn_start.grid(row=0, column=1, sticky="ew", padx=6, pady=6)
    btn_stop.grid(row=1, column=0, sticky="ew", padx=6, pady=6)
    btn_open_dir.grid(row=1, column=1, sticky="ew", padx=6, pady=6)
    chk_autorun.grid(row=2, column=0, columnspan=2, sticky="w", padx=8, pady=(6, 2))
    btn_exit.grid(row=3, column=0, sticky="ew", padx=6, pady=6)
    btn_about.grid(row=3, column=1, sticky="ew", padx=6, pady=6)

    frm_status = ttk.LabelFrame(frm_right, text="状态")
    frm_status.grid(row=0, column=0, sticky="ew")
    for i in range(4):
        frm_status.columnconfigure(i, weight=1)

    var_wifi = tk.StringVar(value="未知")
    var_inet = tk.StringVar(value="未知")
    var_portal = tk.StringVar(value="未知")
    var_running = tk.StringVar(value="未运行")

    ttk.Label(frm_status, text="运行状态").grid(row=0, column=0, sticky="w", padx=8, pady=6)
    ttk.Label(frm_status, textvariable=var_running).grid(row=0, column=1, sticky="w", padx=8, pady=6)
    ttk.Label(frm_status, text="当前 Wi-Fi").grid(row=0, column=2, sticky="w", padx=8, pady=6)
    ttk.Label(frm_status, textvariable=var_wifi).grid(row=0, column=3, sticky="w", padx=8, pady=6)

    ttk.Label(frm_status, text="互联网").grid(row=1, column=0, sticky="w", padx=8, pady=6)
    ttk.Label(frm_status, textvariable=var_inet).grid(row=1, column=1, sticky="w", padx=8, pady=6)
    ttk.Label(frm_status, text="门户").grid(row=1, column=2, sticky="w", padx=8, pady=6)
    ttk.Label(frm_status, textvariable=var_portal).grid(row=1, column=3, sticky="w", padx=8, pady=6)

    frm_log = ttk.LabelFrame(frm_right, text="运行日志")
    frm_log.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
    frm_log.columnconfigure(0, weight=1)
    frm_log.rowconfigure(0, weight=1)

    txt_log = tk.Text(frm_log, height=20, wrap="none")
    yscroll = ttk.Scrollbar(frm_log, orient="vertical", command=txt_log.yview)
    xscroll = ttk.Scrollbar(frm_log, orient="horizontal", command=txt_log.xview)
    txt_log.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
    txt_log.grid(row=0, column=0, sticky="nsew", padx=8, pady=(8, 0))
    yscroll.grid(row=0, column=1, sticky="ns", pady=(8, 0))
    xscroll.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 8))
    txt_log.configure(state="disabled")

    def _save_now() -> AppConfig:
        """从界面读取并保存配置与凭据，返回最新配置。"""

        ssid = var_ssid.get().strip()
        edge_path = var_edge_path.get().strip()
        service = var_service.get().strip()
        username = var_user.get().strip()
        password = var_pass.get()
        check_interval = var_check_interval.get().strip()
        login_interval = var_login_interval.get().strip()

        if not ssid:
            raise ValueError("SSID 不能为空")
        if not service:
            raise ValueError("服务类型ID 不能为空")
        if not service.isdigit():
            raise ValueError("服务类型ID 必须为数字")
        if not check_interval.isdigit() or int(check_interval) <= 0:
            raise ValueError("检测间隔必须为正整数")
        if not login_interval.isdigit() or int(login_interval) <= 0:
            raise ValueError("重登间隔必须为正整数")

        new_cfg = dataclasses.replace(
            config,
            ssid=ssid,
            service_type_id=service,
            edge_path=edge_path,
            browser_headless=bool(var_browser_headless.get()),
            auto_open_portal_page=bool(var_auto_open_portal.get()),
            check_interval_seconds=int(check_interval),
            login_interval_seconds=int(login_interval),
        )
        save_config(new_cfg)
        if username and password:
            save_credentials(Credentials(username=username, password=password))
        return new_cfg

    def on_save() -> None:
        """保存按钮回调。"""

        nonlocal config
        try:
            config = _save_now()
            messagebox.showinfo("已保存", "配置已保存（密码已加密存储）。")
        except Exception as e:
            messagebox.showerror("保存失败", str(e))

    def _worker_entry(cfg: AppConfig) -> None:
        """后台线程入口，运行自动联网循环直到停止。"""

        try:
            run_daemon_until_stopped(cfg, stop_event)
        except Exception as e:
            logging.info("后台线程异常退出：%s", type(e).__name__)

    def on_start() -> None:
        """开始运行按钮回调。"""

        nonlocal config
        if worker["thread"] is not None and worker["thread"].is_alive():
            return
        try:
            config = _save_now()
        except Exception as e:
            messagebox.showerror("无法启动", str(e))
            return

        stop_event.clear()
        t = threading.Thread(target=_worker_entry, args=(config,), daemon=True)
        worker["thread"] = t
        t.start()
        btn_start.configure(state="disabled")
        btn_stop.configure(state="normal")
        var_running.set("运行中")

    def on_stop() -> None:
        """停止运行按钮回调。"""

        stop_event.set()
        btn_stop.configure(state="disabled")
        var_running.set("停止中")

        def _poll_worker_stopped() -> None:
            """轮询后台线程是否已停止，避免阻塞 UI。"""

            t = worker.get("thread")
            if t is not None and t.is_alive():
                root.after(200, _poll_worker_stopped)
                return
            btn_start.configure(state="normal")
            btn_stop.configure(state="disabled")
            var_running.set("未运行")

        root.after(0, _poll_worker_stopped)

    def on_toggle_autorun() -> None:
        """开机自动运行勾选框回调。"""

        try:
            set_autorun_enabled(bool(var_autorun.get()))
        except Exception as e:
            var_autorun.set(is_autorun_enabled())
            messagebox.showerror("设置失败", str(e))

    def on_open_dir() -> None:
        """打开配置目录按钮回调。"""

        try:
            _ensure_dirs()
            subprocess.run(["explorer", str(_app_data_dir())], check=False)
        except Exception as e:
            messagebox.showerror("打开失败", str(e))

    def on_edge_auto() -> None:
        """自动查找 Edge 路径按钮回调。"""

        p = _find_edge_executable()
        if not p:
            messagebox.showwarning("未找到", "未找到 Edge 可执行文件。")
            return
        var_edge_path.set(p)

    def on_edge_pick() -> None:
        """选择 Edge 路径按钮回调。"""

        p = filedialog.askopenfilename(
            title="选择 msedge.exe",
            filetypes=[("msedge.exe", "msedge.exe"), ("可执行文件", "*.exe"), ("所有文件", "*.*")],
        )
        if p:
            var_edge_path.set(p)

    def on_about() -> None:
        """关于按钮回调。"""

        messagebox.showinfo(
            "关于",
            f"CSU 自动联网助手\n\n版本：{APP_VERSION}\n作者：李炎龙\n\n功能：在连接校园网时自动完成门户认证，"
            "支持快速登录、断网重连与开机自启，并可在后台托盘运行。",
        )

    status_lock = threading.Lock()
    status_snapshot: dict[str, str] = {"wifi": "未知", "inet": "未知", "portal": "未知"}
    probe_stop_event = threading.Event()
    probe_worker: dict[str, Optional[threading.Thread]] = {"thread": None}

    def _probe_status_loop() -> None:
        """后台探测当前 Wi-Fi、互联网与门户状态，避免阻塞 UI 线程。"""

        next_wifi = 0.0
        next_inet = 0.0
        next_portal = 0.0

        wifi = "未知"
        inet = "未知"
        portal = "未知"

        while not probe_stop_event.is_set():
            now = time.monotonic()

            if now >= next_wifi:
                try:
                    ssid_now = get_current_ssid()
                    wifi = ssid_now if ssid_now else "未连接"
                except Exception:
                    wifi = "未知"
                next_wifi = now + 2.0

            if now >= next_inet:
                try:
                    inet = "可用" if is_internet_available() else "不可用"
                except Exception:
                    inet = "未知"
                next_inet = now + 4.0

            if now >= next_portal:
                try:
                    if inet == "可用":
                        portal = "已联网"
                    else:
                        st = is_portal_logged_in(load_config())
                        if st is True:
                            portal = "已登录"
                        elif st is False:
                            portal = "未登录"
                        else:
                            portal = "未知"
                except Exception:
                    portal = "未知"
                next_portal = now + 8.0

            with status_lock:
                status_snapshot["wifi"] = wifi
                status_snapshot["inet"] = inet
                status_snapshot["portal"] = portal

            next_tick = min(next_wifi, next_inet, next_portal)
            probe_stop_event.wait(timeout=max(0.2, min(2.0, next_tick - time.monotonic())))

    def refresh_status() -> None:
        """定时刷新状态与日志显示。"""

        with status_lock:
            var_wifi.set(status_snapshot.get("wifi", "未知"))
            var_inet.set(status_snapshot.get("inet", "未知"))
            var_portal.set(status_snapshot.get("portal", "未知"))

        new_text, new_pos = _read_log_since(resolved_log_path, int(log_state["pos"]))
        log_state["pos"] = int(new_pos)
        if new_text:
            txt_log.configure(state="normal")
            txt_log.insert(tk.END, new_text)
            max_lines = 800
            try:
                current_lines = int(txt_log.index("end-1c").split(".")[0])
                if current_lines > max_lines:
                    drop = current_lines - max_lines
                    txt_log.delete("1.0", f"{drop + 1}.0")
            except Exception:
                pass
            txt_log.configure(state="disabled")
            txt_log.see(tk.END)

        root.after(2000, refresh_status)

    def on_exit() -> None:
        """退出程序按钮回调。"""

        try:
            icon_obj = tray_icon.get("icon")
        except Exception:
            icon_obj = None
        if icon_obj is not None:
            try:
                icon_obj.stop()
            except Exception:
                pass
        try:
            probe_stop_event.set()
            t2 = probe_worker.get("thread")
            if t2 is not None:
                t2.join(timeout=2)
        except Exception:
            pass
        try:
            stop_event.set()
            t = worker.get("thread")
            if t is not None:
                t.join(timeout=2)
        except Exception:
            pass
        root.destroy()

    def _tray_show() -> None:
        """从托盘恢复主窗口。"""

        def _do() -> None:
            try:
                root.deiconify()
                root.after(0, root.lift)
            except Exception:
                pass

        root.after(0, _do)

    def _tray_exit() -> None:
        """从托盘退出程序。"""

        root.after(0, on_exit)

    def _run_tray_icon() -> None:
        """运行系统托盘图标循环。"""

        if pystray is None or Image is None or ImageDraw is None:
            return
        try:
            size = 64
            image = Image.new("RGB", (size, size), (0, 102, 204))
            drawer = ImageDraw.Draw(image)
            drawer.rectangle((8, 8, 56, 56), outline=(255, 255, 255), width=4)
        except Exception:
            return

        menu = pystray.Menu(
            pystray.MenuItem("显示主界面", lambda: _tray_show()),
            pystray.MenuItem("退出程序", lambda: _tray_exit()),
        )
        icon = pystray.Icon(APP_NAME, image, APP_NAME, menu)
        tray_icon["icon"] = icon
        try:
            icon.run()
        finally:
            tray_icon["icon"] = None

    def on_close() -> None:
        """窗口关闭回调：隐藏到系统托盘或退出程序。"""

        if tray_icon.get("icon") is not None:
            try:
                root.withdraw()
                return
            except Exception:
                pass
        on_exit()

    btn_save.configure(command=on_save)
    btn_start.configure(command=on_start)
    btn_stop.configure(command=on_stop)
    btn_open_dir.configure(command=on_open_dir)
    btn_exit.configure(command=on_exit)
    btn_about.configure(command=on_about)
    btn_edge_auto.configure(command=on_edge_auto)
    btn_edge_pick.configure(command=on_edge_pick)
    chk_autorun.configure(command=on_toggle_autorun)

    root.protocol("WM_DELETE_WINDOW", on_close)
    log_state: dict[str, int] = {"pos": 0}
    try:
        if resolved_log_path.exists():
            log_state["pos"] = int(resolved_log_path.stat().st_size)
    except Exception:
        log_state["pos"] = 0
    try:
        txt_log.configure(state="normal")
        txt_log.delete("1.0", tk.END)
        txt_log.configure(state="disabled")
    except Exception:
        pass
    try:
        probe_stop_event.clear()
        t2 = threading.Thread(target=_probe_status_loop, daemon=True)
        probe_worker["thread"] = t2
        t2.start()
    except Exception:
        pass
    if pystray is not None and Image is not None and ImageDraw is not None:
        try:
            t_tray = threading.Thread(target=_run_tray_icon, daemon=True)
            t_tray.start()
        except Exception:
            pass
    refresh_status()
    if start_minimized:
        root.iconify()
    if auto_start:
        root.after(0, on_start)
    root.mainloop()


def main(argv: list[str]) -> int:
    """程序入口：处理命令行并执行相应动作。"""

    parser = argparse.ArgumentParser(prog="csu_autonet", add_help=True)
    sub = parser.add_subparsers(dest="cmd", required=False)

    sub.add_parser("configure", help="交互式配置账号密码（加密存储）")

    p_gui = sub.add_parser("gui", help="启动可视化界面")
    p_gui.add_argument("--log", default="", help="日志文件路径（默认写入 AppData）")
    p_gui.add_argument("--start-minimized", action="store_true", help="启动后最小化窗口")
    p_gui.add_argument("--auto-start", action="store_true", help="启动后自动开始运行")

    p_run = sub.add_parser("run", help="运行自动联网守护循环")
    p_run.add_argument("--quiet", action="store_true", help="不输出到控制台，仅写日志")
    p_run.add_argument("--log", default="", help="日志文件路径（默认写入 AppData）")

    args = parser.parse_args(argv)
    cmd = args.cmd or "gui"

    if cmd == "configure":
        configure_interactive()
        return 0

    if cmd == "gui":
        log_path = Path(args.log).expanduser().resolve() if getattr(args, "log", "") else None
        run_gui(
            log_path=log_path,
            start_minimized=bool(getattr(args, "start_minimized", False)),
            auto_start=bool(getattr(args, "auto_start", False)),
        )
        return 0

    if cmd == "run":
        config = load_config()
        log_path = Path(args.log).expanduser().resolve() if getattr(args, "log", "") else _default_log_path()
        _setup_logging(log_path=log_path, quiet=bool(getattr(args, "quiet", False)))
        run_daemon(config)
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

