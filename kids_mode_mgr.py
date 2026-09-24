# -*- coding: utf-8 -*-
import json
import tkinter as tk
from tkinter import messagebox
import win32net
import win32netcon
import win32serviceutil
import win32service
import win32event
import servicemanager
import win32security
import win32api
import win32con
import ntsecuritycon as con
import win32ts
import time
import os
import ctypes
from ctypes import wintypes
import winreg
from datetime import datetime, date
import hashlib
import sys
import subprocess
import threading


# =============================================================================
# WTS API
# =============================================================================
WTS_CURRENT_SERVER_HANDLE = 0
WTSActive = 0
WTSUserName = 5
WTSDomainName = 7
WTSConnected = 1
WTSConnectQuery = 2
WTSShadow = 3
WTSDisconnected = 4
WTSIdle = 5
WTSListen = 6
WTSReset = 7
WTSDown = 8
WTSInit = 9
WTSSessionInfoEx = 25
INVALID_SESSION_ID = 0xFFFFFFFF
WTS_SESSIONSTATE_LOCK = 0
WTS_SESSIONSTATE_UNLOCK = 1
WTS_SESSIONSTATE_UNKNOWN = 0xFFFFFFFF
MB_OK = 0
MB_ICONWARNING = 0x30
MB_ICONINFORMATION = 0x40
ADMINISTRATORS_SID_STR = "S-1-5-32-544"
ADMINISTRATORS_SID = win32security.ConvertStringSidToSid(ADMINISTRATORS_SID_STR)
TOKEN_ELEVATION_TYPE_LIMITED = 3
PASSWORD_ROTATION_DATE_FORMAT = "%Y%m%d"
POWER_RESUME_EVENT_TYPES = {
    win32con.PBT_APMRESUMEAUTOMATIC,
    win32con.PBT_APMRESUMESUSPEND,
}

class WTS_SESSION_INFO(ctypes.Structure):
    _fields_ = [("SessionId", ctypes.c_uint32),
                ("pWinStationName", ctypes.c_char_p),
                ("State", ctypes.c_uint32)]

class WTSINFOEX_LEVEL1_W(ctypes.Structure):
    _fields_ = [
        ("SessionId", ctypes.c_uint32),
        ("SessionState", ctypes.c_uint32),
        ("SessionFlags", ctypes.c_int32),
        ("WinStationName", ctypes.c_wchar * 33),
        ("UserName", ctypes.c_wchar * 21),
        ("DomainName", ctypes.c_wchar * 18),
        ("LogonTime", ctypes.c_int64),
        ("ConnectTime", ctypes.c_int64),
        ("DisconnectTime", ctypes.c_int64),
        ("LastInputTime", ctypes.c_int64),
        ("CurrentTime", ctypes.c_int64),
        ("IncomingBytes", ctypes.c_uint32),
        ("OutgoingBytes", ctypes.c_uint32),
        ("IncomingFrames", ctypes.c_uint32),
        ("OutgoingFrames", ctypes.c_uint32),
        ("IncomingCompressedBytes", ctypes.c_uint32),
        ("OutgoingCompressedBytes", ctypes.c_uint32),
    ]

class WTSINFOEX_LEVEL_W(ctypes.Union):
    _fields_ = [("WTSInfoExLevel1", WTSINFOEX_LEVEL1_W)]

class WTSINFOEX_W(ctypes.Structure):
    _fields_ = [
        ("Level", ctypes.c_uint32),
        ("Data", WTSINFOEX_LEVEL_W),
    ]

wtsapi32 = ctypes.windll.wtsapi32
kernel32 = ctypes.windll.kernel32
kernel32.WTSGetActiveConsoleSessionId.restype = ctypes.c_uint32

WTS_STATE_NAMES = {
    WTSActive: "Active",
    WTSConnected: "Connected",
    WTSConnectQuery: "ConnectQuery",
    WTSShadow: "Shadow",
    WTSDisconnected: "Disconnected",
    WTSIdle: "Idle",
    WTSListen: "Listen",
    WTSReset: "Reset",
    WTSDown: "Down",
    WTSInit: "Init",
}

def wts_state_name(state):
    return WTS_STATE_NAMES.get(int(state), f"Unknown({state})")

def is_windows_7():
    try:
        version = sys.getwindowsversion()
        return version.major == 6 and version.minor == 1
    except Exception:
        return False

def query_session_unlocked(session_id):
    if session_id is None:
        return None

    pBuffer = ctypes.c_void_p()
    bytes_returned = ctypes.c_uint32()
    try:
        ok = wtsapi32.WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            ctypes.c_uint32(session_id),
            ctypes.c_int(WTSSessionInfoEx),
            ctypes.byref(pBuffer),
            ctypes.byref(bytes_returned),
        )
        if not ok or not pBuffer.value or bytes_returned.value < ctypes.sizeof(WTSINFOEX_W):
            return None

        info = ctypes.cast(pBuffer, ctypes.POINTER(WTSINFOEX_W)).contents
        if info.Level != 1:
            return None

        flags = int(info.Data.WTSInfoExLevel1.SessionFlags)
        if flags == WTS_SESSIONSTATE_UNKNOWN:
            return None

        if is_windows_7():
            return flags == WTS_SESSIONSTATE_LOCK
        return flags == WTS_SESSIONSTATE_UNLOCK
    except Exception as e:
        write_log(f"查询会话锁定状态失败：session_id={session_id}, error={e}")
        return None
    finally:
        if pBuffer.value:
            wtsapi32.WTSFreeMemory(pBuffer)

def lock_state_name(is_unlocked):
    if is_unlocked is True:
        return "Unlocked"
    if is_unlocked is False:
        return "Locked"
    return "Unknown"

def _decode_station_name(raw_name):
    if not raw_name:
        return ""
    if isinstance(raw_name, bytes):
        return raw_name.decode("utf-8", errors="ignore")
    return str(raw_name)

def enumerate_sessions():
    pSessionInfo = ctypes.POINTER(WTS_SESSION_INFO)()
    pCount = ctypes.c_uint32()
    sessions = []
    if wtsapi32.WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1,
                                       ctypes.byref(pSessionInfo), ctypes.byref(pCount)):
        try:
            for i in range(pCount.value):
                sess = pSessionInfo[i]
                sessions.append({
                    "session_id": int(sess.SessionId),
                    "state": int(sess.State),
                    "state_name": wts_state_name(sess.State),
                    "station_name": _decode_station_name(sess.pWinStationName),
                })
        finally:
            wtsapi32.WTSFreeMemory(pSessionInfo)
    return sessions

def get_console_session_info():
    console_session_id = int(kernel32.WTSGetActiveConsoleSessionId())
    if console_session_id == INVALID_SESSION_ID:
        console_session_id = None

    sessions = enumerate_sessions()
    console_session = None
    for session in sessions:
        if session["session_id"] == console_session_id:
            console_session = session
            break

    if console_session is None:
        return {
            "console_session_id": console_session_id,
            "active_session_id": None,
            "disconnect_session_id": None,
            "is_active": False,
            "is_unlocked": None,
            "state": None,
            "state_name": "NotFound",
            "station_name": "",
            "sessions": sessions,
        }

    is_active = console_session["state"] == WTSActive
    is_unlocked = query_session_unlocked(console_session_id) if is_active else None
    return {
        "console_session_id": console_session_id,
        "active_session_id": console_session_id if is_active and is_unlocked is True else None,
        "disconnect_session_id": console_session_id if is_active else None,
        "is_active": is_active,
        "is_unlocked": is_unlocked,
        "state": console_session["state"],
        "state_name": console_session["state_name"],
        "station_name": console_session["station_name"],
        "sessions": sessions,
    }

def format_session_snapshot(console_info):
    sessions = console_info.get("sessions", [])
    if sessions:
        session_text = "; ".join(
            f"id={sess['session_id']},station={sess['station_name'] or '-'},state={sess['state_name']}"
            for sess in sessions
        )
    else:
        session_text = "none"

    console_session_id = console_info.get("console_session_id")
    console_session_text = "None" if console_session_id is None else str(console_session_id)
    station_name = console_info.get("station_name") or "-"
    return (
        f"console_id={console_session_text}, "
        f"console_station={station_name}, "
        f"console_state={console_info.get('state_name', 'Unknown')}, "
        f"console_active={'yes' if console_info.get('is_active') else 'no'}, "
        f"console_lock={lock_state_name(console_info.get('is_unlocked'))}, "
        f"sessions=[{session_text}]"
    )

def disconnect_session(session_id):
    if session_id is None:
        return False
    return bool(wtsapi32.WTSDisconnectSession(WTS_CURRENT_SERVER_HANDLE, session_id, False))

def query_session_info_string(session_id, info_class):
    if session_id is None:
        return ""
    buffer = wintypes.LPWSTR()
    bytes_returned = wintypes.DWORD()
    if not wtsapi32.WTSQuerySessionInformationW(
        WTS_CURRENT_SERVER_HANDLE, session_id, info_class,
        ctypes.byref(buffer), ctypes.byref(bytes_returned)
    ):
        return ""
    try:
        return buffer.value or ""
    finally:
        wtsapi32.WTSFreeMemory(buffer)

def get_session_user_key(session_id):
    username = query_session_info_string(session_id, WTSUserName).strip()
    if not username:
        return None
    domain = query_session_info_string(session_id, WTSDomainName).strip()
    return f"{domain}\\{username}" if domain else username

def close_win32_handle(handle):
    if handle is None:
        return
    try:
        handle.Close()
    except Exception:
        pass

def is_token_in_admin_group(token_handle):
    if token_handle is None:
        return False
    try:
        if win32security.CheckTokenMembership(token_handle, ADMINISTRATORS_SID):
            return True
        elevation_type = win32security.GetTokenInformation(
            token_handle, win32security.TokenElevationType
        )
        if elevation_type != TOKEN_ELEVATION_TYPE_LIMITED:
            return False
        linked_token = None
        try:
            linked_token = win32security.GetTokenInformation(
                token_handle, win32security.TokenLinkedToken
            )
            return win32security.CheckTokenMembership(linked_token, ADMINISTRATORS_SID)
        finally:
            close_win32_handle(linked_token)
    except Exception:
        return False

def is_user_key_in_admin_group(user_key):
    if not user_key:
        return False
    candidates = [user_key]
    if "\\" in user_key:
        candidates.append(user_key.split("\\", 1)[1])
    for candidate in dict.fromkeys(item.strip() for item in candidates if item.strip()):
        try:
            groups = win32net.NetUserGetLocalGroups(None, candidate, win32netcon.LG_INCLUDE_INDIRECT)
        except Exception:
            continue
        for group_name in groups:
            try:
                sid, _, _ = win32security.LookupAccountName(None, group_name)
                if win32security.ConvertSidToStringSid(sid) == ADMINISTRATORS_SID_STR:
                    return True
            except Exception:
                if group_name.strip().lower() in {"administrators", "管理员"}:
                    return True
    return False

def is_session_user_admin(session_id, user_key=None):
    token = None
    try:
        token = win32ts.WTSQueryUserToken(session_id)
        if is_token_in_admin_group(token):
            return True
    except Exception:
        pass
    finally:
        close_win32_handle(token)
    return is_user_key_in_admin_group(user_key)

def get_today_key():
    return datetime.now().strftime("%Y-%m-%d")

def normalize_local_username(username):
    return str(username or "").strip()

def coerce_bool(value, default=False):
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    return bool(default)

def get_local_username_from_user_key(user_key):
    normalized = normalize_local_username(user_key)
    if not normalized:
        return ""
    if "\\" not in normalized:
        return normalized
    domain, username = normalized.split("\\", 1)
    local_domains = {os.environ.get("COMPUTERNAME", "").strip().lower(), "."}
    return username.strip() if domain.strip().lower() in local_domains else ""

def validate_password_rotation_username(username):
    normalized = normalize_local_username(username)
    if not normalized:
        return False, normalized, "请先填写需要自动改密的本地用户名。"
    if "\\" in normalized:
        return False, normalized, "自动改密目标用户必须填写本地用户名，不能使用 域\\用户名 格式。"
    try:
        win32net.NetUserGetInfo(None, normalized, 1)
    except win32net.error:
        return False, normalized, f"本地用户 {normalized} 不存在。"
    except Exception as e:
        return False, normalized, f"无法校验用户 {normalized}: {e}"
    if is_user_key_in_admin_group(normalized):
        return False, normalized, f"用户 {normalized} 属于管理员组，不能启用自动改密。"
    return True, normalized, ""

def build_password_rotation_value(now=None):
    date_key = (now or datetime.now()).strftime(PASSWORD_ROTATION_DATE_FORMAT)
    return date_key, hashlib.md5(date_key.encode("utf-8")).hexdigest()[-6:]

def create_hidden_startupinfo():
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    return startupinfo

def run_hidden_process(command):
    return subprocess.run(command, capture_output=True, text=True, errors="replace",
                          startupinfo=create_hidden_startupinfo())

def get_subprocess_output(result):
    return "\n".join(part.strip() for part in (result.stdout, result.stderr) if part and part.strip())

def get_net_executable():
    path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "net.exe")
    return path if os.path.exists(path) else "net"

def build_elevation_command():
    if getattr(sys, "frozen", False):
        return sys.executable, subprocess.list2cmdline(sys.argv[1:])
    return sys.executable, subprocess.list2cmdline([os.path.abspath(__file__)] + sys.argv[1:])

def _send_message_blocking(session_id, title, message, style, timeout):
    """在独立线程中阻塞调用 WTSSendMessageW，timeout 秒后弹窗自动关闭。"""
    try:
        response = ctypes.c_uint32(0)
        wtsapi32.WTSSendMessageW(
            WTS_CURRENT_SERVER_HANDLE,
            ctypes.c_uint32(session_id),
            ctypes.c_wchar_p(title),
            ctypes.c_uint32(len(title) * 2),
            ctypes.c_wchar_p(message),
            ctypes.c_uint32(len(message) * 2),
            ctypes.c_uint32(style),
            ctypes.c_uint32(timeout),
            ctypes.byref(response),
            ctypes.c_bool(True),   # bWait=True，timeout 到期后自动关闭
        )
    except Exception:
        pass

def send_session_message(session_id, title, message, style=MB_ICONWARNING, timeout=3):
    """非阻塞发送弹窗：在后台线程中等待 timeout 秒后自动消失，不影响服务主循环。"""
    if session_id is None:
        return
    t = threading.Thread(
        target=_send_message_blocking,
        args=(session_id, title, message, style, timeout),
        daemon=True,
    )
    t.start()

def get_uptime_seconds():
    """返回系统自启动以来的秒数，不受系统时间修改影响（GetTickCount64 约49天溢出免疫版本）。"""
    return kernel32.GetTickCount64() / 1000.0

def fmt_seconds(secs):
    """将秒数格式化为 mm:ss 或 hh:mm:ss。"""
    secs = max(0, int(secs))
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}小时{m:02d}分{s:02d}秒"
    return f"{m}分{s:02d}秒"

# =============================================================================
# 日志
# =============================================================================
# 硬编码路径，避免 SYSTEM 账户与普通用户账户环境变量不一致导致路径错误
LOG_DIR = r"C:\ProgramData\KidsModeMgr"
LOG_FILE = os.path.join(LOG_DIR, "usage.log")

def write_log(message):
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {message}\n")
    except Exception:
        pass

# =============================================================================
# 注册表 ACL 保护
# =============================================================================
REG_PATH = r"SOFTWARE\KidsModeMgr"

def apply_registry_acl():
    """
    限制 HKLM\\SOFTWARE\\KidsModeMgr 只有 SYSTEM 和 Administrators 可写，
    普通用户只能读。需要管理员权限执行。
    """
    try:
        # 先确保 key 存在
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH)
        winreg.CloseKey(key)

        sd = win32security.GetNamedSecurityInfo(
            f"MACHINE\\{REG_PATH}",
            win32security.SE_REGISTRY_KEY,
            win32security.DACL_SECURITY_INFORMATION
        )
        dacl = win32security.ACL()

        system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
        admins_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)
        users_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinUsersSid, None)

        # SYSTEM & Administrators: 完全控制
        # KEY_ALL_ACCESS / KEY_READ 属于 win32con，不在 ntsecuritycon 中
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION,
                                  win32con.KEY_ALL_ACCESS, system_sid)
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION,
                                  win32con.KEY_ALL_ACCESS, admins_sid)
        # 普通用户：只读
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION,
                                  win32con.KEY_READ, users_sid)

        win32security.SetNamedSecurityInfo(
            f"MACHINE\\{REG_PATH}",
            win32security.SE_REGISTRY_KEY,
            win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            None, None, dacl, None
        )
    except Exception as e:
        write_log(f"ACL 设置失败（可忽略）: {e}")

# =============================================================================
# 服务崩溃自动恢复
# =============================================================================
SC_ACTION_RESTART = 1
SC_ACTION_NONE = 0

class SC_ACTION(ctypes.Structure):
    _fields_ = [("Type", ctypes.c_int), ("Delay", ctypes.c_uint32)]

class SERVICE_FAILURE_ACTIONS(ctypes.Structure):
    _fields_ = [
        ("dwResetPeriod", ctypes.c_uint32),
        ("lpRebootMsg",   ctypes.c_wchar_p),
        ("lpCommand",     ctypes.c_wchar_p),
        ("cActions",      ctypes.c_uint32),
        ("lpsaActions",   ctypes.POINTER(SC_ACTION)),
    ]

SERVICE_CONFIG_FAILURE_ACTIONS = 2

def configure_service_recovery(svc_name):
    """配置服务失败后自动重启（前3次失败均在5秒后重启）。"""
    try:
        actions = (SC_ACTION * 3)(
            SC_ACTION(SC_ACTION_RESTART, 5000),
            SC_ACTION(SC_ACTION_RESTART, 5000),
            SC_ACTION(SC_ACTION_RESTART, 5000),
        )
        failure_actions = SERVICE_FAILURE_ACTIONS(
            dwResetPeriod=86400,
            lpRebootMsg=None,
            lpCommand=None,
            cActions=3,
            lpsaActions=actions,
        )
        hscm = ctypes.windll.advapi32.OpenSCManagerW(None, None, 0x0001)
        if not hscm:
            return
        hsvc = ctypes.windll.advapi32.OpenServiceW(hscm, svc_name, 0x0001 | 0x0010)
        if hsvc:
            ctypes.windll.advapi32.ChangeServiceConfig2W(
                hsvc, SERVICE_CONFIG_FAILURE_ACTIONS,
                ctypes.byref(failure_actions)
            )
            ctypes.windll.advapi32.CloseServiceHandle(hsvc)
        ctypes.windll.advapi32.CloseServiceHandle(hscm)
    except Exception as e:
        write_log(f"配置服务恢复策略失败: {e}")

# =============================================================================
# 服务类
# =============================================================================
class KidsModeService(win32serviceutil.ServiceFramework):
    _svc_name_ = "KidsModeMgrService"
    _svc_display_name_ = "Kids Mode Manager Service"
    _svc_description_ = "监控电脑使用时间，支持连续使用时长和每日总时长限制。"
    _svc_start_type_ = win32service.SERVICE_AUTO_START

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = True
        self.current_usage_seconds = 0
        self.last_active_user_key = None
        self.last_force_lock_time = 0
        self.admin_user_cache = {}
        self.user_states = {}
        self.session_was_active = False
        self.last_console_snapshot = None
        self.last_rest_log_bucket = None
        self.rest_end_logged = False

        # 防时间篡改：记录锁屏时的系统 uptime，而非 wall clock
        # uptime_at_lock 存在内存；LastForceLockTime 存 wall clock 作为持久化备份
        self.uptime_at_lock = None

        # 服务启动时尝试从 wall clock 重建 uptime_at_lock，
        # 使本次服务启动后仍能用 uptime 防篡改（而非纯 wall clock 降级）
        self._try_restore_uptime_at_lock()

        # 预警状态，避免重复弹窗
        self.warned_3min = False
        self.warned_30sec = False

        # 计时持久化：记录上次写入的分钟数，每分钟写一次
        self.last_persist_minute = -1

        # 服务启动时从注册表恢复本轮已用时间
        self._restore_daily_usage()
        self._load_user_states()

    def GetAcceptedControls(self):
        return super().GetAcceptedControls() | win32service.SERVICE_ACCEPT_POWEREVENT

    # ------------------------------------------------------------------
    # 注册表 helpers
    # ------------------------------------------------------------------
    def _get_reg_value(self, name, default):
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_READ)
            value, _ = winreg.QueryValueEx(key, name)
            winreg.CloseKey(key)
            return value
        except Exception:
            return default

    def _set_reg_value(self, name, value, val_type=winreg.REG_DWORD):
        try:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH)
            winreg.SetValueEx(key, name, 0, val_type, value)
            winreg.CloseKey(key)
        except Exception as e:
            servicemanager.LogInfoMsg(f"Registry Error: {e}")

    # ------------------------------------------------------------------
    # 配置 & 状态
    # ------------------------------------------------------------------
    def load_config(self):
        legacy = coerce_bool(self._get_reg_value("EnableRest", 1), True)
        def non_negative(name, default):
            try:
                return max(0, int(self._get_reg_value(name, default)))
            except (TypeError, ValueError):
                return default
        return {
            "max_usage_seconds": non_negative("MaxUsage", 1800),
            "mandatory_rest_seconds": non_negative("MandatoryRest", 300),
            "daily_usage_limit_seconds": non_negative("DailyUsageLimit", 0),
            "enable_continuous_usage_limit": coerce_bool(
                self._get_reg_value("EnableContinuousUsageLimit", int(legacy)), legacy
            ),
            "enable_daily_usage_limit": coerce_bool(
                self._get_reg_value("EnableDailyUsageLimit", int(legacy)), legacy
            ),
            "password_rotation_enabled": coerce_bool(
                self._get_reg_value("PasswordRotationEnabled", 1), True
            ),
            "password_rotation_username": normalize_local_username(
                self._get_reg_value("PasswordRotationUsername", "")
            ),
        }

    def rotate_password_for_username(self, username, trigger):
        valid, normalized, message = validate_password_rotation_username(username)
        if not valid:
            servicemanager.LogInfoMsg(f"{trigger}时自动改密已跳过: {message}")
            return False
        date_key, password = build_password_rotation_value()
        result = run_hidden_process([get_net_executable(), "user", normalized, password])
        output = get_subprocess_output(result)
        if result.returncode == 0:
            servicemanager.LogInfoMsg(f"{trigger}时已更新用户 {normalized} 的密码。日期种子: {date_key}")
            return True
        servicemanager.LogInfoMsg(f"{trigger}时更新用户 {normalized} 的密码失败，退出码 {result.returncode}。{output}")
        return False

    def rotate_configured_user_password(self, trigger):
        config = self.load_config()
        if not config["password_rotation_enabled"]:
            return False
        return self.rotate_password_for_username(config["password_rotation_username"], trigger)

    def rotate_timed_out_user_password(self, user_key, trigger):
        config = self.load_config()
        if not config["password_rotation_enabled"]:
            return False
        username = get_local_username_from_user_key(user_key)
        return self.rotate_password_for_username(username, trigger) if username else False

    def _load_user_states(self):
        try:
            raw = json.loads(self._get_reg_value("UserStates", "{}"))
        except Exception:
            raw = {}
        self.user_states = {}
        if isinstance(raw, dict):
            for key, value in raw.items():
                if isinstance(key, str) and isinstance(value, dict):
                    try:
                        seconds = max(0, int(value.get("daily_usage_seconds", 0)))
                    except (TypeError, ValueError):
                        seconds = 0
                    self.user_states[key] = {
                        "daily_usage_date": str(value.get("daily_usage_date", "")),
                        "daily_usage_seconds": seconds,
                    }

    def _get_user_state(self, user_key):
        state = self.user_states.setdefault(user_key, {"daily_usage_date": "", "daily_usage_seconds": 0})
        today = get_today_key()
        if state["daily_usage_date"] != today:
            state["daily_usage_date"] = today
            state["daily_usage_seconds"] = 0
        return state

    def _save_user_states(self):
        self._set_reg_value("UserStates", json.dumps(self.user_states, ensure_ascii=False), winreg.REG_SZ)

    def load_lock_state(self):
        """读取上次锁屏的 wall-clock 时间戳（持久化）。
        优先读 REG_DWORD 整数键（不受字符串解析失败影响），降级读字符串键。
        """
        # 优先用整数键（更可靠）
        val_int = self._get_reg_value("LastForceLockTimeInt", None)
        if val_int is not None:
            try:
                return float(val_int)
            except Exception:
                pass
        # 降级：字符串键
        val = self._get_reg_value("LastForceLockTime", "0")
        try:
            return float(val)
        except Exception:
            return 0.0

    def save_lock_state(self, ts):
        # 同时写 REG_SZ（wall clock）和 REG_DWORD（整数秒，防止字符串解析失败）
        self._set_reg_value("LastForceLockTime",    str(ts), winreg.REG_SZ)
        self._set_reg_value("LastForceLockTimeInt", int(ts), winreg.REG_DWORD)

    def clear_lock_state(self):
        self._set_reg_value("LastForceLockTime", "0", winreg.REG_SZ)
        self._set_reg_value("LastForceLockTimeInt", 0, winreg.REG_DWORD)
        self.uptime_at_lock = None

    def _try_restore_uptime_at_lock(self):
        """
        服务重启后，uptime_at_lock 丢失。若注册表记录的锁屏 wall-clock 时间显示
        仍在休息期内，则用当前 uptime 反推一个等效的 uptime_at_lock，
        后续判断继续用 uptime 差值而非 wall clock，抵抗时间篡改。
        """
        try:
            mandatory_rest = self._get_reg_value("MandatoryRest", 300)
            last_lock_wall = self.load_lock_state()
            if last_lock_wall <= 0:
                return
            elapsed_wall = time.time() - last_lock_wall
            if elapsed_wall < mandatory_rest:
                # 仍在休息期：反推 uptime_at_lock
                # uptime_at_lock = 当前 uptime - 已经过的秒数（按 wall clock 估算）
                # 若 wall clock 被篡改导致 elapsed_wall < 0，保守取 0（视为刚锁屏）
                elapsed_wall = max(0.0, elapsed_wall)
                self.uptime_at_lock = get_uptime_seconds() - elapsed_wall
                servicemanager.LogInfoMsg(
                    f"服务重启：恢复 uptime_at_lock，休息期剩余约 {int(mandatory_rest - elapsed_wall)} 秒"
                )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 计时持久化（Task #4）
    # ------------------------------------------------------------------
    def _today_key(self):
        return "DailyUsage_" + date.today().strftime("%Y%m%d")

    def _restore_daily_usage(self):
        """服务启动时恢复本轮已用秒数，跨天自动忽略。"""
        val = self._get_reg_value(self._today_key(), 0)
        try:
            self.current_usage_seconds = int(val)
            servicemanager.LogInfoMsg(f"恢复本轮已用时间: {self.current_usage_seconds}秒")
        except Exception:
            self.current_usage_seconds = 0

    def _persist_daily_usage(self):
        """每秒写 CurrentUsage 供 GUI 实时读取；每分钟写本轮用量防关机丢失。"""
        usage = int(self.current_usage_seconds)
        # 每秒都更新 CurrentUsage，GUI 3秒轮询时能看到最新值
        self._set_reg_value("CurrentUsage", usage)
        # 每分钟写一次持久化键，减少注册表写入频率
        current_minute = usage // 60
        if current_minute != self.last_persist_minute:
            self.last_persist_minute = current_minute
            self._set_reg_value(self._today_key(), usage)

    def _reset_usage_counter(self):
        """重置本轮可用时间，确保服务重启后不会恢复上一轮已用秒数。"""
        self.current_usage_seconds = 0
        self.last_persist_minute = -1
        self._set_reg_value("CurrentUsage", 0)
        self._set_reg_value(self._today_key(), 0)

    def _log_console_snapshot(self, console_info):
        snapshot = format_session_snapshot(console_info)
        if snapshot != self.last_console_snapshot:
            write_log(f"控制台会话状态变化：{snapshot}")
            self.last_console_snapshot = snapshot

    def _log_rest_block(self, console_info, remaining, source):
        current_bucket = remaining // 30
        if self.last_rest_log_bucket != current_bucket:
            write_log(
                f"休息期拦截控制台登录：剩余 {remaining} 秒，判定来源={source}，"
                f"{format_session_snapshot(console_info)}"
            )
            self.last_rest_log_bucket = current_bucket

    def _reset_rest_block_log(self):
        self.last_rest_log_bucket = None

    def _is_admin_user(self, session_id, user_key):
        if user_key not in self.admin_user_cache:
            self.admin_user_cache[user_key] = is_session_user_admin(session_id, user_key)
        return self.admin_user_cache[user_key]

    # ------------------------------------------------------------------
    # 服务主循环
    # ------------------------------------------------------------------
    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.is_running = False
        self._save_user_states()

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
        write_log("服务已启动。")
        try:
            self.rotate_configured_user_password("服务启动")
        except Exception as e:
            servicemanager.LogInfoMsg(f"服务启动时执行自动改密失败: {e}")
        self.main()

    def SvcOtherEx(self, control, event_type, data):
        if control == win32service.SERVICE_CONTROL_POWEREVENT and event_type in POWER_RESUME_EVENT_TYPES:
            try:
                self.rotate_configured_user_password("系统唤醒")
            except Exception as e:
                servicemanager.LogInfoMsg(f"系统唤醒后执行自动改密失败: {e}")
            return 0
        return super().SvcOtherEx(control, event_type, data)

    def main(self):
        while self.is_running:
            if win32event.WaitForSingleObject(self.hWaitStop, 1000) == win32event.WAIT_OBJECT_0:
                break
            try:
                self.check_logic()
            except Exception as e:
                servicemanager.LogInfoMsg(f"服务运行出错: {e}")

    # ------------------------------------------------------------------
    # 核心逻辑
    # ------------------------------------------------------------------
    def check_logic(self):
        config = self.load_config()
        max_usage = config["max_usage_seconds"]
        mandatory_rest = config["mandatory_rest_seconds"]
        daily_limit = config["daily_usage_limit_seconds"]
        enable_continuous = config["enable_continuous_usage_limit"]
        enable_daily = config["enable_daily_usage_limit"]

        current_uptime = get_uptime_seconds()
        last_lock_wall = self.load_lock_state()
        console_info = get_console_session_info()
        active_session = console_info["active_session_id"]
        disconnect_session_id = console_info.get("disconnect_session_id")
        if console_info.get("is_active") and console_info.get("is_unlocked") is not True:
            active_session = None
        active_user_key = get_session_user_key(active_session) if active_session is not None else None
        self._log_console_snapshot(console_info)

        elapsed_rest = None
        rest_source = None
        if enable_continuous and last_lock_wall > 0:
            if self.uptime_at_lock is not None:
                elapsed_rest = current_uptime - self.uptime_at_lock
                rest_source = "uptime"
            else:
                elapsed_rest = max(0.0, time.time() - last_lock_wall)
                rest_source = "wall-clock"
            if elapsed_rest >= mandatory_rest and not self.rest_end_logged:
                write_log(
                    f"休息期结束：已过去 {int(elapsed_rest)} 秒，"
                    f"{format_session_snapshot(console_info)}"
                )
                self.rest_end_logged = True
                self._reset_rest_block_log()
                self.clear_lock_state()
                elapsed_rest = None

        if disconnect_session_id is not None and enable_continuous and elapsed_rest is not None and elapsed_rest < mandatory_rest:
            remaining = int(mandatory_rest - elapsed_rest)
            self._log_rest_block(console_info, remaining, rest_source)
            self._reset_usage_counter()
            self.session_was_active = False
            disconnect_session(disconnect_session_id)
            return

        if active_session is None or active_user_key is None:
            if self.session_was_active:
                write_log(f"控制台会话离开活动状态，暂停计时：{format_session_snapshot(console_info)}")
            self.session_was_active = False
            return

        if self.last_active_user_key != active_user_key:
            self.current_usage_seconds = 0
            self.warned_3min = False
            self.warned_30sec = False
            self.last_active_user_key = active_user_key

        if self._is_admin_user(active_session, active_user_key):
            self.current_usage_seconds = 0
            self.session_was_active = False
            return

        user_state = self._get_user_state(active_user_key)
        if enable_daily and daily_limit > 0 and user_state["daily_usage_seconds"] >= daily_limit:
            self.rotate_timed_out_user_password(active_user_key, "每日总时长超时")
            disconnect_session(active_session)
            self.current_usage_seconds = 0
            self._reset_usage_counter()
            self._save_user_states()
            return

        remaining_usage = max_usage - self.current_usage_seconds
        if enable_continuous and remaining_usage <= 180 and not self.warned_3min:
            self.warned_3min = True
            send_session_message(
                active_session, "  儿童模式提醒  ",
                f"\n  距离锁屏还有 {fmt_seconds(remaining_usage)}，请准备保存作业。  \n\n"
                f"  已用时间：{fmt_seconds(self.current_usage_seconds)} / {fmt_seconds(max_usage)}  \n",
                MB_ICONWARNING, timeout=3,
            )
        if enable_continuous and remaining_usage <= 30 and not self.warned_30sec:
            self.warned_30sec = True
            send_session_message(
                active_session, "  儿童模式提醒  ",
                f"\n  距离锁屏还有 30 秒！请立即保存！  \n\n"
                f"  已用时间：{fmt_seconds(self.current_usage_seconds)} / {fmt_seconds(max_usage)}  \n",
                MB_ICONWARNING, timeout=3,
            )

        if not self.session_was_active:
            write_log(f"检测到本机控制台会话进入活动状态，开始计时：{format_session_snapshot(console_info)}")
        self.session_was_active = True
        self.current_usage_seconds += 1
        user_state["daily_usage_seconds"] += 1
        self._persist_daily_usage()

        if enable_daily and daily_limit > 0 and user_state["daily_usage_seconds"] >= daily_limit:
            self.rotate_timed_out_user_password(active_user_key, "每日总时长超时")
            disconnect_session(active_session)
            self.current_usage_seconds = 0
            self._reset_usage_counter()
            self._save_user_states()
            return

        if enable_continuous and self.current_usage_seconds >= max_usage:
            servicemanager.LogInfoMsg(f"Max usage reached: {max_usage}s")
            write_log(
                f"锁屏触发：本轮已用 {fmt_seconds(self.current_usage_seconds)}，"
                f"target_session={active_session}，{format_session_snapshot(console_info)}"
            )
            lock_ts = time.time()
            self.save_lock_state(lock_ts)
            self.uptime_at_lock = current_uptime
            self.rest_end_logged = False
            self._reset_rest_block_log()
            disconnect_session(active_session)
            self._reset_usage_counter()
            self._save_user_states()
            self.session_was_active = False
            self.warned_3min = False
            self.warned_30sec = False

# =============================================================================
# GUI
# =============================================================================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

class KidsModeManager(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("儿童模式管理工具")
        self.geometry("480x760")
        self.resizable(False, False)

        try:
            if getattr(sys, 'frozen', False):
                icon_path = os.path.join(sys._MEIPASS, 'app_icon.ico')
            else:
                icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app_icon.ico')
            if os.path.exists(icon_path):
                self.iconbitmap(icon_path)
        except Exception:
            pass

        self.create_widgets()
        self.load_config()
        self.refresh_service_status()
        self._update_status_panel()

    # ------------------------------------------------------------------
    # 注册表 helpers（GUI 层）
    # ------------------------------------------------------------------
    def _get_reg_value(self, name, default):
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_READ)
            value, _ = winreg.QueryValueEx(key, name)
            winreg.CloseKey(key)
            return value
        except Exception:
            return default

    def _set_reg_value(self, name, value, val_type=winreg.REG_DWORD):
        try:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH)
            winreg.SetValueEx(key, name, 0, val_type, value)
            winreg.CloseKey(key)
        except Exception as e:
            raise e

    def _is_service_running(self):
        try:
            return win32serviceutil.QueryServiceStatus(KidsModeService._svc_name_)[1] == win32service.SERVICE_RUNNING
        except Exception:
            return False

    # ------------------------------------------------------------------
    # 界面构建
    # ------------------------------------------------------------------
    def create_widgets(self):
        # ---- 参数设置 ----
        config_frame = tk.LabelFrame(self, text="参数设置", padx=15, pady=10)
        config_frame.pack(padx=15, pady=12, fill="x")

        # 最大使用时间（分钟）
        tk.Label(config_frame, text="最大使用时间:").grid(row=0, column=0, sticky="w", pady=6)
        frm_u = tk.Frame(config_frame)
        frm_u.grid(row=0, column=1, sticky="w", pady=6)
        self.entry_max_usage = tk.Entry(frm_u, width=7)
        self.entry_max_usage.pack(side="left")
        tk.Label(frm_u, text="分钟").pack(side="left", padx=4)
        self.lbl_max_usage_hint = tk.Label(frm_u, text="= 1800秒", fg="gray", font=("Microsoft YaHei UI", 8))
        self.lbl_max_usage_hint.pack(side="left")
        self.entry_max_usage.bind("<KeyRelease>", lambda e: self._update_hints())

        # 强制休息时间（分钟）
        tk.Label(config_frame, text="强制休息时间:").grid(row=1, column=0, sticky="w", pady=6)
        frm_r = tk.Frame(config_frame)
        frm_r.grid(row=1, column=1, sticky="w", pady=6)
        self.entry_mandatory_rest = tk.Entry(frm_r, width=7)
        self.entry_mandatory_rest.pack(side="left")
        tk.Label(frm_r, text="分钟").pack(side="left", padx=4)
        self.lbl_rest_hint = tk.Label(frm_r, text="= 300秒", fg="gray", font=("Microsoft YaHei UI", 8))
        self.lbl_rest_hint.pack(side="left")
        self.entry_mandatory_rest.bind("<KeyRelease>", lambda e: self._update_hints())

        self.var_enable_rest = tk.BooleanVar()
        tk.Checkbutton(config_frame, text="开启强制休息", variable=self.var_enable_rest).grid(
            row=2, column=0, columnspan=2, sticky="w", pady=6)

        tk.Label(config_frame, text="每日可用总时间:").grid(row=3, column=0, sticky="w", pady=6)
        frm_d = tk.Frame(config_frame)
        frm_d.grid(row=3, column=1, sticky="w", pady=6)
        self.entry_daily_usage_limit = tk.Entry(frm_d, width=7)
        self.entry_daily_usage_limit.pack(side="left")
        tk.Label(frm_d, text="分钟（0=不限）").pack(side="left", padx=4)

        tk.Label(config_frame, text="自动改密目标用户:").grid(row=4, column=0, sticky="w", pady=6)
        self.entry_password_rotation_username = tk.Entry(config_frame, width=25)
        self.entry_password_rotation_username.grid(row=4, column=1, pady=6, padx=5)
        self.var_enable_password_rotation = tk.BooleanVar(value=True)
        tk.Checkbutton(config_frame, text="开机/唤醒自动修改该用户密码",
                       variable=self.var_enable_password_rotation).grid(
            row=5, column=0, columnspan=2, sticky="w", pady=6)
        self.var_enable_daily_usage_limit = tk.BooleanVar(value=False)
        tk.Checkbutton(config_frame, text="开启每日总时长限制",
                       variable=self.var_enable_daily_usage_limit).grid(
            row=6, column=0, columnspan=2, sticky="w", pady=6)

        tk.Button(config_frame, text="保存配置", command=self.save_config,
                  width=20, bg="#f0f0f0").grid(row=7, column=0, columnspan=2, pady=10)

        # ---- 实时状态面板（Task #10）----
        stat_frame = tk.LabelFrame(self, text="实时状态", padx=15, pady=10)
        stat_frame.pack(padx=15, pady=4, fill="x")

        self.lbl_today_used   = tk.Label(stat_frame, text="本轮已用：--", anchor="w",
                                          font=("Microsoft YaHei UI", 10))
        self.lbl_today_used.pack(fill="x", pady=2)
        self.lbl_remaining    = tk.Label(stat_frame, text="距锁屏剩余：--", anchor="w",
                                          font=("Microsoft YaHei UI", 10))
        self.lbl_remaining.pack(fill="x", pady=2)
        self.lbl_rest_remain  = tk.Label(stat_frame, text="", anchor="w",
                                          font=("Microsoft YaHei UI", 10), fg="red")
        self.lbl_rest_remain.pack(fill="x", pady=2)

        # ---- 服务控制 ----
        control_frame = tk.LabelFrame(self, text="服务控制", padx=15, pady=10)
        control_frame.pack(padx=15, pady=4, fill="x")

        self.btn_install   = tk.Button(control_frame, text="安装服务",   command=self.install_service,   width=18)
        self.btn_install.grid(row=0, column=0, padx=8, pady=6)
        self.btn_restart   = tk.Button(control_frame, text="重启服务",   command=self.restart_service,   width=18)
        self.btn_restart.grid(row=0, column=1, padx=8, pady=6)
        self.btn_stop      = tk.Button(control_frame, text="停止服务",   command=self.stop_service,      width=18)
        self.btn_stop.grid(row=1, column=0, padx=8, pady=6)
        self.btn_uninstall = tk.Button(control_frame, text="卸载服务",   command=self.uninstall_service, width=18)
        self.btn_uninstall.grid(row=1, column=1, padx=8, pady=6)

        status_frame = tk.Frame(control_frame, pady=6)
        status_frame.grid(row=2, column=0, columnspan=2, sticky="ew")
        self.lbl_status = tk.Label(status_frame, text="服务状态: 未知", fg="gray",
                                    font=("Microsoft YaHei UI", 11, "bold"))
        self.lbl_status.pack()

        # ---- 使用记录 ----
        log_frame = tk.LabelFrame(self, text="使用记录", padx=10, pady=8)
        log_frame.pack(padx=15, pady=4, fill="both", expand=True)

        btn_bar = tk.Frame(log_frame)
        btn_bar.pack(fill="x", pady=(0, 4))
        tk.Button(btn_bar, text="刷新记录", command=self._refresh_log, width=12).pack(side="left")
        tk.Label(btn_bar, text=LOG_FILE, fg="gray",
                 font=("Microsoft YaHei UI", 7)).pack(side="left", padx=8)

        self.log_text = tk.Text(log_frame, height=8, state=tk.DISABLED,
                                font=("Consolas", 9), bg="#f8f8f8", relief="flat",
                                wrap="none")
        sb = tk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.log_text.pack(fill="both", expand=True)
        self._refresh_log()

    # ------------------------------------------------------------------
    # 实时换算提示（Task #11）
    # ------------------------------------------------------------------
    def _update_hints(self):
        for entry, lbl in [(self.entry_max_usage, self.lbl_max_usage_hint),
                           (self.entry_mandatory_rest, self.lbl_rest_hint)]:
            try:
                mins = int(entry.get())
                lbl.config(text=f"= {mins * 60}秒", fg="gray")
            except ValueError:
                lbl.config(text="请输入整数", fg="red")

    # ------------------------------------------------------------------
    # 实时状态轮询（Task #10）
    # ------------------------------------------------------------------
    def _update_status_panel(self):
        try:
            max_usage      = self._get_reg_value("MaxUsage", 1800)
            mandatory_rest = self._get_reg_value("MandatoryRest", 300)
            current_usage  = self._get_reg_value("CurrentUsage", 0)
            last_lock_str  = self._get_reg_value("LastForceLockTime", "0")
            try:
                last_lock = float(last_lock_str)
            except Exception:
                last_lock = 0.0

            self.lbl_today_used.config(
                text=f"本轮已用：{fmt_seconds(current_usage)} / {fmt_seconds(max_usage)}"
            )

            now = time.time()
            if last_lock > 0:
                elapsed_rest = now - last_lock
                enable_rest = bool(self._get_reg_value("EnableRest", 1))
                if enable_rest and elapsed_rest < mandatory_rest:
                    rest_remain = int(mandatory_rest - elapsed_rest)
                    self.lbl_rest_remain.config(
                        text=f"休息期剩余：{fmt_seconds(rest_remain)}"
                    )
                    self.lbl_remaining.config(text="距锁屏剩余：（休息期中）")
                else:
                    self.lbl_rest_remain.config(text="")
                    remaining = max(0, max_usage - current_usage)
                    self.lbl_remaining.config(text=f"距锁屏剩余：{fmt_seconds(remaining)}")
            else:
                self.lbl_rest_remain.config(text="")
                remaining = max(0, max_usage - current_usage)
                self.lbl_remaining.config(text=f"距锁屏剩余：{fmt_seconds(remaining)}")
        except Exception:
            pass
        # 每 3 秒刷新
        self.after(3000, self._update_status_panel)

    # ------------------------------------------------------------------
    # 配置读写（Task #11 单位转换）
    # ------------------------------------------------------------------
    def load_config(self):
        try:
            max_usage_sec   = self._get_reg_value("MaxUsage", 1800)
            rest_sec        = self._get_reg_value("MandatoryRest", 300)
            enable_rest     = coerce_bool(self._get_reg_value("EnableRest", 1), True)
            daily_limit_sec = self._get_reg_value("DailyUsageLimit", 0)
            password_enabled = coerce_bool(self._get_reg_value("PasswordRotationEnabled", 1), True)
            password_username = normalize_local_username(
                self._get_reg_value("PasswordRotationUsername", "")
            )
            enable_daily = coerce_bool(self._get_reg_value("EnableDailyUsageLimit", 0), False)
            self.entry_max_usage.delete(0, tk.END)
            self.entry_max_usage.insert(0, str(max_usage_sec // 60))
            self.entry_mandatory_rest.delete(0, tk.END)
            self.entry_mandatory_rest.insert(0, str(rest_sec // 60))
            self.entry_daily_usage_limit.delete(0, tk.END)
            self.entry_daily_usage_limit.insert(0, str(int(daily_limit_sec) // 60))
            self.entry_password_rotation_username.delete(0, tk.END)
            self.entry_password_rotation_username.insert(0, password_username)
            self.var_enable_rest.set(enable_rest)
            self.var_enable_password_rotation.set(password_enabled)
            self.var_enable_daily_usage_limit.set(enable_daily)
            self._update_hints()
        except Exception as e:
            messagebox.showerror("错误", f"读取配置失败: {e}")

    def save_config(self):
        try:
            max_usage_min = int(self.entry_max_usage.get())
            rest_min      = int(self.entry_mandatory_rest.get())
            daily_limit_min = int(self.entry_daily_usage_limit.get())
            if max_usage_min < 0 or rest_min < 0 or daily_limit_min < 0:
                raise ValueError("时间必须大于 0")
            enable_rest = 1 if self.var_enable_rest.get() else 0
            enable_daily = 1 if self.var_enable_daily_usage_limit.get() else 0
            password_enabled = 1 if self.var_enable_password_rotation.get() else 0
            password_username = normalize_local_username(self.entry_password_rotation_username.get())
            if password_enabled:
                valid, password_username, error = validate_password_rotation_username(password_username)
                if not valid:
                    raise ValueError(error)
            self._set_reg_value("MaxUsage",       max_usage_min * 60)
            self._set_reg_value("MandatoryRest",  rest_min * 60)
            self._set_reg_value("EnableRest",     enable_rest)
            self._set_reg_value("DailyUsageLimit", daily_limit_min * 60)
            self._set_reg_value("EnableContinuousUsageLimit", enable_rest)
            self._set_reg_value("EnableDailyUsageLimit", enable_daily)
            self._set_reg_value("PasswordRotationEnabled", password_enabled)
            self._set_reg_value("PasswordRotationUsername", password_username, winreg.REG_SZ)
        except ValueError as e:
            messagebox.showerror("错误", f"请输入有效的正整数分钟数：{e}")
            return
        except Exception as e:
            messagebox.showerror("错误", f"保存配置失败: {e}")
            return

        if self._is_service_running():
            messagebox.showinfo("成功", "配置已保存，服务将在 1 秒内自动读取新配置。")
        else:
            messagebox.showinfo("成功", "配置已保存。")

    # ------------------------------------------------------------------
    # 服务控制
    # ------------------------------------------------------------------
    def _get_exe_path(self):
        """获取当前可执行文件路径（兼容 PyInstaller 打包和直接运行）。"""
        if getattr(sys, 'frozen', False):
            return sys.executable          # 打包后的 exe 本身
        else:
            return os.path.abspath(__file__)  # 开发时用脚本路径

    def install_service(self):
        """直接调用 win32serviceutil 注册服务，再通过 SCM API 启动，不走子进程。"""
        exe = self._get_exe_path()
        svc_name = KidsModeService._svc_name_
        try:
            # 注册服务（等价于 HandleCommandLine install）
            win32serviceutil.InstallService(
                None,                             # 使用类默认的 pythonClassString
                svc_name,
                KidsModeService._svc_display_name_,
                startType=win32service.SERVICE_AUTO_START,
                exeName=exe,
                description=KidsModeService._svc_description_,
            )
        except Exception as e:
            # 如果已安装则忽略
            if "already exists" not in str(e).lower() and "1073" not in str(e):
                messagebox.showerror("安装失败", f"注册服务失败:\n{e}")
                return

        # 启动服务
        try:
            win32serviceutil.StartService(svc_name)
        except Exception as e:
            if "already running" not in str(e).lower() and "1056" not in str(e):
                messagebox.showwarning("提示", f"服务已注册，但启动失败（可手动重启）:\n{e}")

        # 配置崩溃恢复策略和注册表 ACL
        configure_service_recovery(svc_name)
        apply_registry_acl()
        write_log("服务已安装，崩溃恢复策略和注册表 ACL 已配置。")
        messagebox.showinfo("成功", "服务安装成功（已设为开机自动启动）。")
        self.refresh_service_status()

    def restart_service(self, silent=False):
        try:
            win32serviceutil.RestartService(KidsModeService._svc_name_)
            if not silent:
                messagebox.showinfo("成功", "服务已重启")
        except Exception as e:
            if not silent:
                messagebox.showerror("失败", f"重启服务失败:\n{e}")
        finally:
            self.refresh_service_status()

    def stop_service(self):
        try:
            win32serviceutil.StopService(KidsModeService._svc_name_)
            messagebox.showinfo("成功", "服务已停止")
        except Exception as e:
            messagebox.showerror("失败", f"停止服务失败:\n{e}")
        finally:
            self.refresh_service_status()

    def uninstall_service(self):
        try:
            win32serviceutil.StopService(KidsModeService._svc_name_)
        except Exception:
            pass
        try:
            win32serviceutil.RemoveService(KidsModeService._svc_name_)
            messagebox.showinfo("成功", "服务已卸载")
        except Exception as e:
            messagebox.showerror("失败", f"卸载服务失败:\n{e}")
        finally:
            self.refresh_service_status()

    def refresh_service_status(self):
        status_text, status_color, is_installed = "未知", "gray", False
        try:
            status = win32serviceutil.QueryServiceStatus(KidsModeService._svc_name_)[1]
            if status == win32service.SERVICE_RUNNING:
                status_text, status_color = "运行中", "green"
            elif status == win32service.SERVICE_STOPPED:
                status_text, status_color = "已停止", "red"
            else:
                status_text, status_color = "其他状态", "orange"
            is_installed = True
        except Exception:
            status_text, status_color, is_installed = "未安装", "black", False

        self.lbl_status.config(text=f"服务状态: {status_text}", fg=status_color)
        if is_installed:
            self.btn_install.config(state=tk.DISABLED)
            self.btn_restart.config(state=tk.NORMAL)
            self.btn_uninstall.config(state=tk.NORMAL)
            self.btn_stop.config(state=tk.NORMAL if status == win32service.SERVICE_RUNNING else tk.DISABLED)
        else:
            self.btn_install.config(state=tk.NORMAL)
            self.btn_restart.config(state=tk.DISABLED)
            self.btn_stop.config(state=tk.DISABLED)
            self.btn_uninstall.config(state=tk.DISABLED)

    # ------------------------------------------------------------------
    # 使用记录
    # ------------------------------------------------------------------
    def _refresh_log(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        if not os.path.exists(LOG_FILE):
            self.log_text.insert(tk.END, "暂无使用记录。")
        else:
            try:
                with open(LOG_FILE, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                # 显示最近 50 条
                for line in lines[-50:]:
                    self.log_text.insert(tk.END, line)
                self.log_text.see(tk.END)
            except Exception as e:
                self.log_text.insert(tk.END, f"读取日志失败: {e}")
        self.log_text.config(state=tk.DISABLED)

# =============================================================================
# 主入口
# =============================================================================
if __name__ == '__main__':
    if len(sys.argv) > 1:
        sys.exit(win32serviceutil.HandleCommandLine(KidsModeService))
    else:
        try:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(KidsModeService)
            servicemanager.StartServiceCtrlDispatcher()
        except Exception as e:
            if "1063" in str(e):
                if not is_admin():
                    executable, parameters = build_elevation_command()
                    result = ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", executable, parameters, None, 1)
                    if result <= 32:
                        ctypes.windll.user32.MessageBoxW(None, "管理员权限请求被取消或启动失败。", "错误", 0x10)
                else:
                    app = KidsModeManager()
                    app.mainloop()
            else:
                write_log(f"KidsModeMgr 启动失败: {e}")
                raise
