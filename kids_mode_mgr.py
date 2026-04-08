# -*- coding: utf-8 -*-
import json
import tkinter as tk
from tkinter import messagebox
import win32con
import win32net
import win32netcon
import win32security
import win32serviceutil
import win32service
import win32event
import servicemanager
import win32ts
import time
import os
import ctypes
from ctypes import wintypes
import winreg
from datetime import datetime
import hashlib
import sys
import subprocess

# =============================================================================
# WTS API Constants
# =============================================================================
WTS_CURRENT_SERVER_HANDLE = 0
WTSActive = 0
WTSUserName = 5
WTSDomainName = 7
REG_PATH = r"SOFTWARE\KidsModeMgr"
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

wtsapi32 = ctypes.windll.wtsapi32
kernel32 = ctypes.windll.kernel32
wtsapi32.WTSQuerySessionInformationW.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.c_int,
    ctypes.POINTER(wintypes.LPWSTR),
    ctypes.POINTER(wintypes.DWORD),
]
wtsapi32.WTSQuerySessionInformationW.restype = wintypes.BOOL

def get_active_session_id():
    pSessionInfo = ctypes.POINTER(WTS_SESSION_INFO)()
    pCount = ctypes.c_uint32()
    if wtsapi32.WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1, ctypes.byref(pSessionInfo), ctypes.byref(pCount)):
        active_session = None
        for i in range(pCount.value):
            sess = pSessionInfo[i]
            if sess.State == WTSActive:
                active_session = sess.SessionId
                break
        wtsapi32.WTSFreeMemory(pSessionInfo)
        return active_session
    return None

def disconnect_session(session_id):
    if session_id is None: return
    wtsapi32.WTSDisconnectSession(WTS_CURRENT_SERVER_HANDLE, session_id, False)

def query_session_info_string(session_id, info_class):
    if session_id is None:
        return ""

    buffer = wintypes.LPWSTR()
    bytes_returned = wintypes.DWORD()
    if not wtsapi32.WTSQuerySessionInformationW(
        WTS_CURRENT_SERVER_HANDLE,
        session_id,
        info_class,
        ctypes.byref(buffer),
        ctypes.byref(bytes_returned)
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
    if domain:
        return f"{domain}\\{username}"
    return username

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
            token_handle,
            win32security.TokenElevationType
        )
        if elevation_type != TOKEN_ELEVATION_TYPE_LIMITED:
            return False

        linked_token = None
        try:
            linked_token = win32security.GetTokenInformation(
                token_handle,
                win32security.TokenLinkedToken
            )
            return win32security.CheckTokenMembership(linked_token, ADMINISTRATORS_SID)
        except Exception:
            return False
        finally:
            close_win32_handle(linked_token)
    except Exception:
        return False

def is_user_key_in_admin_group(user_key):
    if not user_key:
        return False

    user_candidates = [user_key]
    if "\\" in user_key:
        _, username = user_key.split("\\", 1)
        user_candidates.append(username)

    checked_candidates = set()
    for candidate in user_candidates:
        normalized_candidate = candidate.strip()
        if not normalized_candidate or normalized_candidate in checked_candidates:
            continue
        checked_candidates.add(normalized_candidate)

        try:
            group_names = win32net.NetUserGetLocalGroups(
                None,
                normalized_candidate,
                win32netcon.LG_INCLUDE_INDIRECT
            )
        except Exception:
            continue

        for group_name in group_names:
            try:
                group_sid, _, _ = win32security.LookupAccountName(None, group_name)
                if win32security.ConvertSidToStringSid(group_sid) == ADMINISTRATORS_SID_STR:
                    return True
            except Exception:
                if group_name.strip().lower() in {"administrators", "管理员"}:
                    return True

    return False

def is_session_user_admin(session_id, user_key=None):
    if session_id is None:
        return False

    session_token = None
    try:
        session_token = win32ts.WTSQueryUserToken(session_id)
        if is_token_in_admin_group(session_token):
            return True
    except Exception:
        pass
    finally:
        close_win32_handle(session_token)

    return is_user_key_in_admin_group(user_key)

def get_today_key():
    return datetime.now().strftime("%Y-%m-%d")

def get_command_prefix():
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, os.path.abspath(__file__)]

def build_elevation_command():
    if getattr(sys, "frozen", False):
        return sys.executable, subprocess.list2cmdline(sys.argv[1:])
    return sys.executable, subprocess.list2cmdline([os.path.abspath(__file__)] + sys.argv[1:])

def show_error_dialog(title, message):
    ctypes.windll.user32.MessageBoxW(None, message, title, 0x10)

def report_startup_failure(message):
    try:
        servicemanager.LogErrorMsg(message)
    except Exception:
        pass

    try:
        print(message, file=sys.stderr)
    except Exception:
        pass

    try:
        if not servicemanager.RunningAsService():
            show_error_dialog("错误", message)
    except Exception:
        pass

def coerce_non_negative_int(value, default):
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default

def coerce_bool(value, default):
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

def normalize_local_username(username):
    return str(username or "").strip()

def get_local_username_from_user_key(user_key):
    normalized_user_key = normalize_local_username(user_key)
    if not normalized_user_key:
        return ""

    if "\\" not in normalized_user_key:
        return normalized_user_key

    domain, username = normalized_user_key.split("\\", 1)
    local_domains = {
        os.environ.get("COMPUTERNAME", "").strip().lower(),
        ".",
    }
    if domain.strip().lower() in local_domains:
        return username.strip()
    return ""

def validate_password_rotation_username(username):
    normalized_username = normalize_local_username(username)
    if not normalized_username:
        return False, normalized_username, "请先填写需要自动改密的本地用户名。"

    if "\\" in normalized_username:
        return False, normalized_username, "自动改密目标用户必须填写本地用户名，不能使用 域\\用户名 格式。"

    try:
        win32net.NetUserGetInfo(None, normalized_username, 1)
    except win32net.error:
        return False, normalized_username, f"本地用户 {normalized_username} 不存在。"
    except Exception as e:
        return False, normalized_username, f"无法校验用户 {normalized_username}: {e}"

    if is_user_key_in_admin_group(normalized_username):
        return False, normalized_username, f"用户 {normalized_username} 属于管理员组，不能启用自动改密。"

    return True, normalized_username, ""

def build_password_rotation_value(now=None):
    current_time = now or datetime.now()
    date_key = current_time.strftime(PASSWORD_ROTATION_DATE_FORMAT)
    password = hashlib.md5(date_key.encode("utf-8")).hexdigest()[-6:]
    return date_key, password

def create_hidden_startupinfo():
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    return startupinfo

def run_hidden_process(command):
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        errors="replace",
        startupinfo=create_hidden_startupinfo(),
    )

def get_subprocess_output(result):
    return "\n".join(
        part.strip() for part in [result.stdout, result.stderr] if part and part.strip()
    )

def get_net_executable():
    net_executable = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "net.exe")
    if os.path.exists(net_executable):
        return net_executable
    return "net"

# =============================================================================
# Service Class
# =============================================================================
class KidsModeService(win32serviceutil.ServiceFramework):
    _svc_name_ = "KidsModeMgrService"
    _svc_display_name_ = "Kids Mode Manager Service"
    _svc_description_ = "监控电脑使用时间，支持连续使用时长和每日总时长限制。"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = True
        
        try:
            self.base_path = os.path.dirname(os.path.abspath(__file__))
        except:
            self.base_path = "C:\\KidsModeMgr"
            
        self.current_usage_seconds = 0
        self.last_active_session = None
        self.last_active_user_key = None
        self.last_force_lock_time = 0
        self.admin_user_cache = {}
        self.user_states = {}
        self.load_state()

    def GetAcceptedControls(self):
        accepted_controls = super().GetAcceptedControls()
        return accepted_controls | win32service.SERVICE_ACCEPT_POWEREVENT

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.is_running = False
        self.save_state(force=True)

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
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

    def _get_reg_value(self, name, default):
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_READ)
            value, _ = winreg.QueryValueEx(key, name)
            winreg.CloseKey(key)
            return value
        except:
            return default

    def _set_reg_value(self, name, value, val_type=winreg.REG_DWORD):
        try:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH)
            winreg.SetValueEx(key, name, 0, val_type, value)
            winreg.CloseKey(key)
        except Exception as e:
            servicemanager.LogInfoMsg(f"Registry Error: {e}")

    def _delete_reg_value(self, name):
        key = None
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, name)
        except FileNotFoundError:
            pass
        except Exception as e:
            servicemanager.LogInfoMsg(f"Registry Error: {e}")
        finally:
            if key is not None:
                winreg.CloseKey(key)

    def load_config(self):
        legacy_enable_limits = coerce_bool(self._get_reg_value("EnableRest", 1), True)
        return {
            "max_usage_seconds": coerce_non_negative_int(self._get_reg_value("MaxUsage", 1800), 1800),
            "mandatory_rest_seconds": coerce_non_negative_int(self._get_reg_value("MandatoryRest", 300), 300),
            "daily_usage_limit_seconds": coerce_non_negative_int(self._get_reg_value("DailyUsageLimit", 0), 0),
            "enable_continuous_usage_limit": coerce_bool(
                self._get_reg_value("EnableContinuousUsageLimit", int(legacy_enable_limits)),
                legacy_enable_limits
            ),
            "enable_daily_usage_limit": coerce_bool(
                self._get_reg_value("EnableDailyUsageLimit", int(legacy_enable_limits)),
                legacy_enable_limits
            ),
            "password_rotation_enabled": coerce_bool(
                self._get_reg_value("PasswordRotationEnabled", 1),
                True
            ),
            "password_rotation_username": normalize_local_username(
                self._get_reg_value("PasswordRotationUsername", "")
            ),
        }

    def rotate_password_for_username(self, username, trigger):
        is_valid, normalized_username, validation_message = validate_password_rotation_username(username)
        if not is_valid:
            servicemanager.LogInfoMsg(f"{trigger}时自动改密已跳过: {validation_message}")
            return False

        date_key, password = build_password_rotation_value()
        result = run_hidden_process([get_net_executable(), "user", normalized_username, password])
        output = get_subprocess_output(result)
        if result.returncode == 0:
            servicemanager.LogInfoMsg(
                f"{trigger}时已更新用户 {normalized_username} 的密码。日期种子: {date_key}"
            )
            return True

        detail_suffix = f"\n{output}" if output else ""
        servicemanager.LogInfoMsg(
            f"{trigger}时更新用户 {normalized_username} 的密码失败，退出码 {result.returncode}。{detail_suffix}"
        )
        return False

    def rotate_configured_user_password(self, trigger):
        config = self.load_config()
        if not config.get("password_rotation_enabled", True):
            return False

        return self.rotate_password_for_username(
            config.get("password_rotation_username", ""),
            trigger
        )

    def rotate_timed_out_user_password(self, user_key, trigger):
        config = self.load_config()
        if not config.get("password_rotation_enabled", True):
            return False

        local_username = get_local_username_from_user_key(user_key)
        if not local_username:
            servicemanager.LogInfoMsg(
                f"{trigger}时自动改密已跳过: 超时用户 {user_key} 不是本地用户。"
            )
            return False

        return self.rotate_password_for_username(local_username, trigger)

    def enforce_daily_usage_limit(self, active_session, active_user_key, daily_usage_limit, save_state_first=False):
        servicemanager.LogInfoMsg(f"已达到每日可用总时间 {daily_usage_limit}秒，正在执行锁屏...")
        if save_state_first:
            self.save_state(force=True)
        try:
            self.rotate_timed_out_user_password(active_user_key, "每日总时长超时")
        except Exception as e:
            servicemanager.LogInfoMsg(f"每日总时长超时时执行自动改密失败: {e}")
        disconnect_session(active_session)
        self.current_usage_seconds = 0

    def load_state(self):
        try:
            raw_states = json.loads(self._get_reg_value("UserStates", "{}"))
        except:
            raw_states = {}

        if not isinstance(raw_states, dict):
            raw_states = {}

        embedded_last_force_lock_time = 0
        self.user_states = {}
        for user_key, raw_state in raw_states.items():
            if not isinstance(user_key, str) or not isinstance(raw_state, dict):
                continue
            embedded_last_force_lock_time = max(
                embedded_last_force_lock_time,
                self._extract_last_force_lock_time(raw_state)
            )
            self.user_states[user_key] = self._normalize_user_state(raw_state)

        self.last_force_lock_time = max(
            self._load_legacy_last_force_lock_time(),
            embedded_last_force_lock_time
        )

    def _load_legacy_last_force_lock_time(self):
        try:
            return max(0, float(self._get_reg_value("LastForceLockTime", "0")))
        except:
            return 0

    def _extract_last_force_lock_time(self, state):
        try:
            return max(0, float(state.get("last_force_lock_time", 0)))
        except:
            return 0

    def _normalize_user_state(self, state):
        try:
            daily_usage_seconds = max(0, int(state.get("daily_usage_seconds", 0)))
        except:
            daily_usage_seconds = 0

        return {
            "daily_usage_date": str(state.get("daily_usage_date", "")),
            "daily_usage_seconds": daily_usage_seconds,
        }

    def _get_user_state(self, user_key):
        state = self.user_states.get(user_key)
        if state is None:
            state = self._normalize_user_state({})
            self.user_states[user_key] = state

        self._reset_user_daily_usage_if_needed(user_key)
        return state

    def save_state(self, force=False):
        today = get_today_key()
        active_states = {}
        serialized_states = {}
        for user_key, state in self.user_states.items():
            normalized_state = self._normalize_user_state(state)
            if normalized_state["daily_usage_date"] != today:
                continue

            active_states[user_key] = normalized_state
            serialized_states[user_key] = normalized_state

        self.user_states = active_states

        self._set_reg_value("UserStates", json.dumps(serialized_states, ensure_ascii=False), winreg.REG_SZ)
        if self.last_force_lock_time > 0:
            self._set_reg_value("LastForceLockTime", str(self.last_force_lock_time), winreg.REG_SZ)
        else:
            self._delete_reg_value("LastForceLockTime")

    def _reset_user_daily_usage_if_needed(self, user_key):
        state = self.user_states.get(user_key)
        if state is None:
            return

        today = get_today_key()
        if state["daily_usage_date"] != today:
            state["daily_usage_date"] = today
            state["daily_usage_seconds"] = 0

    def _is_admin_user(self, session_id, user_key):
        cached_result = self.admin_user_cache.get(user_key)
        if cached_result is not None:
            return cached_result

        is_admin_user = is_session_user_admin(session_id, user_key)
        self.admin_user_cache[user_key] = is_admin_user
        return is_admin_user

    def main(self):
        while self.is_running:
            if win32event.WaitForSingleObject(self.hWaitStop, 1000) == win32event.WAIT_OBJECT_0:
                break
            try:
                self.check_logic()
            except Exception as e:
                servicemanager.LogInfoMsg(f"服务运行出错: {e}")

    def check_logic(self):
        config = self.load_config()
        max_usage = config.get("max_usage_seconds", 1800)
        mandatory_rest = config.get("mandatory_rest_seconds", 300)
        daily_usage_limit = config.get("daily_usage_limit_seconds", 0)
        enable_continuous_usage_limit = config.get("enable_continuous_usage_limit", True)
        enable_daily_usage_limit = config.get("enable_daily_usage_limit", True)
        current_time = time.time()
        active_session = get_active_session_id()
        active_user_key = get_session_user_key(active_session)
        
        if active_session is not None and active_user_key:
            is_admin_user = self._is_admin_user(active_session, active_user_key)
            if self.last_active_session != active_session or self.last_active_user_key != active_user_key:
                self.current_usage_seconds = 0
                self.last_active_session = active_session
                self.last_active_user_key = active_user_key
                if is_admin_user:
                    servicemanager.LogInfoMsg(f"检测到管理员账号 {active_user_key}，跳过所有管控。")

            if is_admin_user:
                return

            user_state = self._get_user_state(active_user_key)

            if enable_continuous_usage_limit:
                time_since_last_lock = current_time - self.last_force_lock_time
                if time_since_last_lock < mandatory_rest:
                    remaining_time = int(mandatory_rest - time_since_last_lock)
                    servicemanager.LogInfoMsg(f"处于强制休息期，禁止登录。剩余休息时间: {remaining_time}秒")
                    disconnect_session(active_session)
                    return

            if enable_daily_usage_limit and daily_usage_limit > 0 and user_state["daily_usage_seconds"] >= daily_usage_limit:
                self.enforce_daily_usage_limit(active_session, active_user_key, daily_usage_limit)
                return

            self.current_usage_seconds += 1
            user_state["daily_usage_seconds"] += 1

            if enable_daily_usage_limit and daily_usage_limit > 0 and user_state["daily_usage_seconds"] >= daily_usage_limit:
                self.enforce_daily_usage_limit(
                    active_session,
                    active_user_key,
                    daily_usage_limit,
                    save_state_first=True
                )
                return

            if enable_continuous_usage_limit and self.current_usage_seconds >= max_usage:
                servicemanager.LogInfoMsg(f"已达到最大使用时间 {max_usage}秒，正在执行锁屏...")
                self.last_force_lock_time = current_time
                self.save_state(force=True)
                disconnect_session(active_session)
                self.current_usage_seconds = 0
                return

            self.save_state()
        else:
            self.current_usage_seconds = 0
            self.last_active_session = None
            self.last_active_user_key = None

# =============================================================================
# GUI Manager Class
# =============================================================================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

class KidsModeManager(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("儿童模式管理工具 (Kids Mode Manager)")
        self.geometry("460x580")
        self.resizable(False, False)
        
        # 设置窗口图标
        try:
            # 如果是打包后的环境
            if getattr(sys, 'frozen', False):
                # PyInstaller 会将资源解压到 sys._MEIPASS
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

    def _get_reg_value(self, name, default):
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_READ)
            value, _ = winreg.QueryValueEx(key, name)
            winreg.CloseKey(key)
            return value
        except:
            return default

    def _set_reg_value(self, name, value, val_type=winreg.REG_DWORD):
        try:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH)
            winreg.SetValueEx(key, name, 0, val_type, value)
            winreg.CloseKey(key)
        except Exception as e:
            raise e

    def create_widgets(self):
        config_frame = tk.LabelFrame(self, text="参数设置", padx=15, pady=15)
        config_frame.pack(padx=15, pady=15, fill="x")
        
        tk.Label(config_frame, text="最大使用时间(秒):").grid(row=0, column=0, sticky="w", pady=8)
        self.entry_max_usage = tk.Entry(config_frame, width=25)
        self.entry_max_usage.grid(row=0, column=1, pady=8, padx=5)
        
        tk.Label(config_frame, text="强制休息时间(秒):").grid(row=1, column=0, sticky="w", pady=8)
        self.entry_mandatory_rest = tk.Entry(config_frame, width=25)
        self.entry_mandatory_rest.grid(row=1, column=1, pady=8, padx=5)

        tk.Label(config_frame, text="每日可用总时间(秒, 0=不限):").grid(row=2, column=0, sticky="w", pady=8)
        self.entry_daily_usage_limit = tk.Entry(config_frame, width=25)
        self.entry_daily_usage_limit.grid(row=2, column=1, pady=8, padx=5)

        tk.Label(config_frame, text="自动改密目标用户:").grid(row=3, column=0, sticky="w", pady=8)
        self.entry_password_rotation_username = tk.Entry(config_frame, width=25)
        self.entry_password_rotation_username.grid(row=3, column=1, pady=8, padx=5)

        self.var_enable_password_rotation = tk.BooleanVar(value=True)
        tk.Checkbutton(
            config_frame,
            text="开机/唤醒自动修改该用户密码",
            variable=self.var_enable_password_rotation
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=8)
        
        self.var_enable_continuous_usage_limit = tk.BooleanVar()
        tk.Checkbutton(
            config_frame,
            text="开启连续使用时长限制",
            variable=self.var_enable_continuous_usage_limit
        ).grid(row=5, column=0, columnspan=2, sticky="w", pady=8)

        self.var_enable_daily_usage_limit = tk.BooleanVar()
        tk.Checkbutton(
            config_frame,
            text="开启每日总时长限制",
            variable=self.var_enable_daily_usage_limit
        ).grid(row=6, column=0, columnspan=2, sticky="w", pady=8)
        
        tk.Button(config_frame, text="保存配置", command=self.save_config, width=20, bg="#f0f0f0").grid(row=7, column=0, columnspan=2, pady=10)
        
        control_frame = tk.LabelFrame(self, text="服务控制", padx=15, pady=15)
        control_frame.pack(padx=15, pady=5, fill="x")
        
        self.btn_install = tk.Button(control_frame, text="安装服务", command=self.install_service, width=18)
        self.btn_install.grid(row=0, column=0, padx=8, pady=8)
        self.btn_restart = tk.Button(control_frame, text="重启服务", command=self.restart_service, width=18)
        self.btn_restart.grid(row=0, column=1, padx=8, pady=8)
        self.btn_stop = tk.Button(control_frame, text="停止服务", command=self.stop_service, width=18)
        self.btn_stop.grid(row=1, column=0, padx=8, pady=8)
        self.btn_uninstall = tk.Button(control_frame, text="卸载服务", command=self.uninstall_service, width=18)
        self.btn_uninstall.grid(row=1, column=1, padx=8, pady=8)

        status_frame = tk.Frame(control_frame, pady=10)
        status_frame.grid(row=2, column=0, columnspan=2, sticky="ew")
        self.lbl_status = tk.Label(status_frame, text="服务状态: 未知", fg="gray", font=("Microsoft YaHei UI", 11, "bold"))
        self.lbl_status.pack()

    def load_config(self):
        try:
            legacy_enable_limits = coerce_bool(self._get_reg_value("EnableRest", 1), True)
            max_usage = coerce_non_negative_int(self._get_reg_value("MaxUsage", 1800), 1800)
            mandatory_rest = coerce_non_negative_int(self._get_reg_value("MandatoryRest", 300), 300)
            daily_usage_limit = coerce_non_negative_int(self._get_reg_value("DailyUsageLimit", 0), 0)
            password_rotation_enabled = coerce_bool(
                self._get_reg_value("PasswordRotationEnabled", 1),
                True
            )
            password_rotation_username = normalize_local_username(
                self._get_reg_value("PasswordRotationUsername", "")
            )
            enable_continuous_usage_limit = coerce_bool(
                self._get_reg_value("EnableContinuousUsageLimit", int(legacy_enable_limits)),
                legacy_enable_limits
            )
            enable_daily_usage_limit = coerce_bool(
                self._get_reg_value("EnableDailyUsageLimit", int(legacy_enable_limits)),
                legacy_enable_limits
            )
            self.entry_max_usage.delete(0, tk.END)
            self.entry_max_usage.insert(0, str(max_usage))
            self.entry_mandatory_rest.delete(0, tk.END)
            self.entry_mandatory_rest.insert(0, str(mandatory_rest))
            self.entry_daily_usage_limit.delete(0, tk.END)
            self.entry_daily_usage_limit.insert(0, str(daily_usage_limit))
            self.entry_password_rotation_username.delete(0, tk.END)
            self.entry_password_rotation_username.insert(0, password_rotation_username)
            self.var_enable_password_rotation.set(password_rotation_enabled)
            self.var_enable_continuous_usage_limit.set(enable_continuous_usage_limit)
            self.var_enable_daily_usage_limit.set(enable_daily_usage_limit)
        except Exception as e:
            messagebox.showerror("错误", f"读取配置失败: {e}")

    def save_config(self):
        try:
            max_usage = int(self.entry_max_usage.get())
            mandatory_rest = int(self.entry_mandatory_rest.get())
            daily_usage_limit = int(self.entry_daily_usage_limit.get())
            if max_usage < 0 or mandatory_rest < 0 or daily_usage_limit < 0:
                raise ValueError
            password_rotation_username = normalize_local_username(self.entry_password_rotation_username.get())
            password_rotation_enabled = 1 if self.var_enable_password_rotation.get() else 0
            enable_continuous_usage_limit = 1 if self.var_enable_continuous_usage_limit.get() else 0
            enable_daily_usage_limit = 1 if self.var_enable_daily_usage_limit.get() else 0

            if password_rotation_enabled:
                is_valid, normalized_username, validation_message = validate_password_rotation_username(
                    password_rotation_username
                )
                if not is_valid:
                    raise RuntimeError(validation_message)
                password_rotation_username = normalized_username

            self._set_reg_value("MaxUsage", max_usage)
            self._set_reg_value("MandatoryRest", mandatory_rest)
            self._set_reg_value("DailyUsageLimit", daily_usage_limit)
            self._set_reg_value("PasswordRotationEnabled", password_rotation_enabled)
            self._set_reg_value("PasswordRotationUsername", password_rotation_username, winreg.REG_SZ)
            self._set_reg_value("EnableContinuousUsageLimit", enable_continuous_usage_limit)
            self._set_reg_value("EnableDailyUsageLimit", enable_daily_usage_limit)
            messagebox.showinfo("成功", "配置已保存到注册表，请重启服务生效。")
        except ValueError:
            messagebox.showerror("错误", "请输入大于或等于 0 的有效数字。")
        except RuntimeError as e:
            messagebox.showerror("错误", str(e))
        except Exception as e:
            messagebox.showerror("错误", f"保存配置失败: {e}")

    def run_command(self, args, success_msg):
        cmd = get_command_prefix() + args
        try:
            result = run_hidden_process(cmd)
            output = get_subprocess_output(result)
            if result.returncode == 0:
                if output and ("Error" in result.stdout or "Error" in result.stderr):
                    messagebox.showerror("失败", f"操作失败:\n{output}")
                    return False
                message = success_msg if not output else f"{success_msg}\n{output}"
                messagebox.showinfo("成功", message)
                return True
            else:
                messagebox.showerror("失败", f"操作失败:\n{output or f'命令返回退出码 {result.returncode}。'}")
                return False
        except Exception as e:
            messagebox.showerror("错误", f"执行命令出错: {e}")
            return False
        finally:
            self.refresh_service_status()

    def install_service(self):
        if self.run_command(["--startup", "auto", "install"], "服务安装成功"):
            try:
                win32serviceutil.StartService(KidsModeService._svc_name_)
            except Exception as e:
                messagebox.showerror("错误", f"服务已安装，但启动失败: {e}")
        self.refresh_service_status()

    def restart_service(self):
        self.run_command(["restart"], "服务已重启")

    def stop_service(self):
        try:
            win32serviceutil.StopService(KidsModeService._svc_name_)
            messagebox.showinfo("成功", "服务已停止")
        except:
            self.run_command(["stop"], "服务已停止")
        finally:
            self.refresh_service_status()

    def uninstall_service(self):
        try: win32serviceutil.StopService(KidsModeService._svc_name_)
        except: pass
        self.run_command(["remove"], "服务已卸载")

    def refresh_service_status(self):
        status = None
        status_text, status_color, status_mode = "未知", "gray", "error"
        try:
            status = win32serviceutil.QueryServiceStatus(KidsModeService._svc_name_)[1]
            if status == win32service.SERVICE_RUNNING:
                status_text, status_color = "运行中", "green"
            elif status == win32service.SERVICE_STOPPED:
                status_text, status_color = "已停止", "red"
            else:
                status_text, status_color = "其他状态", "orange"
            status_mode = "installed"
        except Exception as e:
            if getattr(e, "winerror", None) == 1060:
                status_text, status_color, status_mode = "未安装", "black", "missing"
            else:
                status_text, status_color, status_mode = "查询失败", "orange", "error"
        
        self.lbl_status.config(text=f"服务状态: {status_text}", fg=status_color)
        if status_mode == "installed":
            self.btn_install.config(state=tk.DISABLED)
            self.btn_restart.config(state=tk.NORMAL)
            self.btn_uninstall.config(state=tk.NORMAL)
            self.btn_stop.config(state=tk.NORMAL if status == win32service.SERVICE_RUNNING else tk.DISABLED)
        elif status_mode == "missing":
            self.btn_install.config(state=tk.NORMAL)
            self.btn_restart.config(state=tk.DISABLED)
            self.btn_stop.config(state=tk.DISABLED)
            self.btn_uninstall.config(state=tk.DISABLED)
        else:
            self.btn_install.config(state=tk.DISABLED)
            self.btn_restart.config(state=tk.DISABLED)
            self.btn_stop.config(state=tk.DISABLED)
            self.btn_uninstall.config(state=tk.DISABLED)

# =============================================================================
# Main Entry Point
# =============================================================================
if __name__ == '__main__':
    if len(sys.argv) > 1:
        # 有参数，交给 pywin32 处理 (install, remove, start, debug, etc.)
        sys.exit(win32serviceutil.HandleCommandLine(KidsModeService))
    else:
        # 无参数，可能是 SCM 启动（服务模式），也可能是用户双击（GUI 模式）
        try:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(KidsModeService)
            # 尝试连接服务控制器。如果是 SCM 启动，这里会成功并阻塞直到服务停止。
            # 如果是用户双击，这里会抛出错误 1063 (ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
            servicemanager.StartServiceCtrlDispatcher()
        except Exception as e:
            # 捕获异常，判断是否为 1063 错误
            if "1063" in str(e):
                # 说明不是由 SCM 启动的，进入 GUI 模式
                if not is_admin():
                    executable, parameters = build_elevation_command()
                    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, parameters, None, 1)
                    if result <= 32:
                        show_error_dialog("错误", "管理员权限请求被取消或启动失败。")
                else:
                    app = KidsModeManager()
                    app.mainloop()
            else:
                report_startup_failure(f"KidsModeMgr 启动失败: {e}")
                sys.exit(1)
