import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time
import zipfile
import tempfile
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
PORT, BEACON_PORT = 6000, 6001
SERVICE_NAME = "KanekiControlV2"
SCRIPT_PATH = os.path.abspath(__file__)
OUT = os.path.join(os.path.expanduser("~"), "KanekiControl")
LOG_PATH = os.path.join(OUT, "client.log")
CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".kaneki_client.json")
HOTSPOT_DEFAULT = "192.168.42.1"
def _find_adb():
    found = shutil.which("adb")
    if found:
        return found
    for p in [
        r"C:\platform-tools\adb.exe",
        r"C:\Android\platform-tools\adb.exe",
        os.path.expanduser(r"~/AppData\Local\Android\Sdk\platform-tools\adb.exe"),
        os.path.expanduser(r"~\platform-tools\adb.exe"),
    ]:
        if os.path.exists(p):
            return p
    return "adb"
ADB = _find_adb()
SCRCPY = shutil.which("scrcpy")
STATES = {"device", "offline", "unauthorized", "recovery", "sideload",
          "bootloader", "authorizing", "rescue", "no"}
ERR = re.compile(r"(?i)(error|exception|not allowed|unknown command|permission denial|aborted|failure|failed)")
jobs = ThreadPoolExecutor(max_workers=24)
_batt = {}
def log(msg):
    line = f"[{datetime.now():%H:%M:%S}] {msg}"
    print(line, flush=True)
    try:
        os.makedirs(OUT, exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
def stamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")
def safe(s):
    return re.sub(r"[^\w.-]", "_", s)
def adb(serial, *args, timeout=30, binary=False):
    global ADB
    cmd = [ADB] + (["-s", serial] if serial else []) + [str(a) for a in args]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, creationflags=subprocess.CREATE_NO_WINDOW)
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except FileNotFoundError:
        try:
            key = "windows" if sys.platform.startswith("win") else "darwin" if sys.platform == "darwin" else "linux"
            base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~")) if os.name == "nt" else os.path.join(os.path.expanduser("~"), ".local", "share")
            dest = os.path.join(base, "platform-tools")
            exe = os.path.join(dest, "adb.exe" if os.name == "nt" else "adb")
            if not os.path.isfile(exe):
                url = f"https://dl.google.com./android/repository/platform-tools-latest-{key}.zip"
                tmp = os.path.join(tempfile.gettempdir(), "pt.zip")
                req = urllib.request.Request(url, headers={"User-Agent": "KanekiControl"})
                with urllib.request.urlopen(req, timeout=120) as r, open(tmp, "wb") as f:
                    shutil.copyfileobj(r, f)
                with zipfile.ZipFile(tmp) as z:
                    z.extractall(os.path.dirname(dest))
                os.remove(tmp)
                if os.name != "nt":
                    os.chmod(exe, 0o755)
            os.environ["PATH"] = dest + os.pathsep + os.environ.get("PATH", "")
            ADB = exe
            cmd[0] = ADB
            p = subprocess.run(
                cmd, capture_output=True, timeout=timeout, creationflags=subprocess.CREATE_NO_WINDOW
            )
        except Exception as e:
            return False
    if binary:
        return p.returncode == 0, p.stdout
    return p.returncode == 0, (p.stdout + p.stderr).decode("utf-8", "replace").strip()
def sh(serial, command, timeout=30):
    ok, out = adb(serial, "shell", command, timeout=timeout)
    return ok and not ERR.search(out), out
def battery(serial):
    lvl, ts = _batt.get(serial, (-1, 0))
    if time.time() - ts > 30:
        _batt[serial] = (lvl, time.time())
        jobs.submit(_read_battery, serial)
    return lvl
def _read_battery(serial):
    _, out = adb(serial, "shell", "dumpsys battery", timeout=10)
    m = re.search(r"level:\s*(\d+)", out)
    if m:
        _batt[serial] = (int(m.group(1)), time.time())
def list_devices(exclude=()):
    _, out = adb(None, "devices", "-l", timeout=10)
    devs = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[1] not in STATES or parts[0] in exclude:
            continue
        model = next((p[6:] for p in parts if p.startswith("model:")), "?").replace("_", " ")
        state = "no-permission" if parts[1] == "no" else parts[1]
        devs.append({"serial": parts[0], "state": state, "model": model, "battery": battery(parts[0]) if state == "device" else -1})
    return devs
def num(a, lo, hi, default=None, name="value"):
    if not a and default is not None:
        return default
    try:
        v = int(a)
    except ValueError:
        raise ValueError(f"{name} must be a number")
    if not lo <= v <= hi:
        raise ValueError(f"{name} must be {lo}-{hi}")
    return v
def ints(a, lo, hi, name):
    try:
        v = [int(x) for x in a.replace(",", " ").split()]
    except ValueError:
        raise ValueError(f"{name}: number only")
    if not lo <= len(v) <= hi:
        raise ValueError(f"{name}: needs {lo}-{hi} numbers")
    return v
def pkg(a):
    if not re.fullmatch(r"[\w.]+(/[\w.$]+)?", a):
        raise ValueError(f"bad package: {a}")
    return a
def pc_path(a):
    p = os.path.expanduser(a.strip().strip('"'))
    if not os.path.exists(p):
        raise ValueError(f"not found on PC: {p}")
    return p
def S(cmd):
    return lambda s, a: sh(s, cmd)
def KEY(code):
    return S(f"input keyevent {code}")
def c_keyevent(s, a):
    return sh(s, "input keyevent " + " ".join(shlex.quote(k) for k in a.split()))
def c_tap(s, a):
    x, y = ints(a, 2, 2, "tap")
    return sh(s, f"input tap {x} {y}")
def c_swipe(s, a):
    return sh(s, "input swipe " + " ".join(map(str, ints(a, 4, 5, "swipe"))))
def c_text(s, a):
    return sh(s, "input text " + shlex.quote(a.replace(" ", "%s")))
def c_volume(s, a):
    v = num(a, 0, 30, name="volume")
    return sh(s, f"cmd media_session volume --stream 3 --set {v}")
def c_brightness(s, a):
    v = num(a, 0, 255, name="brightness")
    return sh(s, f"settings put system screen_brightness_mode 0; settings put system screen_brightness {v}")
def c_timeout(s, a):
    v = num(a, 5, 86400, name="seconds")
    return sh(s, f"settings put system screen_off_timeout {v * 1000}")
def c_wireless(s, a):
    _, out = sh(s, "ip -f inet addr show wlan0")
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
    if not m:
        return False, "no wlan0 IP - turn WiFi on first"
    ok, out = adb(s, "tcpip", "5555")
    if not ok:
        return False, out
    time.sleep(2)
    ok, out = adb(None, "connect", f"{m.group(1)}:5555", timeout=15)
    return ok and "connected" in out, out
def c_connect(_, a):
    target = a if ":" in a else f"{a}:5555"
    ok, out = adb(None, "connect", target, timeout=15)
    return ok and "connected" in out, out
def c_launch(s, a):
    p = pkg(a)
    if "/" in p:
        return sh(s, f"am start -n {shlex.quote(p)}")
    return sh(s, f"monkey -p {p} -c android.intent.category.LAUNCHER 1")
def c_url(s, a):
    has_scheme = re.match(r"^[a-zA-Z][\w+.-]*://", a) or a.startswith(
        ("market:", "tel:", "mailto:", "intent:", "geo:", "sms:"))
    url = a if has_scheme else "https://" + a
    return sh(s, f"am start -a android.intent.action.VIEW -d {shlex.quote(url)}")
def c_apps(s, a):
    ok, out = adb(s, "shell", "pm list packages -3")
    return ok, " ".join(sorted(l[8:] for l in out.splitlines() if l.startswith("package:")))
def c_install(s, a):
    return adb(s, "install", "-r", "-g", pc_path(a), timeout=600)
def c_push(s, a):
    try:
        src, dst = pc_path(a), "/sdcard/Download/"
    except ValueError:
        head, _, dst = a.strip().rpartition(" ")
        if not head:
            raise
        src = pc_path(head)
    return adb(s, "push", src, dst, timeout=600)
def c_screenshot(s, a):
    ok, data = adb(s, "exec-out", "screencap", "-p", binary=True)
    if not ok or not data.startswith(b"\x89PNG"):
        return False, "screencap failed"
    path = os.path.join(OUT, "screens", f"{safe(s)}_{stamp()}.png")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return True, path
def c_record(s, a):
    secs = num(a, 1, 180, default=10, name="seconds")
    remote = f"/sdcard/kc_rec_{stamp()}.mp4"
    sh(s, f"screenrecord --time-limit {secs} {remote}", timeout=secs + 30)
    path = os.path.join(OUT, "records", f"{safe(s)}_{stamp()}.mp4")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    ok, out = adb(s, "pull", remote, path, timeout=180)
    sh(s, f"rm -f {remote}")
    return ok, (path if ok else out)
def c_notify(s, a):
    t = shlex.quote(a)
    return sh(s, f"cmd notification post -S bigtext -t KanekiControl kc {t}")
def c_vibrate(s, a):
    ms = num(a, 10, 10000, default=500, name="ms")
    return sh(s, f"cmd vibrator_manager synced oneshot {ms}")
def c_mirror(s, a):
    if not SCRCPY:
        return False, "scrcpy not installed on this PC"
    subprocess.Popen(
        [SCRCPY, "-s", s, "-m", "800", "--max-fps", "30", "--window-title", s],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=subprocess.DETACHED_PROCESS
    )
    return True, "scrcpy opened"
def c_info(s, a):
    _, out = adb(s, "shell",
                 "getprop ro.product.manufacturer; getprop ro.product.model; "
                 "getprop ro.build.version.release; getprop ro.build.version.sdk; "
                 "ip -f inet addr show wlan0")
    p = out.splitlines() + ["?"] * 4
    ip = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
    bat = _batt.get(s, (-1, 0))[0]
    return True, f"{p[0]} {p[1]} | Android {p[2]} (SDK {p[3]}) | batt {bat}% | wlan0 {ip.group(1) if ip else '-'}"
CMDS = {
    "reboot":           lambda s, a: adb(s, "reboot"),
    "reboot_recovery":  lambda s, a: adb(s, "reboot", "recovery"),
    "reboot_bootloader":lambda s, a: adb(s, "reboot", "bootloader"),
    "poweroff":         S("svc power shutdown"),
    "screen_on":        KEY(224),
    "screen_off":       KEY(223),
    "unlock":           S("input keyevent 224; sleep 0.5; wm dismiss-keyguard"),
    "stayon_on":        S("svc power stayon true"),
    "stayon_off":       S("svc power stayon false"),
    "key_home":         KEY(3),
    "key_back":         KEY(4),
    "key_recents":      KEY(187),
    "key_power":        KEY(26),
    "key_enter":        KEY(66),
    "keyevent":         c_keyevent,
    "tap":              c_tap,
    "swipe":            c_swipe,
    "text":             c_text,
    "vol_up":           KEY(24),
    "vol_down":         KEY(25),
    "mute":             KEY(164),
    "set_volume":       c_volume,
    "brightness":       c_brightness,
    "timeout":          c_timeout,
    "rotate_auto":      S("settings put system accelerometer_rotation 1"),
    "rotate_lock":      S("settings put system accelerometer_rotation 0; settings put system user_rotation 0"),
    "wifi_on":          S("cmd wifi set-wifi-enabled enabled"),
    "wifi_off":         S("cmd wifi set-wifi-enabled disabled"),
    "data_on":          S("svc data enable"),
    "data_off":         S("svc data disable"),
    "bt_on":            S("cmd bluetooth_manager enable"),
    "bt_off":           S("cmd bluetooth_manager disable"),
    "airplane_on":      S("cmd connectivity airplane-mode enable"),
    "airplane_off":     S("cmd connectivity airplane-mode disable"),
    "wireless":         c_wireless,
    "launch":           c_launch,
    "force_stop":       lambda s, a: sh(s, f"am force-stop {pkg(a).split('/')[0]}"),
    "clear_data":       lambda s, a: sh(s, f"pm clear {pkg(a).split('/')[0]}"),
    "uninstall":        lambda s, a: adb(s, "uninstall", pkg(a).split("/")[0]),
    "install":          c_install,
    "open_url":         c_url,
    "list_apps":        c_apps,
    "foreground":       S("dumpsys window | grep -E mCurrentFocus"),
    "screenshot":       c_screenshot,
    "record":           c_record,
    "notify":           c_notify,
    "vibrate":          c_vibrate,
    "push":             c_push,
    "mirror":           c_mirror,
    "info":             c_info,
    "shell":            lambda s, a: adb(s, "shell", a, timeout=60),
    "adb":              lambda s, a: adb(s, *shlex.split(a, posix=False), timeout=300),
}
PC_CMDS = {"connect": c_connect}
def run_safe(fn, serial, arg):
    try:
        return fn(serial, arg)
    except ValueError as e:
        return False, str(e)
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
def handle_cmd(msg, send, exclude):
    cid, cmd, arg = msg.get("id"), msg.get("cmd", ""), (msg.get("arg") or "").strip()

    def reply(serial, ok, out):
        out = out if isinstance(out, str) else str(out)
        log(f"{'OK ' if ok else 'ERR'} #{cid} {cmd} [{serial}] {out[:200].replace(chr(10), ' ')}")
        try:
            send({"t": "result", "id": cid, "cmd": cmd, "serial": serial,
                  "ok": bool(ok), "out": out[:4000]})
        except OSError:
            pass

    if cmd in PC_CMDS:
        return reply("PC", *run_safe(PC_CMDS[cmd], None, arg))
    fn = CMDS.get(cmd)
    if not fn:
        return reply("PC", False, f"unknown command: {cmd}")
    targets = msg.get("targets")
    if targets is None:
        targets = [d["serial"] for d in list_devices(exclude) if d["state"] == "device"]
    if not targets:
        return reply("PC", False, "no ready devices")
    futs = {jobs.submit(run_safe, fn, s, arg): s for s in targets}
    for f in as_completed(futs):
        reply(futs[f], *f.result())
def load_config():
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except Exception:
        return {}
def save_config(key, value):
    cfg = load_config()
    cfg[key] = value
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(cfg, f)
    except Exception:
        pass
def try_connect(host, port, timeout=3):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False
def discover_host(port, args_host=None):
    if args_host:
        return args_host, port

    candidates = []
    cfg = load_config()
    last = cfg.get("last_host")
    if last:
        candidates.append((f"last known ({last})", last))
    if HOTSPOT_DEFAULT not in [c[1] for c in candidates]:
        candidates.append(("Android hotspot default", HOTSPOT_DEFAULT))

    for label, host in candidates:
        log(f"trying {label}...")
        if try_connect(host, port):
            log(f"reachable: {host}:{port}")
            return host, port
    log(f"no cached host reachable — waiting for UDP beacon on port {BEACON_PORT}...")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
        u.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        u.bind(("", BEACON_PORT))
        u.settimeout(1.0)
        while True:
            try:
                data, (ip, _) = u.recvfrom(256)
            except socket.timeout:
                continue
            if data.startswith(b"KANEKICTL2"):
                parts = data.split()
                p = int(parts[1]) if len(parts) > 1 else port
                log(f"beacon from {ip}:{p}")
                return ip, p
def mac(token, nonce):
    return hmac.new(token.encode(), nonce.encode(), hashlib.sha256).hexdigest()
def session(host, port, args, exclude):
    s = socket.create_connection((host, port), timeout=10)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    rf = s.makefile("r", encoding="utf-8")
    lock = threading.Lock()
    def send(obj):
        data = (json.dumps(obj) + "\n").encode()
        with lock:
            s.sendall(data)
    ch = json.loads(rf.readline() or "{}")
    if ch.get("t") != "challenge":
        raise RuntimeError("not a KanekiControl v2 server")
    mine = secrets.token_hex(16)
    send({"t": "auth", "mac": mac(args.token, ch["nonce"]), "nonce": mine, "host": args.name, "token": args.token})
    ok = json.loads(rf.readline() or "{}")
    if ok.get("t") != "auth_ok" or not hmac.compare_digest(str(ok.get("mac", "")), mac(args.token, mine)):
        raise RuntimeError("auth failed — token mismatch")
    s.settimeout(20)
    log(f"connected to {host}:{port} as '{args.name}'")
    save_config("last_host", host)
    save_config("token", args.token)
    stop = threading.Event()
    def save_token(token):
        if token and token != "kaneki":
            save_config("token", token)
    def pusher():
        while not stop.is_set():
            try:
                send({"t": "devices", "list": list_devices(exclude)})
            except OSError:
                break
            stop.wait(3)
    threading.Thread(target=pusher, daemon=True).start()
    try:
        for line in rf:
            msg = json.loads(line)
            if msg.get("t") == "cmd":
                log(f"cmd #{msg.get('id')} {msg.get('cmd')} {msg.get('arg') or ''}".rstrip())
                threading.Thread(target=handle_cmd, args=(msg, send, exclude), daemon=True).start()
    finally:
        stop.set()
        s.close()
    raise ConnectionError("phone closed the connection")
def install_autostart(args):
    os.makedirs(OUT, exist_ok=True)
    pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    if not os.path.exists(pythonw):
        pythonw = sys.executable   # fallback, will show a console briefly
    extra = ""
    if args.token != "kaneki":
        extra += f" --token {args.token}"
    if args.host:
        extra += f" --host {args.host}"
    vbs_path = os.path.join(os.path.dirname(SCRIPT_PATH), "kaneki_client_launch.vbs")
    vbs = (
        'Set ws = CreateObject("WScript.Shell")\n'
        f'ws.Run Chr(34) & "{pythonw}" & Chr(34) & " {SCRIPT_PATH}{extra} >> {LOG_PATH} 2>&1", 0, False\n'
    )
    with open(vbs_path, "w") as f:
        f.write(vbs)
    xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>KanekiControl v2 PC Hub - hidden background client</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT10S</Delay>
    </BootTrigger>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>9999</Count>
    </RestartOnFailure>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
  </Settings>
  <Principals>
    <Principal>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Actions>
    <Exec>
      <Command>wscript.exe</Command>
      <Arguments>//B "{vbs_path}"</Arguments>
    </Exec>
  </Actions>
</Task>"""
    xml_path = os.path.join(os.environ.get("TEMP", "."), "kaneki_task.xml")
    with open(xml_path, "w", encoding="utf-16") as f:
        f.write(xml)
    ret = subprocess.run(
        ["schtasks", "/Create", "/TN", SERVICE_NAME, "/XML", xml_path, "/F"],
        capture_output=True, text=True
    )
    try:
        os.remove(xml_path)
    except Exception:
        pass
    if ret.returncode == 0:
        print(f"[OK] Task '{SERVICE_NAME}' created.")
        print(f"     Hidden launcher : {vbs_path}")
        print(f"     Log file        : {LOG_PATH}")
        print(f"     Starts on boot + logon, restarts on crash.")
        print(f"\n     To start NOW run:")
        print(f'     wscript.exe //B "{vbs_path}"')
    else:
        print(f"[FAIL] schtasks: {ret.stderr.strip()}")
        print("       Re-run this as Administrator:")
        print('       Right-click CMD → "Run as administrator" → python kaneki_client.py --install')
def uninstall_autostart():
    ret = subprocess.run(
        ["schtasks", "/Delete", "/TN", SERVICE_NAME, "/F"],
        capture_output=True, text=True
    )
    if ret.returncode == 0:
        print(f"[OK] Task '{SERVICE_NAME}' removed.")
    else:
        print(f"[FAIL] {ret.stderr.strip()}")

    vbs = os.path.join(os.path.dirname(SCRIPT_PATH), "kaneki_client_launch.vbs")
    if os.path.exists(vbs):
        os.remove(vbs)
        print(f"[OK] Removed {vbs}")
def _ensure_autostart():
    check = subprocess.run(["schtasks", "/Query", "/TN", SERVICE_NAME], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    task_missing = check.returncode != 0
    vbs_path = os.path.join(os.path.dirname(SCRIPT_PATH), "kaneki_client_launch.vbs")
    vbs_missing = not os.path.exists(vbs_path)
    if not task_missing and not vbs_missing:
        return
    pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    if not os.path.exists(pythonw):
        pythonw = sys.executable
    cfg = load_config()
    extra = ""
    saved_token = cfg.get("token", "kaneki")
    saved_host = cfg.get("last_host", "")
    if saved_token and saved_token != "kaneki":
        extra += f" --token {saved_token}"
    if saved_host:
        extra += f" --host {saved_host}"
    try:
        os.makedirs(OUT, exist_ok=True)
        vbs = (
            'Set ws = CreateObject("WScript.Shell")\n'
            f'ws.Run Chr(34) & "{pythonw}" & Chr(34) & " {SCRIPT_PATH}{extra} >> {LOG_PATH} 2>81", 0, False\n' 
        )
        with open(vbs_path, "w") as f:
            f.write(vbs)
    except Exception as e:
        log(f"[self-heal] could not write VBS: {e}")
        return
    if task_missing:
        subprocess.run(
            [
                "schtasks", "/Create",
                "/TN", SERVICE_NAME,
                "/TR", f'wscript.exe //B "{vbs_path}"',
                "/SC", "ONLOGON",
                "/IT",   
                "/F",    
                "/RL", "LIMITED",
            ],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        subprocess.run(
            [
                "schtasks", "/Create",
                "/TN", SERVICE_NAME + "_Boot",
                "/TR", f'wscript.exe //B "{vbs_path}"',
                "/SC", "ONSTART",
                "/DELAY", "0:10",
                "/RU", "SYSTEM",
                "/F",
            ],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
    log("[self-heal] autostart re-registered silenty")
def main():
    ap = argparse.ArgumentParser(description="KanekiControl v2 PC client (Windows)")
    ap.add_argument("--host",      help="phone IP — skips auto-discovery")
    ap.add_argument("--port",      type=int, default=PORT)
    ap.add_argument("--token",     default=os.environ.get("KC_TOKEN", "kaneki"))
    ap.add_argument("--usb",       metavar="SERIAL",
                    help="controller phone plugged into this PC via USB — tunnels over adb")
    ap.add_argument("--name",      default=socket.gethostname())
    ap.add_argument("--install",   action="store_true",
                    help="install hidden autostart task (run as Administrator)")
    ap.add_argument("--uninstall", action="store_true", help="remove autostart task")
    args = ap.parse_args()
    if args.install:
        install_autostart(args)
        return
    if args.uninstall:
        uninstall_autostart()
        return
    _ensure_autostart()
    exclude = {args.usb} if args.usb else set()
    ok, out = adb(None, "start-server", timeout=30)
    if not ok and "not found" in out:
        log(out)
        return
    log(f"adb: {ADB}")
    log(f"scrcpy: {SCRCPY or 'not found — Mirror button will not work'}")
    log(f"output folder: {OUT}")
    while True:
        try:
            if args.usb:
                ok, out = adb(args.usb, "forward", f"tcp:{args.port}", f"tcp:{args.port}")
                if not ok:
                    raise RuntimeError(f"adb forward failed: {out}")
                host, port = "127.0.0.1", args.port
            else:
                host, port = discover_host(args.port, args.host)

            session(host, port, args, exclude)

        except KeyboardInterrupt:
            log("bye")
            return
        except Exception as e:
            log(f"{type(e).__name__}: {e} — retrying in 3s")
        try:
            time.sleep(3)
        except KeyboardInterrupt:
            return
if __name__ == "__main__":
    main()