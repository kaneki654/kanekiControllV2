import argparse
import hashlib
import hmac
import json
import os
import secrets
import shutil
import socket
import sys
import threading
import time
import urllib.request
from datetime import datetime
PORT = 6000
BEACON_PORT = 6001
CONFIG_PATH = os.path.expanduser("~/kaneki_config.json")
VERSION = "1.0.0"
GITHUB_REPO = "kaneki654/kanekiControllV2"
GITHUB_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
SCRIPT_PATH = os.path.abspath(__file__)
LOG_PATH = os.path.expanduser("~/kaneki_server.log")
TOKEN = None
TOKEN_LOCK = threading.Lock()
class SafeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return super().default(obj)
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
            json.dump(cfg, f, indent=2)
    except Exception as e:
        log(f"config save error: {e}")
def get_token():
    global TOKEN
    with TOKEN_LOCK:
        if TOKEN:
            return TOKEN
        cfg = load_config()
        saved = cfg.get("token")
        if saved:
            TOKEN = saved
            log(f"loaded saved token from config")
            return TOKEN
        return None
def set_token(tok):
    global TOKEN
    if not tok:
        return
    with TOKEN_LOCK:
        TOKEN = tok
    save_config("token", tok)
    log(f"token captured and saved automatically")
def log(msg):
    line = f"[{datetime.now():%H:%M:%S}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
def mac(token, nonce):
    return hmac.new(token.encode(), nonce.encode(), hashlib.sha256).hexdigest()
def safe_eq(a, b):
    return hmac.compare_digest(a.encode(), b.encode())
def local_ips():
    ips = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if not ip.startswith("127.") and ":" not in ip:
                ips.append(ip)
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return list(dict.fromkeys(ips))
clients = {}
clients_lock = threading.Lock()
cmd_id = 0
cmd_id_lock = threading.Lock()
pending = {}
pending_lock = threading.Lock()
def next_id():
    global cmd_id
    with cmd_id_lock:
        cmd_id += 1
        return cmd_id
def send_to(client, obj):
    data = (json.dumps(obj, cls=SafeEncoder) + "\n").encode()
    with client["lock"]:
        try:
            client["sock"].sendall(data)
            return True
        except OSError:
            return False
def all_devices():
    devs = []
    with clients_lock:
        for addr, c in clients.items():
            for d in c.get("devices", []):
                d["pc"] = c["name"]
                d["pc_addr"] = addr
                devs.append(d)
    return devs
def handle_pc(sock, addr):
    addr_str = f"{addr[0]}:{addr[1]}"
    client = {"sock": sock, "name": addr[0], "lock": threading.Lock(), "devices": []}
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(10)
        rf = sock.makefile("r", encoding="utf-8")
        nonce = secrets.token_hex(16)
        send_to(client, {"t": "challenge", "nonce": nonce})
        line = rf.readline()
        if not line:
            return
        auth = json.loads(line)
        if auth.get("t") != "auth":
            log(f"X bad handshake from {addr_str}")
            return
        pc_token = auth.get("token", "").strip()
        current_token = get_token()
        if current_token is None:
            if not pc_token:
                log(f"X rejected {addr_str}: no token saved and PC sent to token")
                return
            if not safe_eq(auth.get("mac", ""), mac(pc_token, nonce)):
                log(f"X rejected {addr_str}: MAC mismatch even with provided token")
                return
            set_token(pc_token)
            current_token = pc_token
            log(f"/ first connection - token auto-set from {addr[0]}")
        else:
            if not safe_eq(auth.get("mac", ""), mac(current_token, nonce)):
                log(f"X rejected {addr_str}: wrong token")
                send_to(client, {"t": "auth_fail", "reason": "wrong token"})
                return
            if pc_token and pc_token != current_token:
                log(f"⚠ {addr_str} sent difference token - keeping saved token")
        pc_name = auth.get("host", addr[0]) or addr[0]
        client["name"] = pc_name
        mine = auth.get("nonce", secrets.token_hex(16))
        send_to(client, {"t": "auth_ok", "mac": mac(current_token, mine)})
        sock.settimeout(15)
        with clients_lock:
            stale = [k for k, v in clients.items() if k.startswith(addr[0] + ":")]
            for k in stale:
                clients.pop(k)
            clients[addr_str] = client
        log(f"PC connected: {pc_name} ({addr_str})")
        print_devices()
        for line in rf:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            t = msg.get("t")
            if t == "devices":
                client["devices"] = msg.get("list", [])
                print_devices()
            elif t == "result":
                cid = msg.get("id")
                ok = msg.get("ok", False)
                out = msg.get("out", "").strip()
                serial = msg.get("serial", "?")
                cmd = msg.get("cmd", "?")
                mark = "/" if ok else "X"
                log(f"{mark} #{cid} {cmd} [{serial}] {out[:300].replace(chr(10), ' ')}")
                with pending_lock:
                    if cid in pending:
                        pending[cid]["results"].append(msg)
                        pending[cid]["event"].set()
            elif t == "ping":
                send_to(client, {"t": "pong"})
    except Exception as e:
        log(f"{client['name']}: {type(e).__name__} {e}")
    finally:
        sock.close()
        with clients_lock:
            client.pop(addr_str, None)
        log(f"PC disconnected: {client['name']}")
        print_devices()
def print_devices():
    devs = all_devices()
    with clients_lock:
        pc_count = len(clients)
    log(f"--- PCs: {pc_count} | Devices: {len(devs)} ---")
    for d in devs:
        bat = f"{d['battery']}%" if d.get("battery", -1) >=  0 else "-"
        log(f"  {d.get('serial','?')} | {d.get('model','?')} | {d.get('state', '?')} | {bat} | pc:{d.get('pc','?')}")
def send_command(cmd, arg="", targets=None, pc_level=False, wait=False, timeout=15):
    with clients_lock:
        pcs = list(clients.values())
    if not pcs:
        log("no PCs connected")
        return []
    cid = next_id()
    evt = threading.Event()
    results = []
    if wait:
        with pending_lock:
            pending[cid] = {"event": evt, "results": results}
    for pc in pcs:
        msg = {"t": "cmd", "id": cid, "cmd": cmd, "arg": arg}
        if not pc_level and targets is not None:
            mine = [d["serial"] for d in pc.get("devices", []) if d["serial"] in targets and d.get("state") == "device"]    
            if not mine:
                continue
            msg["targets"] = mine
        send_to(pc, msg)
        log(f"-> #{cid} {cmd} {arg}".rstrip())
    if wait:
        evt.wait(timeout)
        with pending_lock:
            pending.pop(cid, None)
    return results
def beacon_loop():
    payload = f"KANEKICTL2 {PORT}".encode()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while True:
            for bc in ["255.255.255.255", "192.168.43.255", "192.168.1.255", "192.168.0.255", "10.0.0.255"]:
                try:
                    s.sendto(payload, (bc, BEACON_PORT))
                except Exception:
                    pass
            with clients_lock:
                pcs = list(clients.values())
            for pc in pcs:
                send_to(pc, {"t": "ping"})
            time.sleep(2)
    except Exception as e:
        log(f"beacon error: {e}")
def accept_loop(port):
    ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ss.bind(("0.0.0.0", port))
    ss.listen(16)
    ips = local_ips()
    log(f"KanekiControl v2 Server")
    log(f"Listening on TCP {port}")
    log(f"IPs: {', '.join(ips) or 'unknown'}")
    tok = get_token()
    if tok:
        log(f"token loaded from config (saved from previous session)")
    else:
        log(f"no token yet — will capture automatically from first PC connection")
    log("Waiting for PC clients...")
    while True:
        try:
            sock, addr = ss.accept()
            threading.Thread(target=handle_pc, args=(sock, addr), daemon=True).start()
        except Exception as e:
            log(f"accept error: {e}")
HELP = """
Commands:
  devices                     list all connected devices
  pcs                         list connected PCs
  token                       show current token
  reset-token                 clear saved token (next PC sets a new one)
  version                     show server version
  update                      check for updates and apply if available
  <cmd> [arg]                 send to ALL devices
  <cmd> [arg] -s SERIAL       send to specific device

Available commands:
  Power    : reboot reboot_recovery reboot_bootloader poweroff
             screen_on screen_off unlock stayon_on stayon_off
  Input    : key_home key_back key_recents key_power key_enter
             keyevent tap swipe text
  Audio    : vol_up vol_down mute set_volume brightness timeout
             rotate_auto rotate_lock
  Network  : wifi_on wifi_off data_on data_off bt_on bt_off
             airplane_on airplane_off wireless connect
  Apps     : launch force_stop clear_data uninstall install
             open_url list_apps foreground
  Tools    : screenshot record notify vibrate push mirror info
             shell adb
  Files    : list_dir [path]            list device directory (default /sdcard)
             download <path[,path2]>    pull file(s) from device to PC
             delete <path[,path2]>      delete file(s) on device  (multi ok)
             compress <path[,path2]>    zip file(s) on device     (multi ok)
  PC       : shutdown_pc [delay_secs]   shutdown the PC
             restart_pc  [delay_secs]   restart the PC
             list_pc [path]             list PC directory

  log                         show log file path
  log clear                   clear the log file
Type 'help' to show this again, 'quit' to exit.
"""
def _version_tuple(v):
    try:
        return tuple(int(x) for x in v.lstrip("v").split("."))
    except Exception:
        return (0,)

def check_update():
    """Returns (tag, url) if a newer release exists, else (None, None)."""
    try:
        req = urllib.request.Request(GITHUB_API, headers={"User-Agent": "KanekiControl"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        tag = data.get("tag_name", "")
        if not tag or _version_tuple(tag) <= _version_tuple(VERSION):
            return None, None
        for asset in data.get("assets", []):
            if asset.get("name") == "kanekiServ.py":
                return tag, asset["browser_download_url"]
        return tag, data.get("html_url")
    except Exception:
        return None, None

def self_update():
    tag, url = check_update()
    if not tag:
        log(f"Already up to date (v{VERSION}).")
        return False
    if not url or not url.endswith(".py"):
        log(f"Update {tag} available. Download from: {url}")
        return False
    log(f"Downloading update {tag}...")
    tmp = SCRIPT_PATH + ".tmp"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "KanekiControl"})
        with urllib.request.urlopen(req, timeout=60) as r, open(tmp, "wb") as f:
            shutil.copyfileobj(r, f)
        with open(tmp, encoding="utf-8") as f:
            f.read(64)
        os.replace(tmp, SCRIPT_PATH)
        log(f"Updated to {tag}. Run 'python {SCRIPT_PATH}' to restart.")
        return True
    except Exception as e:
        log(f"Update failed: {e}")
        try:
            os.remove(tmp)
        except Exception:
            pass
        return False

def _startup_update_check():
    tag, url = check_update()
    if tag:
        log(f"[update] v{tag} available — type 'update' or run with --update ({url})")

def shell_loop():
    print(HELP)
    while True:
        try:
            line = input("kaneki> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nbye")
            os._exit(0)
        if not line:
            continue
        if line in ("quit", "exit", "q"):
            os._exit(0)
        if line in ("help", "h", "?"):
            print(HELP)
            continue
        if line == "version":
            print(f"KanekiControl v{VERSION} (server)")
            continue
        if line == "update":
            if self_update():
                print("Restart to apply the update.")
            continue
        if line == "log":
            print(f"Log file: {LOG_PATH}")
            continue
        if line == "log clear":
            try:
                open(LOG_PATH, "w").close()
                print("Log cleared.")
            except Exception as e:
                print(f"Error: {e}")
            continue
        if line == "devices":
            devs = all_devices()
            if not devs:
                print("no devices")
            for d in devs:
                bat = f"{d.get('battery')}%" if d.get("battery", -1) >= 0 else "–"
                print(f"  {d.get('serial','?')} | {d.get('model','?')} | {d.get('state','?')} | {bat} | pc:{d.get('pc','?')}")
            continue
        if line == "pcs":
            with clients_lock:
                pcs = list(clients.values())
            if not pcs:
                print("no PCs connected")
            for pc in pcs:
                print(f"  {pc['name']} | devices: {len(pc.get('devices', []))}")
            continue
        if line == "token":
            tok = get_token()
            print(f"current token: {tok or '(none yet)'}")
            continue
        if line == "reset-token":
            global TOKEN
            with TOKEN_LOCK:
                TOKEN = None
            save_config("token", None)
            log("token cleared — next PC connection will set a new one")
            continue
        parts = line.split(None, 1)
        cmd = parts[0]
        rest = parts[1] if len(parts) > 1 else ""
        targets = None
        if " -s " in rest:
            rest, _, serial = rest.rpartition(" -s ")
            targets = {serial.strip()}
        arg = rest.strip()
        pc_level = cmd in ("connect",)
        send_command(cmd, arg, targets=targets, pc_level=pc_level)
def main():
    ap = argparse.ArgumentParser(description="KanekiControl v2 Server (Termux) — token auto-captured")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--no-shell", action="store_true", help="headless mode, no interactive prompt")
    ap.add_argument("--update", action="store_true", help="check for updates and apply if available")
    args = ap.parse_args()
    if args.update:
        self_update()
        return
    threading.Thread(target=beacon_loop, daemon=True).start()
    threading.Thread(target=accept_loop, args=(args.port,), daemon=True).start()
    time.sleep(0.5)
    log(f"KanekiControl v{VERSION} (server)")
    log(f"Log file: {LOG_PATH}")
    threading.Thread(target=_startup_update_check, daemon=True).start()
    if args.no_shell:
        log("running headless — Ctrl+C to stop")
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            log("bye")
    else:
        shell_loop()
if __name__ == "__main__":
    main()