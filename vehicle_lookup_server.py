#!/usr/bin/env python3
import base64
import json
import mimetypes
import os
import re
import socket
import threading
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

NAPIX_BASE_URL = "https://delhigw.napix.gov.in/nic/parivahan/"
NAPIX_API_BASE_URL = "https://delhigw.napix.gov.in/nic/parivahan/mparivahan/wrapperapi/"
CLIENT_ID = "b91c303443f61b37106750823881cd2f"
CLIENT_SECRET = "de83eeeb148878ae375f28756492e8a0"
TIMEOUT = 12.0
_TOKEN = None
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()

VEHICLE_VALIDITY_KEYS = [
    ("regNo", "Registration No"),
    ("stateCd", "State Code"),
    ("stateName", "State"),
    ("officeName", "RTO Office"),
    ("offCd", "Office Code"),
    ("regnUpto", "Registration Upto"),
    ("fitUpto", "Fitness Upto"),
    ("taxUpto", "Tax Upto"),
    ("insUpto", "Insurance Upto"),
    ("puccUpto", "PUCC Upto"),
    ("permitUpto", "Permit Upto"),
]

try:
    import requests
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError as exc:
    raise SystemExit(f"Missing packages: {exc}")


def aes_transform(encrypt: bool, value: str, key: str) -> str:
    key_bytes = key.encode("utf-8")
    if encrypt:
        encrypted = AES.new(key_bytes, AES.MODE_ECB).encrypt(pad(value.encode("utf-8"), 16))
        return base64.b64encode(encrypted).decode("ascii")
    decrypted = AES.new(key_bytes, AES.MODE_ECB).decrypt(base64.b64decode(value))
    return unpad(decrypted, 16).decode("utf-8")


def request_key(timestamp: str) -> str:
    return timestamp[-4:][::-1] + timestamp[:4][::-1] + "!~)#@*&^"


def napix_reachable(timeout: float = 3.0) -> bool:
    host = urlparse(NAPIX_BASE_URL).hostname or "delhigw.napix.gov.in"
    try:
        with socket.create_connection((host, 443), timeout=timeout):
            return True
    except OSError:
        return False


def get_token(force_refresh: bool = False) -> str:
    global _TOKEN
    now = int(time.time())
    if not force_refresh and _TOKEN and int(_TOKEN.get("expires_at", 0)) > now + 30:
        return str(_TOKEN["access_token"])
    if not napix_reachable():
        raise RuntimeError("NAPIX gateway not reachable. Indian IP / good internet required.")
    r = requests.post(
        NAPIX_BASE_URL + "oauth2/token",
        data={
            "grant_type": "client_credentials",
            "scope": "napix",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        headers={
            "User-Agent": "okhttp/4.9.2",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    data = r.json()
    access = data.get("access_token")
    if not access:
        raise RuntimeError("Token endpoint did not return access_token")
    _TOKEN = {
        "access_token": access,
        "expires_at": now + int(data.get("expires_in", 300)),
    }
    return str(access)


def encrypted_post(url: str, body: dict, token: str, timeout: float | None = None):
    timestamp = str(int(time.time() * 1000))
    key = request_key(timestamp)
    plain = json.dumps(body if body is not None else {}, separators=(",", ":"))
    encrypted_data = aes_transform(True, plain, key)
    envelope = {"data": base64.b64encode(encrypted_data.encode("ascii")).decode("ascii")}
    headers = {
        "User-Agent": "okhttp/4.9.2",
        "Accept": "application/json",
        "timestamp": timestamp,
        "Authorization": f"Bearer {token}",
        "Param2": "2.0.142",
        "Param1": "abcd",
        "Content-Type": "application/json; charset=utf-8",
    }
    response = requests.post(url, json=envelope, headers=headers, timeout=timeout or TIMEOUT)
    raw = response.text
    try:
        outer = response.json()
        encoded = outer.get("data")
        if encoded:
            encrypted_text = base64.b64decode(encoded).decode("utf-8")
            raw = aes_transform(False, encrypted_text, key)
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError:
                pass
        else:
            raw = outer
    except Exception:
        pass
    return response.status_code, raw


def vehicle_by_mobile(mobile_no: str) -> dict:
    mobile_no = str(mobile_no or "").strip()
    if not re.fullmatch(r"\d{10}", mobile_no):
        raise ValueError("Mobile number must be exactly 10 digits")

    token = get_token()
    url = NAPIX_API_BASE_URL.rstrip("/") + "/vahan/vahancapi/common/getvehiclevalidity"

    last = None
    for _ in range(2):
        try:
            status, result = encrypted_post(url, {"mobileNo": mobile_no}, token, timeout=10.0)
        except requests.RequestException as exc:
            status, result = None, {"error": str(exc)}
        if status and status < 500 and result not in (None, ""):
            last = result
            break
        last = result
        time.sleep(1.0)

    if last is None:
        raise RuntimeError("Vahan did not respond. Try again.")

    api_message = last.get("apiMessage") or {} if isinstance(last, dict) else {}
    vehicles_raw = last.get("data") if isinstance(last, dict) else None
    vehicles = []
    if isinstance(vehicles_raw, list):
        vehicles = [v for v in vehicles_raw if isinstance(v, dict)]
    elif isinstance(vehicles_raw, dict):
        vehicles = [vehicles_raw]

    if not vehicles:
        msg = (
            (last.get("error") if isinstance(last, dict) else None)
            or api_message.get("developerMessage")
            or api_message.get("message")
            or "No vehicle registered against this mobile number."
        )
        return {"mobileNo": mobile_no, "found": False, "vehicles": [], "message": str(msg)}

    formatted = []
    for v in vehicles:
        entry = {label: v.get(key) for key, label in VEHICLE_VALIDITY_KEYS}
        entry["_raw"] = v
        formatted.append(entry)

    return {"mobileNo": mobile_no, "found": True, "count": len(formatted), "vehicles": formatted}


def telegram_call(method: str, payload: dict | None = None) -> dict:
    response = requests.post(
        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/{method}",
        json=payload or {},
        timeout=35,
    )
    response.raise_for_status()
    result = response.json()
    if not result.get("ok"):
        raise RuntimeError(result.get("description", "Telegram API request failed"))
    return result


def telegram_text(result: dict) -> str:
    if not result.get("found"):
        return f"No vehicle found for {result['mobileNo']}.\n{result.get('message', '')}"

    lines = [f"Vehicle lookup: {result['mobileNo']}", f"Found: {result['count']} vehicle(s)"]
    for index, vehicle in enumerate(result["vehicles"], start=1):
        lines.append(f"\nVehicle {index}")
        for label, value in vehicle.items():
            if label.startswith("_") or value in (None, ""):
                continue
            lines.append(f"{label}: {value}")
    return "\n".join(lines)


def telegram_poll() -> None:
    offset = None
    while True:
        try:
            payload = {"timeout": 25}
            if offset is not None:
                payload["offset"] = offset
            updates = telegram_call("getUpdates", payload).get("result", [])
            for update in updates:
                offset = update["update_id"] + 1
                message = update.get("message", {})
                chat = message.get("chat", {})
                text = (message.get("text") or "").strip()
                if not chat.get("id"):
                    continue
                if text in ("/start", "/help"):
                    reply = "Send a 10-digit mobile number to find linked vehicle records."
                elif not re.fullmatch(r"\d{10}", text):
                    reply = "Please send exactly 10 digits."
                else:
                    try:
                        reply = telegram_text(vehicle_by_mobile(text))
                    except Exception as exc:
                        reply = f"Lookup failed: {exc}"
                telegram_call("sendMessage", {"chat_id": chat["id"], "text": reply})
        except Exception as exc:
            print(f"Telegram polling error: {exc}")
            time.sleep(5)


class LookupHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/vehicle_lookup.html"):
            file_path = os.path.join(os.path.dirname(__file__), "vehicle_lookup.html")
            if os.path.exists(file_path):
                with open(file_path, "rb") as f:
                    body = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_error(404)
            return

        if parsed.path == "/lookup":
            try:
                params = parse_qs(parsed.query)
                mobile = (params.get("mobile", [""])[0] or "").replace(" ", "")
                if len(mobile) != 10 or not mobile.isdigit():
                    raise ValueError("Mobile number must be exactly 10 digits")
                result = vehicle_by_mobile(mobile)
                payload = json.dumps(result).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(payload)
                return
            except (BrokenPipeError, ConnectionAbortedError):
                return
            except Exception as exc:
                payload = json.dumps({"error": str(exc)}).encode("utf-8")
                self.send_response(400)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(payload)
                return

        self.send_error(404)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def log_message(self, format, *args):
        return


def main():
    port = int(os.getenv("PORT", "8002"))
    server = ThreadingHTTPServer(("0.0.0.0", port), LookupHandler)
    print(f"Serving on http://localhost:{port}")
    if TELEGRAM_BOT_TOKEN:
        threading.Thread(target=telegram_poll, daemon=True, name="telegram-bot").start()
        print("Telegram bot polling enabled")
    else:
        print("Telegram bot disabled: set TELEGRAM_BOT_TOKEN to enable it")
    server.serve_forever()


if __name__ == "__main__":
    main()
