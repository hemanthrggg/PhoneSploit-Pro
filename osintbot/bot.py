#!/usr/bin/env python3
"""OSINT Telegram bot — stdlib only.

Runs as a long-polling process and exposes a health endpoint on 0.0.0.0:$PORT
so Freebuff's managed preview can verify readiness.

Required environment variable:
  TELEGRAM_BOT_TOKEN   (get one from @BotFather; set it in Settings → Environment)
Optional:
  PORT                 (defaults to 8080; Freebuff injects the real port)
"""

from __future__ import annotations

import html
import json
import logging
import os
import signal
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import osint  # noqa: E402  (local module)

TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
PORT = int(os.environ.get("PORT", "8080"))
POLL_TIMEOUT = 50
COOLDOWN_SECONDS = 2.0
MAX_REPLY = 4000

STARTED_AT = time.time()
_UPDATES = {"processed": 0}
_LAST_USE: dict[int, float] = {}
_STATE = {"running": True, "telegram": "disabled"}

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("osintbot")


# ---------------------------------------------------------------------------
# Telegram API (thin stdlib client)
# ---------------------------------------------------------------------------

def tg(method: str, **params):
    url = f"https://api.telegram.org/bot{TOKEN}/{method}"
    req = urllib.request.Request(
        url,
        data=json.dumps(params).encode(),
        headers={"Content-Type": "application/json", "User-Agent": osint.UA},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=POLL_TIMEOUT + 15) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read(500).decode("utf-8", "replace").strip()
        except Exception:
            pass
        raise osint.OSINTError(f"telegram API HTTP {e.code}: {detail or 'no body'}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise osint.OSINTError(f"telegram unreachable ({e})") from e
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as e:
        raise osint.OSINTError("telegram returned invalid JSON") from e
    if not payload.get("ok"):
        raise osint.OSINTError(
            f"telegram API error {payload.get('error_code')}: {payload.get('description')}"
        )
    return payload.get("result") or []


def esc(text) -> str:
    return html.escape(str(text), quote=False)


def reply(chat_id: int, text: str) -> None:
    tg(
        "sendMessage",
        chat_id=chat_id,
        text=text[:MAX_REPLY],
        parse_mode="HTML",
        disable_web_page_preview=True,
    )


def reply_long(chat_id: int, text: str) -> None:
    """Send text as one or more messages, splitting on line/word boundaries."""
    limit = 3900
    if len(text) <= limit:
        reply(chat_id, text)
        return
    parts: list[str] = []
    cur = ""
    for line in text.split("\n"):
        if cur and len(cur) + len(line) + 1 > limit:
            parts.append(cur)
            cur = ""
        while len(line) > limit:
            cut = line.rfind(" ", 0, limit)
            cut = cut if cut > 0 else limit
            parts.append(line[:cut])
            line = line[cut:].lstrip()
        cur = cur + ("\n" if cur else "") + line
    if cur:
        parts.append(cur)
    total = len(parts)
    for i, part in enumerate(parts, 1):
        if total > 1:
            part += f"\n\n({i}/{total})"
        reply(chat_id, part)


# ---------------------------------------------------------------------------
# Report formatting (HTML)
# ---------------------------------------------------------------------------

def _row(label: str, value) -> str:
    if value is None or value == "" or value == []:
        return ""
    return f"<b>{esc(label)}:</b> {esc(value)}\n"


def fmt_ip(d: dict) -> str:
    lines = [f"<b>IP {esc(d['ip'])}</b> ({esc(d.get('scope'))})"]
    lines.append(_row("Reverse DNS", d.get("rdns")).rstrip())
    g = d.get("geo")
    if g:
        lines.append(_row("Location", ", ".join(x for x in (g.get("city"), g.get("region"), g.get("country")) if x)).rstrip())
        if g.get("lat") is not None:
            lines.append(_row("Coordinates", f"{g.get('lat')}, {g.get('lon')}").rstrip())
        lines.append(_row("Timezone", g.get("tz")).rstrip())
        lines.append(_row("ASN", g.get("asn")).rstrip())
        lines.append(_row("ISP", g.get("isp")).rstrip())
        lines.append(_row("Org", g.get("org")).rstrip())
        lines.append(f"<i>source: {esc(g.get('source'))}</i>")
    else:
        lines.append(esc(d.get("geo_note") or "no geolocation data"))
    return "\n".join(x for x in lines if x)


def fmt_dns(d: dict) -> str:
    head = f"<b>DNS {esc(d['domain'])}</b> — {esc(d['status'])}"
    recs = d.get("records") or {}
    if not recs:
        return head + "\nNo records found."
    parts = [head]
    for rtype, values in recs.items():
        parts.append(f"\n<b>{esc(rtype)}</b>")
        parts.extend(f"  <code>{esc(v)}</code>" for v in values[:15])
        if len(values) > 15:
            parts.append(f"  … {len(values) - 15} more")
    return "\n".join(parts)


def fmt_rdap(d: dict) -> str:
    lines = [f"<b>Domain {esc(d.get('domain'))}</b>"]
    lines.append(_row("Handle", d.get("handle")).rstrip())
    if d.get("status"):
        lines.append(_row("Status", ", ".join(d["status"])).rstrip())
    lines.append(_row("Registrar", d.get("registrar")).rstrip())
    lines.append(_row("Registrant", d.get("registrant")).rstrip())
    for action, date in (d.get("events") or {}).items():
        lines.append(_row(action, date).rstrip())
    if d.get("nameservers"):
        lines.append("\n<b>Nameservers</b>")
        lines.extend(f"  <code>{esc(ns)}</code>" for ns in d["nameservers"][:10])
    return "\n".join(x for x in lines if x)


def fmt_email(d: dict) -> str:
    lines = [f"<b>Email {esc(d['address'])}</b>"]
    lines.append(_row("Syntax", "valid").rstrip())
    lines.append(_row("Domain", f"{d.get('domain')} ({d.get('domain_status')})").rstrip())
    if d.get("mx"):
        lines.append("\n<b>MX records</b>")
        lines.extend(f"  <code>{esc(v)}</code>" for v in d["mx"][:10])
    else:
        lines.append("\n⚠️ No MX records — mail probably can't be delivered to this domain.")
    lines.append(_row("SPF", d.get("spf")).rstrip())
    if d.get("role_based"):
        lines.append("⚠️ Role-based address (shared mailbox).")
    lines.append("\n<i>Verification only — no message is ever sent.</i>")
    return "\n".join(x for x in lines if x)


def fmt_username(d: dict) -> str:
    results = d.get("results", [])
    found = [r["site"] for r in results if r["state"] == "found"]
    missing = [r["site"] for r in results if r["state"] == "missing"]
    unknown = [f"{r['site']} ({r.get('detail') or 'blocked'})"
               for r in results if r["state"] == "unknown"]
    lines = [f"<b>🔍 @{esc(d['username'])}</b> — checked {len(results)} sites"]
    if found:
        lines.append(f"\n<b>✅ Found ({len(found)})</b>")
        lines.append(", ".join(esc(s) for s in found))
    if missing:
        lines.append(f"\n<b>❌ Not found ({len(missing)})</b>")
        lines.append(", ".join(esc(s) for s in missing))
    if unknown:
        lines.append(f"\n<b>❓ Unknown / blocked ({len(unknown)})</b>")
        lines.append(", ".join(esc(s) for s in unknown))
    lines.append("\n<i>Profiles are public data; blocked sites are reported as unknown.</i>")
    return "\n".join(lines)


def fmt_vehicle(d: dict) -> str:
    if d.get("kind") == "vin":
        lines = [f"<b>🚗 VIN {esc(d['vin'])}</b>"]
        lines.append(_row("Make", d.get("make")).rstrip())
        lines.append(_row("Model", d.get("model")).rstrip())
        lines.append(_row("Year", d.get("year")).rstrip())
        lines.append(_row("Type", d.get("vehicle_type")).rstrip())
        lines.append(_row("Body", d.get("body")).rstrip())
        lines.append(_row("Fuel", d.get("fuel")).rstrip())
        lines.append(_row("Engine", d.get("engine")).rstrip())
        lines.append(_row("Manufacturer", d.get("manufacturer")).rstrip())
        lines.append(_row("Assembly country", d.get("plant_country")).rstrip())
        if d.get("notes"):
            lines.append(f"\n⚠️ {esc(d['notes'])}")
        lines.append("\n<i>Source: NHTSA vPIC (official US VIN decoder)</i>")
        return "\n".join(x for x in lines if x)

    lines = [f"<b>🚘 Plate {esc(d['plate'])}</b>"]
    lines.append(_row("Format", d.get("format")).rstrip())
    lines.append(_row("Region", d.get("region")).rstrip())
    for k, v in (d.get("parts") or {}).items():
        lines.append(_row(k, v).rstrip())
    for note in d.get("notes") or []:
        lines.append(f"\nℹ️ {esc(note)}")
    lines.append(
        "\n<i>Format/region analysis only — registration records (owner details) "
        "are not public API data; use your official RTO/DMV service.</i>"
    )
    return "\n".join(x for x in lines if x)


def fmt_url(d: dict) -> str:
    lines = [f"<b>URL probe</b> — HTTP {esc(d['status'])}"]
    lines.append(_row("Final URL", d.get("final_url")).rstrip())
    if d.get("redirected"):
        lines.append("<i>↩ redirected</i>")
    lines.append(_row("Server IP", d.get("ip")).rstrip())
    lines.append(_row("Server", d.get("server")).rstrip())
    lines.append(_row("Powered-By", d.get("powered_by")).rstrip())
    lines.append(_row("Content-Type", d.get("content_type")).rstrip())
    lines.append(_row("Title", d.get("title")).rstrip())
    lines.append(_row("Body size", f"{d.get('body_bytes')} bytes").rstrip())
    return "\n".join(x for x in lines if x)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

HELP = """\
<b>🤖 OSINT bot — all commands</b>

🔹 <code>/ip &lt;address&gt;</code>
   geolocation, ASN/ISP, reverse DNS
🔹 <code>/dns &lt;domain&gt; [type]</code>
   DNS records (A, MX, TXT, NS… or ALL)
🔹 <code>/rdap &lt;domain&gt;</code>
   domain registration data (alias: /whois)
🔹 <code>/email &lt;address&gt;</code>
   syntax, MX &amp; SPF check (nothing is sent)
🔹 <code>/username &lt;name&gt;</code>
   profile presence across 100+ major sites
   (Facebook, Instagram, X, YouTube, TikTok-adjacent, GitHub…)
🔹 <code>/url &lt;https://…&gt;</code>
   HTTP status, headers, title, redirect chain
🔹 <code>/vehicle &lt;number&gt;</code>
   vehicle info from a registration number or VIN
🔹 <code>/vin &lt;17-char VIN&gt;</code>
   full VIN decode (NHTSA vPIC)
🔹 <code>/help</code>
   this message

<b>Vehicle examples:</b>
<code>/vehicle MH 12 AB 1234</code> — plate format → state/RTO/series
<code>/vehicle 5YJ3E1EA6PF426279</code> — VIN → make, model, year, body, fuel

Public data only. Use responsibly and only on targets you're authorized to research.
"""


def _need(arg: str, usage: str) -> str:
    if not arg:
        raise osint.OSINTError(f"usage: {usage}")
    return arg


def _handle(command: str, arg: str) -> str:
    if command in ("/ip",):
        return fmt_ip(osint.ip_lookup(_need(arg, "/ip 8.8.8.8")))
    if command == "/vehicle":
        return fmt_vehicle(osint.vehicle_lookup(_need(arg, "/vehicle MH 12 AB 1234")))
    if command == "/vin":
        return fmt_vehicle(osint.vin_lookup(_need(arg, "/vin 5YJ3E1EA6PF426279")))
    if command == "/dns":
        parts = arg.split()
        rtype = parts[1] if len(parts) > 1 else "ALL"
        return fmt_dns(osint.dns_lookup(parts[0], rtype))
    if command in ("/rdap", "/whois"):
        return fmt_rdap(osint.rdap_lookup(_need(arg, "/rdap example.com")))
    if command == "/email":
        return fmt_email(osint.email_check(_need(arg, "/email someone@example.com")))
    if command == "/username":
        return fmt_username(osint.username_check(_need(arg, "/username octocat")))
    if command == "/url":
        return fmt_url(osint.url_probe(_need(arg, "/url https://example.com")))
    raise osint.OSINTError(f"unknown command {command}")


USAGE = {
    "/ip": "usage: /ip 8.8.8.8",
    "/vehicle": "usage: /vehicle MH 12 AB 1234  (or a VIN)",
    "/vin": "usage: /vin 5YJ3E1EA6PF426279",
    "/dns": "usage: /dns example.com [A|MX|TXT|NS|…]",
    "/rdap": "usage: /rdap example.com",
    "/whois": "usage: /whois example.com",
    "/email": "usage: /email someone@example.com",
    "/username": "usage: /username octocat",
    "/url": "usage: /url https://example.com",
}


def dispatch(chat_id: int, command: str, arg: str) -> None:
    now = time.monotonic()
    last = _LAST_USE.get(chat_id, 0.0)
    if now - last < COOLDOWN_SECONDS:
        reply(chat_id, "⏳ Slow down — one lookup every couple of seconds.")
        return
    _LAST_USE[chat_id] = now

    try:
        if command in ("/start", "/help"):
            reply(chat_id, HELP)
            log.info("replied: %s ok (%d chars) chat=%s", command, len(HELP), chat_id)
            return
        text = _handle(command, arg)
        reply_long(chat_id, text)
        log.info("replied: %s ok (%d chars) chat=%s", command, len(text), chat_id)
    except osint.OSINTError as e:
        reply(chat_id, f"⚠️ {esc(e)}")
        log.warning("%s rejected: %s chat=%s", command, e, chat_id)
    except Exception:
        log.exception("handler crash for %s", command)
        reply(chat_id, "⚠️ Lookup failed unexpectedly — see logs.")


def handle_update(update: dict) -> None:
    msg = update.get("message") or {}
    chat_id = (msg.get("chat") or {}).get("id")
    text = (msg.get("text") or "").strip()
    if not chat_id or not text:
        return
    _UPDATES["processed"] += 1
    parts = text.split(maxsplit=1)
    command = parts[0].split("@")[0].lower()
    arg = parts[1].strip() if len(parts) > 1 else ""
    if command == "/start":
        command = "/help"
    log.info("received: %r chat=%s", command, chat_id)
    if command in ("/ip", "/dns", "/rdap", "/whois", "/email", "/username", "/url",
                   "/vehicle", "/vin", "/help"):
        dispatch(chat_id, command, arg)
    else:
        reply(chat_id, HELP)


# ---------------------------------------------------------------------------
# Health endpoint (readiness for the Freebuff preview)
# ---------------------------------------------------------------------------

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path.rstrip("/") in ("", "/health"):
            body = {
                "status": "ok" if _STATE["telegram"] == "ok" else "degraded",
                "telegram": _STATE["telegram"],
                "updates_processed": _UPDATES["processed"],
                "uptime_seconds": int(time.time() - STARTED_AT),
            }
            payload = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *_args):  # silence per-request noise
        pass


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def _shutdown(_signum, _frame):
    _STATE["running"] = False
    log.info("shutdown requested")
    raise SystemExit(0)


def main() -> int:
    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    server = ThreadingHTTPServer(("0.0.0.0", PORT), HealthHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log.info("health endpoint listening on 0.0.0.0:%s", PORT)

    if not TOKEN:
        _STATE["telegram"] = "missing TELEGRAM_BOT_TOKEN"
        log.error(
            "TELEGRAM_BOT_TOKEN is not set. Add it in Settings → Environment, "
            "then restart the preview. Serving health only."
        )
        while _STATE["running"]:
            time.sleep(30)
        return 0

    try:
        me = tg("getMe")
    except osint.OSINTError as e:
        _STATE["telegram"] = f"auth failed: {e}"
        log.error("token rejected: %s", e)
        while _STATE["running"]:
            time.sleep(30)
        return 1

    _STATE["telegram"] = "ok"
    log.info("authenticated as @%s — polling for updates", me.get("username"))

    offset = 0
    while _STATE["running"]:
        try:
            updates = tg("getUpdates", offset=offset, timeout=POLL_TIMEOUT,
                         allowed_updates=["message"])
        except osint.OSINTError as e:
            log.warning("poll error: %s — retrying in 3s", e)
            time.sleep(3)
            continue
        for upd in updates:
            offset = upd.get("update_id", offset) + 1
            try:
                handle_update(upd)
            except Exception:
                log.exception("failed to process update")
    return 0


if __name__ == "__main__":
    sys.exit(main())
