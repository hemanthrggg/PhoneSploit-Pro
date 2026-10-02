"""Offline smoke assertions for osintbot — no network calls, no bot token needed.

Run: python3 osintbot/ci_smoke.py   (exits non-zero on any failure)
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bot  # noqa: E402
import osint  # noqa: E402

FAILS: list[str] = []


def ok(name: str, cond: bool) -> None:
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        FAILS.append(name)


def main() -> None:
    # --- site table invariants -------------------------------------------
    ok(f"site count >= 100 (got {len(osint._SITES)})", len(osint._SITES) >= 100)
    labels = [s[0] for s in osint._SITES]
    ok("no duplicate site labels", len(labels) == len(set(labels)))
    ok("every label non-empty", all(s[0].strip() for s in osint._SITES))
    ok("every template has {u}", all("{u}" in s[1] for s in osint._SITES))
    known_kinds = (
        "status404", "marker:", "echo", "telegram", "facebook",
        "subdomain", "gl_api", "title_marker:", "title_echo",
    )
    ok("every detection kind is known",
       all(s[2].startswith(known_kinds) for s in osint._SITES))

    # --- offline error paths (must raise OSINTError before any network) ----
    error_cases = [
        ("ip_lookup", lambda: osint.ip_lookup("not-an-ip")),
        ("vin_lookup", lambda: osint.vin_lookup("tooshort")),
        ("vehicle_lookup empty", lambda: osint.vehicle_lookup("")),
        ("dns_lookup nodots", lambda: osint.dns_lookup("nodots")),
        ("email_check bad", lambda: osint.email_check("bad@")),
        ("username_check bad", lambda: osint.username_check("bad name!")),
        ("rdap_lookup empty", lambda: osint.rdap_lookup("")),
    ]
    for name, fn in error_cases:
        try:
            fn()
            ok(f"{name} rejects invalid input", False)
        except osint.OSINTError:
            ok(f"{name} rejects invalid input", True)

    # --- formatters on synthetic data --------------------------------------
    ip_out = bot.fmt_ip({
        "ip": "1.2.3.4", "scope": "global", "rdns": "rdns.example",
        "geo": {"source": "test", "country": "C", "region": "R", "city": "Ci",
                "lat": 1, "lon": 2, "tz": "T", "asn": 64500, "isp": "ISP", "org": "ORG"},
    })
    ok("fmt_ip renders", "1.2.3.4" in ip_out and "ISP" in ip_out)

    veh_out = bot.fmt_vehicle({
        "kind": "vin", "vin": "TESTVIN123", "make": "MAKE", "model": None,
        "year": None, "vehicle_type": None, "body": None, "fuel": None,
        "engine": None, "manufacturer": None, "plant_country": None, "notes": None,
    })
    ok("fmt_vehicle renders VIN", "TESTVIN123" in veh_out and "MAKE" in veh_out)

    plate_out = bot.fmt_vehicle({
        "kind": "plate", "plate": "MH 12 AB 1234", "format": "Indian registration",
        "region": "Maharashtra (MH)", "parts": {"RTO district code": "12"},
        "notes": [],
    })
    ok("fmt_vehicle renders plate", "MH 12 AB 1234" in plate_out)

    un_out = bot.fmt_username({
        "username": "u1",
        "results": [
            {"site": "SiteA", "state": "found", "detail": None},
            {"site": "SiteB", "state": "missing", "detail": None},
            {"site": "SiteC", "state": "unknown", "detail": "HTTP 403"},
        ],
    })
    ok("fmt_username groups results",
       "Found (1)" in un_out and "Not found (1)" in un_out
       and "Unknown / blocked (1)" in un_out and "SiteA" in un_out)

    ok("HELP lists every command",
       all(c in bot.HELP for c in
           ("/ip", "/dns", "/rdap", "/email", "/username", "/url", "/vehicle", "/vin", "/help")))
    ok("HTML escaping works", "&lt;x&gt;" in bot.esc("<x>"))

    # --- long-reply chunking (transport mocked) ----------------------------
    sent: list[dict] = []
    real_tg = bot.tg
    bot.tg = lambda method, **params: sent.append(params) or True
    try:
        long_text = "<b>header</b>\n" + "\n".join(
            f"line {i} " + "x" * 80 for i in range(120)
        )
        ok("test payload is actually long", len(long_text) > 4096)
        bot.reply_long(1, long_text)
        ok("reply_long splits into multiple messages", len(sent) > 1)
        ok("every chunk within Telegram limit",
           all(len(p["text"]) <= 4096 for p in sent))
        n_before = len(sent)
        bot.reply_long(2, "short message")
        ok("reply_long sends short text as one message", len(sent) == n_before + 1)
    finally:
        bot.tg = real_tg

    # --- module state -------------------------------------------------------
    ok("TOKEN read as string from env", isinstance(bot.TOKEN, str))
    ok("cooldown is positive", bot.COOLDOWN_SECONDS > 0)

    if FAILS:
        print(f"\n{len(FAILS)} check(s) FAILED: {FAILS}")
        sys.exit(1)
    print("\nall smoke checks passed")


if __name__ == "__main__":
    main()
