# OSINT Telegram Bot

A small Telegram bot for **open-source-intelligence lookups** built on the Python 3.10
standard library — no third-party packages, no API keys for the data sources.

Public data only. Use it only on targets you own or are authorized to research.

## Commands

| Command | Description |
| --- | --- |
| `/ip <address>` | Geolocation, ASN/ISP/org, reverse DNS (ipwho.is, fallback ip-api.com) |
| `/dns <domain> [type]` | DNS records via Cloudflare DNS-over-HTTPS (A, AAAA, MX, NS, TXT, SOA, CAA, or ALL) |
| `/rdap <domain>` | Domain registration data via RDAP (`/whois` alias) |
| `/email <address>` | Syntax + domain MX/SPF verification — **no mail is ever sent** |
| `/username <name>` | Profile presence across **102 major sites** — social (Facebook, Instagram, X, LinkedIn, Telegram…), dev (GitHub, GitLab, npm…), gaming (Steam, Chess.com…), media, commerce. Verified detection strategies per site (status codes, page markers, redirects, subdomain DNS); blocked sites report `unknown`, never a false claim |
| `/url <https://…>` | HTTP status, redirect target, server headers, page title |
| `/vehicle <number>` | Vehicle info: auto-detects VIN (full NHTSA decode) or registration plate (state/RTO/region format analysis) |
| `/vin <17-char VIN>` | Full VIN decode — make, model, year, body, fuel, manufacturer (NHTSA vPIC) |
| `/help` | Usage |

## Setup

1. Create a bot with [@BotFather](https://t.me/BotFather) and copy its token.
2. In Freebuff: **Settings → Environment**, add key `TELEGRAM_BOT_TOKEN` (paste the token as the value).
3. Restart the preview so the process picks up the key.

The process serves a health endpoint on `0.0.0.0:$PORT`:

```
GET /  →  {"status": "ok"|"degraded", "telegram": "ok"|"missing TELEGRAM_BOT_TOKEN", ...}
```

If the token is missing the bot stays up (health reports `degraded`) and logs exactly
what to fix — add the key and restart, nothing else changes.

## Run locally

```sh
TELEGRAM_BOT_TOKEN=123:abc PORT=8080 python3 osintbot/bot.py
```

No `pip install` is required; `requirements.txt` at the repo root is untouched.

## Layout

- `osintbot/osint.py` — lookup functions (IP, DNS, RDAP, email, username, URL); each returns a dict and raises `OSINTError` on failure
- `osintbot/bot.py` — Telegram long-poll loop, command dispatch, HTML report formatting, health server

## Notes & limits

- Data sources are free public endpoints: `ipwho.is`, `ip-api.com` (fallback), Cloudflare DoH, `rdap.org`, NHTSA vPIC (VINs), plus direct public profile URLs. No keys, no accounts.
- Vehicle lookups decode VINs and analyze plate *format/region* only. Owner/registration records are restricted personal data in most jurisdictions — the bot deliberately does not query data-broker "RC lookup" services.
- Per-chat rate limit of one lookup every 2s to stay polite toward those endpoints.
- The bot reads messages addressed to it (commands only) and ignores everything else.
