"""OSINT lookup helpers — Python 3.10 stdlib only.

Every function returns a plain dict and raises OSINTError on failure.
Data sources are public, keyless endpoints:
  - IP geo/ASN : ipwho.is (HTTPS), fallback ip-api.com
  - DNS        : Cloudflare DNS-over-HTTPS (HTTPS)
  - Domain     : RDAP via rdap.org (redirects to the authoritative registry)
  - Email      : syntax + MX/SPF checks only (no mail is ever sent)
  - Username   : public profile URLs on a handful of sites
  - URL        : HTTP headers / title of a public page
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

UA = "Mozilla/5.0 (X11; Linux x86_64) compatible; OSINTBot/1.0"
TIMEOUT = 12
MAX_BODY = 65536


class OSINTError(Exception):
    """Raised when a lookup cannot be completed."""


def _request(url, *, method="GET", headers=None, timeout=TIMEOUT, max_bytes=MAX_BODY):
    hdrs = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read(max_bytes), resp.geturl()
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read(max_bytes)
        except Exception:
            pass
        return e.code, dict(e.headers or {}), body, url
    except (urllib.error.URLError, TimeoutError, socket.timeout, ssl.SSLError, OSError) as e:
        raise OSINTError(f"request failed ({e})") from e


def _json(url, **kw):
    status, _, body, _ = _request(url, **kw)
    if status != 200:
        host = urllib.parse.urlsplit(url).netloc
        raise OSINTError(f"HTTP {status} from {host}")
    try:
        return json.loads(body.decode("utf-8", "replace"))
    except json.JSONDecodeError as e:
        raise OSINTError("endpoint returned invalid JSON") from e


def _normalize_domain(raw: str) -> str:
    d = (raw or "").strip()
    if not d:
        raise OSINTError("expected a domain, e.g. example.com")
    if "://" in d:
        d = urllib.parse.urlsplit(d).hostname or ""
    d = d.split("/")[0].split("?")[0].split(":")[0].strip().lower().rstrip(".")
    if not d or "." not in d:
        raise OSINTError(f"not a valid domain: {raw!r}")
    try:
        return d.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise OSINTError(f"invalid domain: {raw!r}") from e


# ---------------------------------------------------------------------------
# IP
# ---------------------------------------------------------------------------

def ip_lookup(target: str) -> dict:
    try:
        ip = ipaddress.ip_address((target or "").strip())
    except ValueError as e:
        raise OSINTError(f"not a valid IP address: {target!r}") from e

    out: dict = {"ip": str(ip), "scope": "global" if ip.is_global else "private/reserved"}

    try:
        out["rdns"] = socket.gethostbyaddr(str(ip))[0]
    except OSError:
        out["rdns"] = None

    geo = None
    try:
        j = _json(f"https://ipwho.is/{ip}")
        if j.get("success"):
            conn = j.get("connection") or {}
            tz = j.get("timezone") or {}
            geo = {
                "source": "ipwho.is",
                "country": j.get("country"),
                "region": j.get("region"),
                "city": j.get("city"),
                "lat": j.get("latitude"),
                "lon": j.get("longitude"),
                "tz": tz.get("id"),
                "asn": conn.get("asn"),
                "isp": conn.get("isp"),
                "org": conn.get("org"),
            }
    except OSINTError:
        geo = None

    if geo is None:
        try:
            j = _json(
                "http://ip-api.com/json/"
                + str(ip)
                + "?fields=status,message,country,regionName,city,lat,lon,timezone,isp,org,as,query"
            )
            if j.get("status") == "success":
                geo = {
                    "source": "ip-api.com",
                    "country": j.get("country"),
                    "region": j.get("regionName"),
                    "city": j.get("city"),
                    "lat": j.get("lat"),
                    "lon": j.get("lon"),
                    "tz": j.get("timezone"),
                    "asn": (j.get("as") or "").split(" ")[0] or None,
                    "isp": j.get("isp"),
                    "org": j.get("org"),
                }
        except OSINTError:
            geo = None

    if geo is None:
        out["geo"] = None
        out["geo_note"] = "geolocation service unavailable — reverse DNS only"
    else:
        out["geo"] = geo
    return out


# ---------------------------------------------------------------------------
# DNS (Cloudflare DoH)
# ---------------------------------------------------------------------------

_DNS_TYPES = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16, "CNAME": 5, "SOA": 6, "CAA": 257}
_DNS_STATUS = {0: "NOERROR", 3: "NXDOMAIN", 2: "SERVFAIL", 5: "REFUSED"}


def dns_lookup(domain: str, rtype: str = "ALL") -> dict:
    name = _normalize_domain(domain)
    rtype = (rtype or "ALL").strip().upper()
    if rtype != "ALL" and rtype not in _DNS_TYPES:
        raise OSINTError(f"unknown DNS type {rtype!r}; use one of {', '.join(_DNS_TYPES)} or ALL")

    wanted = list(_DNS_TYPES) if rtype == "ALL" else [rtype]
    records: dict[str, list[str]] = {}
    status_label = "NOERROR"

    for t in wanted:
        q = urllib.parse.urlencode({"name": name, "type": t})
        try:
            j = _json(
                f"https://cloudflare-dns.com/dns-query?{q}",
                headers={"Accept": "application/dns-json"},
            )
        except OSINTError:
            continue
        code = j.get("Status", 0)
        if code == 3:
            status_label = "NXDOMAIN"
            continue
        for ans in j.get("Answer") or []:
            if ans.get("type") != _DNS_TYPES[t]:
                continue
            data = str(ans.get("data", "")).strip().strip('"')
            if data and data not in records.setdefault(t, []):
                records[t].append(data)

    if status_label == "NXDOMAIN" and not records:
        return {"domain": name, "status": "NXDOMAIN", "records": {}}
    return {"domain": name, "status": "NOERROR", "records": records}


# ---------------------------------------------------------------------------
# RDAP / WHOIS
# ---------------------------------------------------------------------------

def rdap_lookup(domain: str) -> dict:
    name = _normalize_domain(domain)
    status, _, body, _ = _request(f"https://rdap.org/domain/{name}")
    if status == 404:
        raise OSINTError(f"no RDAP record found for {name}")
    if status != 200:
        raise OSINTError(f"RDAP lookup failed (HTTP {status})")
    try:
        j = json.loads(body.decode("utf-8", "replace"))
    except json.JSONDecodeError as e:
        raise OSINTError("RDAP endpoint returned invalid JSON") from e

    out: dict = {
        "domain": j.get("ldhName") or name,
        "handle": j.get("handle"),
        "status": j.get("status") or [],
        "nameservers": [ns.get("ldhName") for ns in (j.get("nameservers") or []) if ns.get("ldhName")],
        "events": {},
        "registrar": None,
        "registrant": None,
    }
    for ev in j.get("events") or []:
        action, date = ev.get("eventAction"), ev.get("eventDate")
        if action and date:
            out["events"][action] = date

    def _vcard_fn(entity) -> str | None:
        arr = entity.get("vcardArray")
        if not isinstance(arr, list) or len(arr) < 2:
            return None
        for item in arr[1]:
            if isinstance(item, list) and item and item[0] == "fn" and len(item) > 1:
                return str(item[3] if len(item) > 3 else item[1])
        return None

    for ent in j.get("entities") or []:
        roles = [str(r).lower() for r in (ent.get("roles") or [])]
        fn = _vcard_fn(ent)
        if "registrar" in roles and fn and not out["registrar"]:
            out["registrar"] = fn
        if "registrant" in roles and fn and not out["registrant"]:
            out["registrant"] = fn
        for sub in ent.get("entities") or []:
            sub_roles = [str(r).lower() for r in (sub.get("roles") or [])]
            if "registrant" in sub_roles and not out["registrant"]:
                out["registrant"] = _vcard_fn(sub)
    return out


# ---------------------------------------------------------------------------
# Email (verification only — nothing is ever sent)
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")
_ROLE_PREFIXES = ("info", "admin", "support", "sales", "contact", "help", "billing", "abuse", "postmaster", "webmaster")


def email_check(addr: str) -> dict:
    address = (addr or "").strip()
    if not _EMAIL_RE.match(address):
        raise OSINTError(f"not a valid email address: {address!r}")
    local, domain = address.rsplit("@", 1)
    domain = _normalize_domain(domain)

    out: dict = {
        "address": address,
        "domain": domain,
        "role_based": local.lower() in _ROLE_PREFIXES,
        "mx": [],
        "spf": None,
        "domain_status": "unknown",
    }
    try:
        dns = dns_lookup(domain, "ALL")
        out["domain_status"] = dns["status"]
        out["mx"] = dns["records"].get("MX", [])
        for txt in dns["records"].get("TXT", []):
            if txt.lower().startswith("v=spf1"):
                out["spf"] = txt
                break
    except OSINTError as e:
        out["domain_status"] = f"lookup failed ({e})"
    return out


# ---------------------------------------------------------------------------
# Username presence (public profile URLs across ~105 major sites)
# ---------------------------------------------------------------------------

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,32}$")

# Each site: (label, url template with {u}, detection kind)
# Kinds:
#   status404 — 200/410-after-404 => found/missing, 403/429/999 => unknown (blocked)
#   marker:X  — 200 + body contains X => missing, otherwise found
#   echo      — found iff the username appears (word-boundary) in the page body
#   telegram  — missing iff boilerplate 'contact'+'message' tokens are present
#   facebook  — missing iff redirect lands on /login (or loses the profile path)
#   subdomain — fetch ok => found, DNS/SSL failure => missing
#   gl_api    — GitLab users API: 200 + non-empty JSON list => found
_SITES = [
    # -- majors / social --
    ("X (Twitter)", "https://x.com/{u}", "status404"),
    ("Facebook", "https://www.facebook.com/{u}", "facebook"),
    ("Instagram", "https://www.instagram.com/{u}", "status404"),
    ("LinkedIn", "https://www.linkedin.com/in/{u}", "status404"),
    ("Snapchat", "https://www.snapchat.com/add/{u}", "status404"),
    ("Telegram", "https://t.me/{u}", "telegram"),
    ("YouTube", "https://www.youtube.com/@{u}", "status404"),
    ("Twitch", "https://www.twitch.tv/{u}", "echo"),
    ("Reddit", "https://www.reddit.com/user/{u}.json", "status404"),
    ("Tumblr", "https://{u}.tumblr.com/", "subdomain"),
    ("Medium", "https://medium.com/@{u}", "status404"),
    ("Quora", "https://www.quora.com/profile/{u}", "status404"),
    ("VK", "https://vk.com/{u}", "status404"),
    ("OK.ru", "https://ok.ru/{u}", "status404"),
    ("Mastodon", "https://mastodon.social/@{u}", "status404"),
    ("9GAG", "https://9gag.com/u/{u}", "status404"),
    ("MySpace", "https://myspace.com/{u}", "status404"),
    ("Gab", "https://gab.com/{u}", "status404"),
    ("Minds", "https://minds.com/{u}", "status404"),
    ("Truth Social", "https://truthsocial.com/@{u}", "status404"),
    ("Foursquare", "https://foursquare.com/{u}", "status404"),
    ("About.me", "https://about.me/{u}", "status404"),
    ("Gravatar", "https://gravatar.com/{u}", "status404"),
    ("Linktree", "https://linktr.ee/{u}", "status404"),
    # -- content / media --
    ("Spotify", "https://open.spotify.com/user/{u}", "status404"),
    ("SoundCloud", "https://soundcloud.com/{u}", "status404"),
    ("Vimeo", "https://vimeo.com/{u}", "status404"),
    ("Bandcamp", "https://{u}.bandcamp.com/", "subdomain"),
    ("Genius", "https://genius.com/{u}", "status404"),
    ("Mixcloud", "https://www.mixcloud.com/{u}/", "status404"),
    ("Flickr", "https://www.flickr.com/people/{u}/", "status404"),
    ("We Heart It", "https://weheartit.com/{u}", "status404"),
    ("Pixiv", "https://www.pixiv.net/en/users/{u}", "status404"),
    ("Wattpad", "https://www.wattpad.com/user/{u}", "status404"),
    ("Goodreads", "https://www.goodreads.com/{u}", "status404"),
    ("Rumble", "https://rumble.com/user/{u}", "status404"),
    # -- blogging / writing --
    ("WordPress", "https://{u}.wordpress.com/", "subdomain"),
    ("Blogger", "https://{u}.blogspot.com/", "subdomain"),
    ("LiveJournal", "https://{u}.livejournal.com/", "subdomain"),
    ("Dreamwidth", "https://{u}.dreamwidth.net/", "subdomain"),
    ("Substack", "https://{u}.substack.com/", "subdomain"),
    ("Dev.to", "https://dev.to/{u}", "status404"),
    ("Hacker News", "https://news.ycombinator.com/user?id={u}", "marker:No such user"),
    ("Lobsters", "https://lobste.rs/users/{u}", "status404"),
    # -- developer / tech --
    ("GitHub", "https://github.com/{u}", "status404"),
    ("GitLab", "https://gitlab.com/api/v4/users?username={u}", "gl_api"),
    ("Bitbucket", "https://bitbucket.org/{u}", "status404"),
    ("Codeberg", "https://codeberg.org/{u}", "status404"),
    ("Replit", "https://replit.com/@{u}", "status404"),
    ("CodePen", "https://codepen.io/{u}", "status404"),
    ("Docker Hub", "https://hub.docker.com/u/{u}", "status404"),
    ("Hugging Face", "https://huggingface.co/{u}", "status404"),
    ("npm", "https://www.npmjs.com/~{u}", "status404"),
    ("crates.io", "https://crates.io/users/{u}", "status404"),
    ("DigitalOcean", "https://www.digitalocean.com/users/{u}", "status404"),
    ("SourceForge", "https://sourceforge.net/u/{u}/profile/", "status404"),
    # -- coding challenge profiles --
    ("Codeforces", "https://codeforces.com/profile/{u}", "title_echo"),
    ("AtCoder", "https://atcoder.jp/users/{u}", "status404"),
    ("LeetCode", "https://leetcode.com/{u}/", "status404"),
    ("HackerEarth", "https://www.hackerearth.com/@{u}", "status404"),
    ("TopCoder", "https://www.topcoder.com/members/{u}", "status404"),
    ("GeeksforGeeks", "https://www.geeksforgeeks.org/user/{u}", "status404"),
    ("freeCodeCamp", "https://www.freecodecamp.org/{u}", "status404"),
    ("HackerOne", "https://hackerone.com/{u}", "status404"),
    # -- gaming --
    ("Steam", "https://steamcommunity.com/id/{u}", "title_marker:community :: error"),
    ("Chess.com", "https://www.chess.com/member/{u}", "status404"),
    ("Lichess", "https://lichess.org/@/{u}", "status404"),
    ("osu!", "https://osu.ppy.sh/users/{u}", "status404"),
    ("Speedrun.com", "https://www.speedrun.com/user/{u}", "status404"),
    ("Roblox", "https://www.roblox.com/users/profile?username={u}", "status404"),
    ("Xbox", "https://xboxgamertag.com/search/{u}", "status404"),
    ("NameMC (Minecraft)", "https://namemc.com/profile/{u}", "status404"),
    ("PSNProfiles", "https://psnprofiles.com/{u}", "status404"),
    # -- anime / wiki --
    ("MyAnimeList", "https://myanimelist.net/profile/{u}", "status404"),
    ("Wikipedia", "https://en.wikipedia.org/wiki/User:{u}", "status404"),
    ("Wiktionary", "https://en.wiktionary.org/wiki/User:{u}", "status404"),
    ("OpenStreetMap", "https://www.openstreetmap.org/user/{u}", "status404"),
    ("Douban", "https://www.douban.com/people/{u}/", "status404"),
    # -- commerce / work --
    ("eBay", "https://www.ebay.com/usr/{u}", "status404"),
    ("Etsy", "https://www.etsy.com/shop/{u}", "status404"),
    ("Patreon", "https://www.patreon.com/{u}", "status404"),
    ("Buy Me a Coffee", "https://www.buymeacoffee.com/{u}", "status404"),
    ("Gumroad", "https://gumroad.com/{u}", "status404"),
    ("PayPal.me", "https://paypal.me/{u}", "status404"),
    ("Venmo", "https://venmo.com/{u}", "status404"),
    ("Fiverr", "https://www.fiverr.com/{u}", "status404"),
    ("Upwork", "https://www.upwork.com/freelancers/~{u}", "status404"),
    ("Freelancer", "https://www.freelancer.com/u/{u}", "status404"),
    ("Indeed", "https://profile.indeed.com/{u}", "status404"),
    ("Crunchbase", "https://www.crunchbase.com/person/{u}", "status404"),
    ("XING", "https://www.xing.com/profile/{u}", "status404"),
    ("Skillshare", "https://www.skillshare.com/members/{u}", "status404"),
    # -- reviews / places --
    ("Yelp", "https://www.yelp.com/user_details?user_id={u}", "status404"),
    ("TripAdvisor", "https://www.tripadvisor.com/Profile/{u}", "status404"),
    ("Zillow", "https://www.zillow.com/profile/{u}", "status404"),
    # -- design / misc --
    ("Dribbble", "https://dribbble.com/{u}", "status404"),
    ("Behance", "https://www.behance.net/{u}", "status404"),
    ("ArtStation", "https://www.artstation.com/{u}", "status404"),
    ("DeviantArt", "https://www.deviantart.com/{u}", "status404"),
    ("Product Hunt", "https://www.producthunt.com/@{u}", "status404"),
    ("Strava", "https://www.strava.com/athletes/{u}", "status404"),
    ("Kaggle", "https://www.kaggle.com/{u}", "status404"),
]

_BLOCK_STATUSES = {403, 406, 429, 451, 999}
_MISSING_STATUSES = {404, 410}


def _probe_site(label: str, url: str, kind: str, username: str) -> dict:
    url = url.format(u=username)
    try:
        status, headers, body, final = _request(url, timeout=7, max_bytes=20000)
        # Python 3.10's urllib does not follow 308; do it once manually
        if status == 308:
            loc = headers.get("Location") or headers.get("location")
            if loc:
                status, headers, body, final = _request(
                    urllib.parse.urljoin(url, loc), timeout=7, max_bytes=20000
                )
    except OSINTError as e:
        if kind == "subdomain":
            return {"site": label, "state": "missing", "detail": None}
        return {"site": label, "state": "unknown", "detail": str(e)[:60]}

    if status in _BLOCK_STATUSES:
        return {"site": label, "state": "unknown", "detail": "blocked/rate-limited"}

    try:
        if kind == "subdomain":
            state = "found" if status == 200 else ("missing" if status in _MISSING_STATUSES else "unknown")
            detail = None if state != "unknown" else f"HTTP {status}"
            return {"site": label, "state": state, "detail": detail}

        if kind == "gl_api":
            if status != 200:
                return {"site": label, "state": "unknown", "detail": f"HTTP {status}"}
            rows = json.loads(body.decode("utf-8", "replace"))
            state = "found" if isinstance(rows, list) and rows else "missing"
            return {"site": label, "state": state, "detail": None}

        if kind.startswith("marker:"):
            if status in _MISSING_STATUSES:
                return {"site": label, "state": "missing", "detail": None}
            if status != 200:
                return {"site": label, "state": "unknown", "detail": f"HTTP {status}"}
            text = body.decode("utf-8", "replace").lower()
            markers = [m.strip().lower() for m in kind.split(":", 1)[1].split("|")]
            state = "missing" if any(m in text for m in markers) else "found"
            return {"site": label, "state": state, "detail": None}

        if kind.startswith("title_marker:") or kind == "title_echo":
            if status != 200:
                return {"site": label, "state": "unknown", "detail": f"HTTP {status}"}
            text = body.decode("utf-8", "replace")
            m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
            title = (m.group(1) if m else "").lower()
            if kind == "title_echo":
                found = bool(re.search(rf"(?<![a-z0-9_]){re.escape(username.lower())}(?![a-z0-9_])", title))
                return {"site": label, "state": "found" if found else "missing", "detail": None}
            marker = kind.split(":", 1)[1].lower()
            state = "missing" if marker in title else "found"
            return {"site": label, "state": state, "detail": None}

        if kind == "echo":
            if status != 200:
                return {"site": label, "state": "unknown", "detail": f"HTTP {status}"}
            text = body.decode("utf-8", "replace").lower()
            found = bool(re.search(rf"(?<![a-z0-9_]){re.escape(username.lower())}(?![a-z0-9_])", text))
            return {"site": label, "state": "found" if found else "missing", "detail": None}

        if kind == "telegram":
            if status != 200:
                return {"site": label, "state": "unknown", "detail": f"HTTP {status}"}
            text = body.decode("utf-8", "replace").lower()
            state = "missing" if ("contact" in text and "message" in text) else "found"
            return {"site": label, "state": state, "detail": None}

        if kind == "facebook":
            if status in _MISSING_STATUSES:
                return {"site": label, "state": "missing", "detail": None}
            if status != 200:
                return {"site": label, "state": "unknown", "detail": f"HTTP {status}"}
            missing = ("/login" in final) or (f"/{username}" not in final)
            return {"site": label, "state": "missing" if missing else "found", "detail": None}

        # default: status404
        if status == 200:
            return {"site": label, "state": "found", "detail": None}
        if status in _MISSING_STATUSES:
            return {"site": label, "state": "missing", "detail": None}
        return {"site": label, "state": "unknown", "detail": f"HTTP {status}"}
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"site": label, "state": "unknown", "detail": "bad response"}


def username_check(username: str) -> dict:
    u = (username or "").strip().lstrip("@")
    if not _USERNAME_RE.match(u):
        raise OSINTError(f"invalid username: {username!r}")
    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(lambda s: _probe_site(*s, u), _SITES))
    return {"username": u, "results": results}


# ---------------------------------------------------------------------------
# Vehicle (VIN decode via official NHTSA vPIC + plate format analysis)
# ---------------------------------------------------------------------------

_VIN_RE = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$")

# Indian RTO state/UT codes (first two letters of a registration number)
_INDIAN_STATES = {
    "AN": "Andaman & Nicobar", "AP": "Andhra Pradesh", "AR": "Arunachal Pradesh",
    "AS": "Assam", "BR": "Bihar", "CG": "Chhattisgarh", "CH": "Chandigarh",
    "DD": "Dadra & Nagar Haveli and Daman & Diu", "DL": "Delhi", "GA": "Goa",
    "GJ": "Gujarat", "HP": "Himachal Pradesh", "HR": "Haryana", "JH": "Jharkhand",
    "JK": "Jammu & Kashmir", "KA": "Karnataka", "KL": "Kerala", "LA": "Ladakh",
    "LD": "Lakshadweep", "MH": "Maharashtra", "ML": "Meghalaya", "MN": "Manipur",
    "MP": "Madhya Pradesh", "MZ": "Mizoram", "NL": "Nagaland", "OD": "Odisha",
    "PB": "Punjab", "PY": "Puducherry", "RJ": "Rajasthan", "SK": "Sikkim",
    "TN": "Tamil Nadu", "TR": "Tripura", "TS": "Telangana", "UK": "Uttarakhand",
    "UP": "Uttar Pradesh", "WB": "West Bengal",
}

# Country codes that some European plates carry as a prefix (format match only)
_EU_CODES = {
    "A": "Austria", "B": "Belgium", "BG": "Bulgaria", "CH": "Switzerland",
    "CZ": "Czechia", "D": "Germany", "DK": "Denmark", "E": "Spain",
    "EST": "Estonia", "F": "France", "FIN": "Finland", "GR": "Greece",
    "H": "Hungary", "HR": "Croatia", "I": "Italy", "IRL": "Ireland",
    "IS": "Iceland", "L": "Luxembourg", "LT": "Lithuania", "LV": "Latvia",
    "M": "Malta", "N": "Norway", "NL": "Netherlands", "P": "Portugal",
    "PL": "Poland", "RO": "Romania", "S": "Sweden", "SK": "Slovakia",
    "SLO": "Slovenia", "TR": "Turkiye", "UA": "Ukraine", "UK": "United Kingdom",
}


def _vin_decode(vin: str) -> dict:
    j = _json(f"https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues/{vin}?format=json")
    results = j.get("Results") or []
    if not results:
        raise OSINTError("no data returned for that VIN")
    r = results[0]
    def g(key):
        v = (r.get(key) or "").strip()
        return v or None
    out = {
        "vin": vin,
        "make": g("Make"),
        "model": g("Model"),
        "year": g("ModelYear"),
        "vehicle_type": g("VehicleType"),
        "body": g("BodyClass"),
        "fuel": g("FuelTypePrimary"),
        "engine": g("EngineCylinders") or g("DisplacementL"),
        "manufacturer": g("Manufacturer"),
        "plant_country": g("PlantCountry"),
        "notes": g("ErrorText"),
    }
    if out["notes"] and out["make"]:
        # decoded successfully; minor spec notes (e.g. check digit) are noise
        out["notes"] = None
    return out


def _plate_analyze(plate: str) -> dict:
    clean = re.sub(r"\s+", " ", plate).strip().upper()
    out: dict = {"plate": clean, "format": "unknown", "region": None, "parts": {}, "notes": []}

    m = re.match(r"^([A-Z]{2})[\s-]?(\d{1,2})[\s-]?([A-Z]{1,3})[\s-]?(\d{1,4})$", clean)
    if m and m.group(1) in _INDIAN_STATES:
        code = m.group(1)
        out.update(
            format="Indian registration",
            region=f"{_INDIAN_STATES[code]} ({code})",
            parts={"State/UT code": code, "RTO district code": m.group(2),
                   "Series": m.group(3), "Number": m.group(4)},
        )
        return out

    if re.search(r"\bBH\b", clean):
        out.update(format="Bharat series (nationwide)", region="India")
        out["notes"].append("BH-series plates are valid across India, independent of state.")
        return out

    for code in sorted(_EU_CODES, key=len, reverse=True):
        if clean.startswith(code) and len(clean) > len(code) and clean[len(code)] in " -":
            out.update(format="prefix-style plate", region=_EU_CODES[code])
            out["parts"]["Country code"] = code
            return out

    out["notes"].append("Unrecognized plate format — try the full number, e.g. MH 12 AB 1234 or a VIN.")
    return out


def vehicle_lookup(number: str) -> dict:
    raw = (number or "").strip().upper()
    if not raw:
        raise OSINTError("usage: /vehicle MH 12 AB 1234  (or a 17-char VIN)")
    compact = re.sub(r"[\s\-]", "", raw)
    if _VIN_RE.match(compact):
        return {"kind": "vin", **_vin_decode(compact)}
    return {"kind": "plate", **_plate_analyze(raw)}


def vin_lookup(number: str) -> dict:
    raw = (number or "").strip().upper()
    compact = re.sub(r"[\s\-]", "", raw)
    if not _VIN_RE.match(compact):
        raise OSINTError("not a valid 17-character VIN (I, O, Q are never used in VINs)")
    return {"kind": "vin", **_vin_decode(compact)}


# ---------------------------------------------------------------------------
# URL probe
# ---------------------------------------------------------------------------

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def url_probe(raw_url: str) -> dict:
    url = (raw_url or "").strip()
    if not re.match(r"^https?://", url, re.I):
        raise OSINTError("include the scheme, e.g. https://example.com")
    parts = urllib.parse.urlsplit(url)
    if not parts.hostname:
        raise OSINTError(f"could not parse URL: {url!r}")
    try:
        ip = socket.gethostbyname(parts.hostname)
    except OSError:
        ip = None

    status, headers, body, final = _request(url)
    text = body.decode("utf-8", "replace")
    m = _TITLE_RE.search(text)
    title = re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else None

    return {
        "requested_url": url,
        "final_url": final,
        "redirected": final != url,
        "status": status,
        "ip": ip,
        "server": headers.get("Server"),
        "powered_by": headers.get("X-Powered-By"),
        "content_type": headers.get("Content-Type"),
        "title": title,
        "body_bytes": len(body),
    }
