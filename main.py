#!/usr/bin/env python3
import asyncio
import json
import os
import random
import re as _re
import sys
import time
from urllib.parse import urlparse, unquote
from contextlib import asynccontextmanager, suppress
from typing import Dict, List, Optional, Union

import httpx
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware

import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

try:
    from camoufox.async_api import AsyncCamoufox
    from browserforge.fingerprints import Screen as _Screen

    HAS_CAMOUFOX = True
except ImportError:
    HAS_CAMOUFOX = False
    logger.warning("Camoufox not installed — Tidal auto-approval will be unavailable")

try:
    from curl_cffi.requests import AsyncSession as _CurlSession

    HAS_CURL_CFFI = True
except ImportError:
    HAS_CURL_CFFI = False
    logger.warning("curl_cffi not installed — Oxaam fast-path disabled, will use Camoufox fallback")

try:
    from playwright.async_api import async_playwright

    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False
    logger.warning("Playwright not installed — will use Camoufox only")

load_dotenv()

API_VERSION = "2.10"

# Shared HTTP client is created in app lifespan for connection reuse
_http_client: Optional[httpx.AsyncClient] = None
_http_client_lock = asyncio.Lock()

# One lock per credential to avoid global contention during token refreshes
_refresh_locks: Dict[str, asyncio.Lock] = {}

# Loaded credential set from token.json; each entry will be enriched with access cache
_creds: List[dict] = []

# Global semaphore to limit concurrent album track fetches across all requests
_album_tracks_sem = asyncio.Semaphore(20)

# List of proxies loaded from file at startup
_proxies: List[str] = []

# Cache of the last proxy confirmed to be working
_last_known_good_proxy: Optional[str] = None

# Last Oxaam observed credential pool; refreshed on each fetch
_oxaam_observed_cred_pool: List[dict] = []
_oxaam_invalid_tidal_emails: set[str] = set()


# Known-good WebGL vendor/renderer pairs for each OS (from Camoufox docs).
# Used as fallback when fingerprint_preset=True picks a GPU not in the
# browserforge database ("No WebGL data found for vendor X").
_VALID_WEBGL_CONFIGS: dict[str, tuple] = {
    "windows": (
        "Google Inc. (NVIDIA)",
        "ANGLE (NVIDIA, NVIDIA GeForce GTX 980 Direct3D11 vs_5_0 ps_5_0), or similar",
    ),
    "macos": (
        "Apple",
        "Apple M1, or similar",
    ),
    "linux": (
        "Google Inc. (NVIDIA)",
        "ANGLE (NVIDIA, NVIDIA GeForce GTX 980 Direct3D11 vs_5_0 ps_5_0), or similar",
    ),
}

# Platform detection for headless mode selection
_IS_LINUX: bool = sys.platform.startswith("linux")


def _camoufox_kwargs(
    fingerprint_preset: bool = True,
    webgl_config: tuple | None = None,
    target_os: str = "windows",
) -> dict:
    """Return Camoufox launch kwargs with full anti-detection configuration.

    Every toggle is chosen to bypass DataDome / Cloudflare WAFs while
    staying undetectable by JavaScript inspection.

    Parameters
    ----------
    fingerprint_preset : bool
        ``True`` uses real-world device fingerprints (312 presets, 180 for
        Windows).  ``False`` falls back to browserforge-generated values.
    webgl_config : tuple | None
        Explicit ``(vendor, renderer)`` pair.  When set, overrides the
        randomly-selected WebGL fingerprint — eliminates the "No WebGL data
        found" launch error entirely.
    target_os : str
        OS to spoof ("windows", "macos", or "linux").  Also used to select
        the default webgl_config fallback when one is not passed.

    Platform behaviour
    ------------------
    - **Linux**  → ``headless="virtual"`` (spawns Xvfb virtual display) —
      the strongest anti-headless-detection guarantee per Camoufox docs.
    - **Windows** → ``headless=True`` (native headless — virtual display
      not available).
    """
    if not HAS_CAMOUFOX:
        return {}

    headless_mode: str | bool = "virtual" if _IS_LINUX else False  # headed on Windows for DataDome

    kwargs: dict = dict(
        headless=headless_mode,
        os=target_os,
        block_webrtc=True,
        disable_coop=True,
        i_know_what_im_doing=True,  # required for disable_coop (Camoufox warns without it)
        screen=_Screen(max_width=1920, max_height=1080),
        window=(1366, 768),
        geoip=True,
    )
    if fingerprint_preset:
        kwargs["fingerprint_preset"] = True
    if webgl_config is not None:
        kwargs["webgl_config"] = webgl_config
    return kwargs


def _build_http_client(proxy_url: Optional[str] = None) -> httpx.AsyncClient:
    # Pack common settings into a dictionary to keep things DRY
    client_kwargs = {
        "http2": True,
        "headers": _tidal_headers(),
        "timeout": httpx.Timeout(connect=3.0, read=12.0, write=8.0, pool=12.0),
        "limits": httpx.Limits(
            max_keepalive_connections=500,
            max_connections=1000,
            keepalive_expiry=30.0,
        ),
    }

    try:
        # Modern httpx
        return httpx.AsyncClient(proxy=proxy_url, **client_kwargs)
    except TypeError:
        # Legacy httpx
        # If proxy_url is None, proxies=None is perfectly valid.
        # If it's a string, older httpx versions require it to be a dictionary mapping.
        legacy_proxies = {"all://": proxy_url} if proxy_url else None
        return httpx.AsyncClient(proxies=legacy_proxies, **client_kwargs)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _http_client
    if DEV_MODE:
        logger.warning("DEV_MODE is enabled — upstream responses will be logged at DEBUG level")
    if _http_client is None:
        proxy_url = None
        if USE_PROXIES:
            proxy_url = await get_working_proxy()
            if not proxy_url and not FALLBACK_TO_DIRECT_CONNECTION:
                logger.error("Could not find a working proxy and FALLBACK_TO_DIRECT_CONNECTION is False. Shutting down.")
                raise RuntimeError("No working proxies available")
            elif not proxy_url and FALLBACK_TO_DIRECT_CONNECTION:
                logger.warning("Could not find a working proxy, falling back to direct connection. HOST IP MAY BE EXPOSED!")
        _http_client = _build_http_client(proxy_url)

    # Auto-login via Oxaam → password grant if no credentials were loaded from token.json / env
    if not _creds and OXAAM_EMAIL and OXAAM_PASSWORD:
        logger.info("No Tidal credentials found; fetching from Oxaam and logging in...")
        if not await _password_login():
            logger.warning("Oxaam auto-login failed. API calls will fail until credentials are available.")
    elif not _creds:
        logger.warning("No Tidal credentials loaded and OXAAM_EMAIL/OXAAM_PASSWORD not set.")

    try:
        yield
    finally:
        if _http_client:
            await _http_client.aclose()
            _http_client = None

app = FastAPI(
    title="HiFi-RestAPI",
    version=API_VERSION,
    description="Tidal Music Proxy",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Config (defaults act as fallback if token file missing)
CLIENT_ID = os.getenv("CLIENT_ID", "")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "")
REFRESH_TOKEN: Optional[str] = os.getenv("REFRESH_TOKEN")
USER_ID = os.getenv("USER_ID")
TOKEN_FILE = os.getenv("TOKEN_FILE", "token.json")
COUNTRY_CODE = os.getenv("COUNTRY_CODE", "US")
# Set your Oxaam account credentials — the app will log into oxaam.com at startup,
# scrape the Tidal (Tiedla) shared account credentials, and use them for auto-login.
# The resulting refresh_token is cached in token.json so Oxaam is only hit when needed.
OXAAM_EMAIL = os.getenv("OXAAM_EMAIL", "")
OXAAM_PASSWORD = os.getenv("OXAAM_PASSWORD", "")

USE_PROXIES = os.getenv("USE_PROXIES", "False").lower() in ("true", "1", "yes")
ROTATE_PROXIES_ON_REFRESH = os.getenv("ROTATE_PROXIES_ON_REFRESH", "False").lower() in ("true", "1", "yes")
PROXIES_FILE = os.getenv("PROXIES_FILE", "proxies.txt")
FALLBACK_TO_DIRECT_CONNECTION = os.getenv("FALLBACK_TO_DIRECT_CONNECTION", "False").lower() in ("true", "1", "yes")
# Maximum number of proxy candidates to test per get_working_proxy() call
MAX_PROXY_CANDIDATES = 10
# Maximum number of concurrent proxy tests inside get_working_proxy()
_PROXY_TEST_CONCURRENCY = 5
_max_retries_raw = os.getenv("MAX_RETRIES", "2")
USER_AGENT = os.getenv("USER_AGENT", "okhttp/5.3.2")


def _tidal_headers(extra: dict | None = None) -> dict:
    h = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Accept-Encoding": "gzip",
        "Accept-Language": "en-US,en;q=0.9",
        "X-Platform": "android",
        "X-Tidal-Platform": "android",
    }
    if extra:
        h.update(extra)
    return h


_TIDAL_DEFAULT_HEADERS = _tidal_headers()

DEV_MODE = os.getenv("DEV_MODE", "False").lower() in ("true", "1", "yes")

_RATE_LIMIT_MAX_RETRIES = 3
_RATE_LIMIT_BASE_DELAY = 1.0
_RATE_LIMIT_MAX_DELAY = 10.0

def _log_response(method: str, url: str, resp: httpx.Response):
    if not DEV_MODE:
        return
    logger.info(
        "[DEV] %s %s → %s\n  headers: %s\n  body: %s",
        method,
        url,
        resp.status_code,
        dict(resp.headers),
        resp.text[:2000],
    )

try:
    MAX_RETRIES = int(_max_retries_raw)
except ValueError:
    MAX_RETRIES = 2
if MAX_RETRIES < 1:
    MAX_RETRIES = 1
def load_proxies():
    """Load proxies from file into the global _proxies list."""
    global _proxies
    if not os.path.exists(PROXIES_FILE):
        logger.warning(f"Proxies file {PROXIES_FILE} not found.")
        _proxies = []
        return
    with open(PROXIES_FILE, "r") as f:
        _proxies = [line.strip() for line in f if line.strip()]
    logger.info(f"Loaded {len(_proxies)} proxies.")


def _random_proxy() -> str | None:
    """Return a random proxy URL from the pool, or None if empty."""
    if not _proxies:
        return None
    return random.choice(_proxies)


def _parse_proxy_for_browser(proxy_url: str) -> dict:
    """Parse a proxy URL into Camoufox-compatible config.

    Returns a dict with keys suitable for Camoufox (``server``, ``username``, ``password``).
    """
    parsed = urlparse(proxy_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 8080
    username = unquote(parsed.username) if parsed.username else None
    password = unquote(parsed.password) if parsed.password else None
    server = f"http://{host}:{port}"

    return {
        "server": server,
        "username": username,
        "password": password,
        # Full URL for Camoufox (keeps auth in URL)
        "url": proxy_url,
    }


async def test_proxy(proxy_url: str) -> bool:
    try:
        async with httpx.AsyncClient(proxy=proxy_url, timeout=5.0) as client:
            resp = await client.get("http://example.com")
            return resp.status_code == 200
    except Exception:
        return False


async def get_working_proxy(avoid_proxy: Optional[str] = None) -> Optional[str]:
    global _last_known_good_proxy

    if not _proxies:
        return None

    # Try the cached proxy first (unless it is the one we want to avoid)
    if _last_known_good_proxy and _last_known_good_proxy != avoid_proxy:
        if await test_proxy(_last_known_good_proxy):
            return _last_known_good_proxy

    shuffled_proxies = _proxies[:]
    random.shuffle(shuffled_proxies)

    if avoid_proxy:
        candidate_proxies = [p for p in shuffled_proxies if p != avoid_proxy]
        if not candidate_proxies:
            candidate_proxies = shuffled_proxies
    else:
        candidate_proxies = shuffled_proxies

    # Exclude the already-tested cached proxy and cap the candidate list
    if _last_known_good_proxy:
        candidate_proxies = [p for p in candidate_proxies if p != _last_known_good_proxy]
    candidate_proxies = candidate_proxies[:MAX_PROXY_CANDIDATES]

    # Test candidates concurrently, returning the first one that succeeds
    sem = asyncio.Semaphore(_PROXY_TEST_CONCURRENCY)
    found_event = asyncio.Event()
    selected_proxy: List[Optional[str]] = [None]

    async def probe(proxy: str) -> None:
        if found_event.is_set():
            return
        async with sem:
            if found_event.is_set():
                return
            if await test_proxy(proxy):
                if not found_event.is_set():
                    selected_proxy[0] = proxy
                    found_event.set()

    await asyncio.gather(*[probe(p) for p in candidate_proxies], return_exceptions=True)

    if selected_proxy[0]:
        _last_known_good_proxy = selected_proxy[0]
    return selected_proxy[0]

async def _delayed_close(client: httpx.AsyncClient):
    await asyncio.sleep(15)
    await client.aclose()

async def update_global_client(force_new_proxy: bool = False):
    global _http_client
    async with _http_client_lock:
        proxy_to_avoid = None
        if force_new_proxy and _http_client and _http_client.proxy:
            proxy_to_avoid = str(_http_client.proxy.url)

        proxy_url = None
        if USE_PROXIES:
            proxy_url = await get_working_proxy(avoid_proxy=proxy_to_avoid)
            if not proxy_url:
                if FALLBACK_TO_DIRECT_CONNECTION:
                    logger.warning("Could not find a working proxy, falling back to direct connection. HOST IP MAY BE EXPOSED!")
                else:
                    logger.error("Could not find a working proxy and FALLBACK_TO_DIRECT_CONNECTION is False.")
                    raise HTTPException(status_code=503, detail="Service Unavailable")

        # Only create a new client if the proxy is actually different
        current_proxy_url: Optional[str] = None
        if _http_client and _http_client.proxy:
            current_proxy_url = str(_http_client.proxy.url)
        if _http_client and current_proxy_url == proxy_url:
            return

        new_client = _build_http_client(proxy_url)
        old_client = _http_client
        _http_client = new_client

        if old_client is not None:
            asyncio.create_task(_delayed_close(old_client))


if os.path.exists(PROXIES_FILE):
    load_proxies()
if USE_PROXIES and not _proxies:
    # If USE_PROXIES was set but file didn't exist, warn
    logger.warning("USE_PROXIES enabled but no proxies loaded from %s", PROXIES_FILE)

if os.path.exists(TOKEN_FILE):
    with open(TOKEN_FILE, "r") as tok:
        token_data = json.load(tok)
        if isinstance(token_data, dict):
            token_data = [token_data]

        for entry in token_data:
            cred = {
                "client_id": entry.get("client_ID") or CLIENT_ID,
                "client_secret": entry.get("client_secret") or CLIENT_SECRET,
                "refresh_token": entry.get("refresh_token") or REFRESH_TOKEN,
                "user_id": entry.get("userID") or USER_ID,
                # Access tokens in file have unknown expiry; force refresh on first use
                "access_token": None,
                "expires_at": 0,
            }
            if cred["refresh_token"]:
                _creds.append(cred)

# Add env var credential if available and unique (simple check)
if REFRESH_TOKEN:
    env_cred = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": REFRESH_TOKEN,
        "user_id": USER_ID,
        "access_token": None,
        "expires_at": 0,
    }
    # Avoid adding duplicate if it was already loaded from file with same refresh token
    if not any(c["refresh_token"] == REFRESH_TOKEN for c in _creds):
        _creds.append(env_cred)

if _creds:
    CLIENT_ID = _creds[0]["client_id"]
    CLIENT_SECRET = _creds[0]["client_secret"]
    REFRESH_TOKEN = _creds[0]["refresh_token"]


def _pick_credential() -> dict:
    if not _creds:
        raise HTTPException(status_code=500, detail="No Tidal credentials available; populate token.json")
    active_creds = [cred for cred in _creds if not cred.get("subscription_limited")]
    return random.choice(active_creds or _creds)


def _lock_for_cred(cred: dict) -> asyncio.Lock:
    key = f"{cred['client_id']}:{cred['refresh_token']}"
    lock = _refresh_locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _refresh_locks[key] = lock
    return lock


async def get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        async with _http_client_lock:
            if _http_client is None:
                proxy_url = None
                if USE_PROXIES:
                    proxy_url = await get_working_proxy()
                    if not proxy_url and not FALLBACK_TO_DIRECT_CONNECTION:
                        raise HTTPException(status_code=503, detail="Service Unavailable")
                    elif not proxy_url and FALLBACK_TO_DIRECT_CONNECTION:
                        logger.warning("Could not find a working proxy, falling back to direct connection. HOST IP MAY BE EXPOSED!")
                _http_client = _build_http_client(proxy_url)
    return _http_client


import re as _re


async def _fetch_oxaam_curl_cffi() -> list[dict] | None:
    """Fast Oxaam extraction via curl_cffi HTTP requests.

    Uses Safari impersonation to bypass Cloudflare, performs form-based
    login, fetches freeservice.php with session cookies, and parses
    CREDENTIALS from the raw HTML.

    Returns credentials on success, ``None`` if curl_cffi is unavailable
    or the site blocks the request (WAF challenge, captcha, etc.).
    """
    if not HAS_CURL_CFFI:
        return None
    if not OXAAM_EMAIL or not OXAAM_PASSWORD:
        return None

    import json as _json

    try:
        async with _CurlSession(impersonate="safari17_0") as session:
            # 1. GET login page for session cookie + CSRF token
            login_resp = await session.get(
                "https://www.oxaam.com/login.php",
                timeout=15,
            )
            if login_resp.status_code != 200:
                logger.warning("curl_cffi: login.php returned %d", login_resp.status_code)
                return None

            # 2. POST login credentials
            login_data = {"email": OXAAM_EMAIL, "password": OXAAM_PASSWORD}
            post_resp = await session.post(
                "https://www.oxaam.com/login.php",
                data=login_data,
                timeout=15,
                allow_redirects=True,
            )
            if post_resp.status_code != 200:
                logger.warning("curl_cffi: login POST returned %d", post_resp.status_code)
                return None

            # Check if login actually succeeded
            html_lower = post_resp.text.lower()
            if "login.php" in str(post_resp.url).lower() or "invalid" in html_lower:
                logger.warning("curl_cffi: login rejected (still on login page or invalid creds)")
                return None

            logger.info("curl_cffi: login OK, fetching freeservice.php...")

            # 3. GET freeservice.php with authenticated cookies
            fs_resp = await session.get(
                "https://www.oxaam.com/freeservice.php",
                timeout=15,
            )
            if fs_resp.status_code != 200:
                logger.warning("curl_cffi: freeservice.php returned %d", fs_resp.status_code)
                return None

            html = fs_resp.text
            logger.info("curl_cffi: freeservice.php HTML size: %d chars", len(html))

            # 4. Parse CREDENTIALS (same non-greedy regex as browser path)
            all_creds: list[dict] = []
            seen_emails: set[str] = set()

            for pattern in (
                r"const\s+CREDENTIALS\s*=\s*(\[.*?\])\s*;",
                r"var\s+CREDENTIALS\s*=\s*(\[.*?\])\s*;",
                r"let\s+CREDENTIALS\s*=\s*(\[.*?\])\s*;",
                r"CREDENTIALS\s*=\s*(\[.*?\])\s*;",
            ):
                for match in _re.finditer(pattern, html, _re.DOTALL):
                    try:
                        parsed = _json.loads(match.group(1))
                        for c in parsed:
                            e = str(c.get("email", "")).strip()
                            p = str(c.get("password", "")).strip()
                            if e and p and e not in seen_emails:
                                seen_emails.add(e)
                                all_creds.append({"email": e, "password": p})
                    except _json.JSONDecodeError:
                        continue

            # Also try inline Email/Password patterns
            inline_blocks = _re.findall(
                r'Email[^<]*➜[^<]*<[^>]*data-copy="([^"]+)"[^>]*>.*?'
                r'Password[^<]*➜\s*([^\s<]{3,60})',
                html, _re.DOTALL,
            )
            for email_val, pass_val in inline_blocks:
                email_val = email_val.strip()
                pass_val = pass_val.strip()
                if "@" in email_val and email_val not in seen_emails and len(pass_val) >= 3:
                    seen_emails.add(email_val)
                    all_creds.append({"email": email_val, "password": pass_val})

            if all_creds:
                logger.info(
                    "curl_cffi: extracted %d Tidal credentials: %s",
                    len(all_creds),
                    ", ".join(c["email"] for c in all_creds[:5]),
                )
                global _oxaam_observed_cred_pool
                _oxaam_observed_cred_pool = all_creds
                return all_creds

            logger.warning("curl_cffi: no credentials found in freeservice.php HTML")
            return None

    except Exception as exc:
        logger.warning("curl_cffi: Oxaam extraction failed: %s", exc)
        return None


async def _fetch_oxaam_tidal_creds(browser=None) -> list[dict]:
    """Login to oxaam.com and scrape ALL Tidal credentials from the CREDENTIALS
    JavaScript block on freeservice.php.

    Strategy (fast path first, browser as fallback):
    1. ``curl_cffi`` HTTP with Safari impersonation — sub-second, no browser.
    2. Shared Camoufox browser when one is already running (no extra cost).
    3. Fresh Camoufox launch when nothing else is available.
    """
    import json as _json

    # ── Fast path: curl_cffi HTTP (no browser overhead) ──────────────
    creds = await _fetch_oxaam_curl_cffi()
    if creds:
        logger.info(
            "Oxaam [curl_cffi]: %d Tidal credential(s): %s",
            len(creds),
            ", ".join(c["email"] for c in creds),
        )
        return creds

    # ── Browser fallback ──────────────────────────────────────────────
    last_exc: Exception = RuntimeError("No attempts made")
    max_attempts = 1 if browser is not None else 3  # single shot with shared browser
    for attempt in range(1, max_attempts + 1):
        own_browser = None
        try:
            if browser is not None:
                cam_browser = browser
            elif not HAS_CAMOUFOX:
                raise RuntimeError("Camoufox not installed — cannot fetch Oxaam credentials")
            else:
                own_browser = AsyncCamoufox(**_camoufox_kwargs())
                cam_browser = await own_browser.__aenter__()

            creds = await _scrape_oxaam_with_browser(cam_browser, _json)

            logger.info(
                "Oxaam [browser]: %d Tidal credential(s): %s",
                len(creds),
                ", ".join(c["email"] for c in creds),
            )
            global _oxaam_observed_cred_pool
            _oxaam_observed_cred_pool = creds
            return creds

        except Exception as exc:
            last_exc = exc
            if own_browser is not None:
                with suppress(Exception):
                    await own_browser.__aexit__(None, None, None)
            logger.warning(
                "Oxaam browser fetch attempt %d/%d failed: %s — retrying in 8s",
                attempt, max_attempts, exc,
            )
            if attempt < max_attempts:
                await asyncio.sleep(8)

    raise last_exc


async def _scrape_oxaam_with_browser(browser, _json) -> list[dict]:
    """Core Oxaam scraping — robust form interaction + multi-strategy extraction.

    Handles Cloudflare JS challenges, CSRF tokens, AJAX-based logins, and
    multiple credential extraction strategies with comprehensive debugging.
    """
    page = None
    try:
        page = await browser.new_page()

        # ── 1. LOAD LOGIN PAGE & WAIT FOR JS CHALLENGES ────────────
        logger.info("Oxaam: navigating to login.php...")
        await page.goto(
            "https://www.oxaam.com/login.php",
            timeout=30_000,
            wait_until="domcontentloaded",
        )
        # Wait for any Cloudflare / JS challenge to complete
        try:
            await page.wait_for_load_state("networkidle", timeout=15_000)
        except Exception:
            pass
        await asyncio.sleep(1)

        # Debug: dump form structure
        try:
            form_info = await page.evaluate("""() => {
                const forms = document.querySelectorAll('form');
                const info = [];
                forms.forEach((f, i) => {
                    const inputs = f.querySelectorAll('input');
                    const desc = {
                        action: f.action,
                        method: f.method,
                        inputs: Array.from(inputs).map(inp => ({
                            name: inp.name, type: inp.type,
                            placeholder: inp.placeholder,
                            required: inp.required,
                        })),
                    };
                    info.push(desc);
                });
                return info;
            }""")
            logger.info("Oxaam login page forms: %s", _json.dumps(form_info, indent=2))
        except Exception as e:
            logger.warning("Oxaam: could not inspect login form: %s", e)

        # Wait for email input to be visible (may be delayed by JS)
        await page.wait_for_selector("input[name='email'], input[type='email']", timeout=15_000)

        # ── 2. FILL CREDENTIALS ─────────────────────────────────────
        # Clear first, then type slowly (bypasses naive bot detection)
        email_sel = "input[name='email']"
        try:
            await page.wait_for_selector(email_sel, timeout=3_000)
        except Exception:
            email_sel = "input[type='email']"
        await page.click(email_sel)
        await page.fill(email_sel, "")
        await page.type(email_sel, OXAAM_EMAIL, delay=50)

        pass_sel = "input[name='password']"
        try:
            await page.wait_for_selector(pass_sel, timeout=3_000)
        except Exception:
            pass_sel = "input[type='password']"
        await page.click(pass_sel)
        await page.fill(pass_sel, "")
        await page.type(pass_sel, OXAAM_PASSWORD, delay=50)
        await asyncio.sleep(0.3)

        # ── 3. SUBMIT — MULTI-STRATEGY ──────────────────────────────
        login_ok = False
        pre_submit_url = page.url

        # Strategy A: click submit button with navigation wait
        for sel in ("button[type='submit']", "input[type='submit']",
                     "button:has-text('Login')", "button:has-text('Sign in')",
                     "button:has-text('LOGIN')", "button:has-text('SIGN IN')",
                     "form button", "[type='submit']"):
            try:
                btn = page.locator(sel).first
                if await btn.count() > 0:
                    logger.info("Oxaam: clicking submit via %s", sel)
                    try:
                        async with page.expect_navigation(wait_until="domcontentloaded", timeout=15_000):
                            await btn.click()
                        login_ok = True
                        break
                    except Exception:
                        # Navigation didn't happen — could be AJAX
                        await btn.click()
                        await asyncio.sleep(3)
                        if page.url != pre_submit_url:
                            login_ok = True
                            break
            except Exception:
                continue

        # Strategy B: press Enter
        if not login_ok:
            logger.info("Oxaam: no submit button worked, trying Enter key")
            try:
                async with page.expect_navigation(wait_until="domcontentloaded", timeout=12_000):
                    await page.press(pass_sel, "Enter")
                login_ok = True
            except Exception:
                await asyncio.sleep(3)
                if page.url != pre_submit_url:
                    login_ok = True

        # Strategy C: direct form DOM submit via page.evaluate
        if not login_ok:
            logger.info("Oxaam: trying direct form submit via page.evaluate")
            try:
                result = await page.evaluate("""() => {
                    const form = document.querySelector('form');
                    if (!form) return 'no-form';
                    form.submit();
                    return 'submitted';
                }""")
                logger.info("Oxaam: direct form submit result=%s", result)
                await asyncio.sleep(4)
                login_ok = True
            except Exception as e:
                logger.warning("Oxaam: direct form submit failed: %s", e)

        # ── 4. VERIFY AUTHENTICATION ─────────────────────────────────
        post_url = page.url
        logger.info("Oxaam: post-login URL: %s (was: %s)", post_url, pre_submit_url)

        # Check multiple auth indicators
        auth_indicators = await page.evaluate("""() => {
            const body = document.body ? document.body.innerText : '';
            const html = document.documentElement.outerHTML;
            return {
                hasLogout: /logout|Logout|LOG OUT|sign out|Sign Out/i.test(body),
                hasDashboard: /dashboard|Dashboard|account|Account|profile|Profile/i.test(body),
                hasWelcome: /welcome|Welcome|success|Success/i.test(body),
                hasUserMenu: !!document.querySelector('[class*="user"], [class*="account"], [class*="profile"], [class*="avatar"]'),
                bodyLength: body.length,
                htmlLength: html.length,
                url: window.location.href,
                hasScripts: document.querySelectorAll('script').length,
                cookies: document.cookie,
            };
        }""")
        logger.info("Oxaam: auth indicators: %s", _json.dumps(auth_indicators, indent=2, default=str)[:800])

        # Check for login error messages
        try:
            body_text = await page.locator("body").inner_text()
            lower = body_text.lower()
            error_phrases = ["invalid", "incorrect", "wrong password", "wrong email",
                             "try again", "not found", "no account", "does not exist",
                             "failed", "error", "denied"]
            found_errors = [p for p in error_phrases if p in lower]
            if found_errors:
                logger.warning("Oxaam: login error indicators found: %s", found_errors)
                raise RuntimeError(
                    f"Oxaam login rejected — error indicators: {found_errors}. "
                    f"Check OXAAM_EMAIL / OXAAM_PASSWORD. URL: {page.url}"
                )
        except RuntimeError:
            raise
        except Exception:
            pass

        # If still on login.php, login definitely failed
        if "login.php" in page.url.lower() or page.url.lower().rstrip("/").endswith("/login"):
            raise RuntimeError(
                f"Oxaam login failed — still on login page ({page.url}). "
                f"Auth indicators: {auth_indicators}"
            )

        # ── 5. FETCH FREESERVICE PAGE & EXTRACT ────────────────────
        logger.info("Oxaam: login appears successful, fetching freeservice.php...")
        await page.goto(
            "https://www.oxaam.com/freeservice.php",
            timeout=20_000,
            wait_until="domcontentloaded",
        )
        try:
            await page.wait_for_load_state("networkidle", timeout=12_000)
        except Exception:
            pass
        await asyncio.sleep(1.5)

        # ── FETCH RAW HTML via browser fetch() ─────────────────
        # CRITICAL: page.content() returns serialized DOM which can be ~9KB
        # smaller than the raw HTTP response — <details> content and inline
        # <script> blocks may be stripped.  Using fetch() from within the
        # authenticated browser context gives us the COMPLETE raw HTML.
        html = await page.evaluate("fetch('/freeservice.php').then(r => r.text())")
        if not html or len(html) < 5000:
            html = await page.content()  # fallback
        logger.info("Oxaam: freeservice.php HTML size: %d chars (via fetch)", len(html))

        creds_list = None
        all_creds: list[dict] = []
        seen_emails: set[str] = set()

        # ── Strategy A: non-greedy regex for CREDENTIALS arrays ──
        # The page has <script> blocks with `const CREDENTIALS = [{...},{...}];`
        # inside <details> elements. Must use NON-GREEDY `.*?` so we stop at
        # the FIRST `];` — greedy `.*` would match across all scripts.

        for pattern in (
            r"const\s+CREDENTIALS\s*=\s*(\[.*?\])\s*;",
            r"var\s+CREDENTIALS\s*=\s*(\[.*?\])\s*;",
            r"let\s+CREDENTIALS\s*=\s*(\[.*?\])\s*;",
            r"CREDENTIALS\s*=\s*(\[.*?\])\s*;",
        ):
            for match in _re.finditer(pattern, html, _re.DOTALL):
                raw = match.group(1)
                try:
                    parsed = _json.loads(raw)
                    for c in parsed:
                        e = str(c.get("email", "")).strip()
                        p = str(c.get("password", "")).strip()
                        if e and p and e not in seen_emails:
                            seen_emails.add(e)
                            all_creds.append({"email": e, "password": p})
                    logger.info("Oxaam: regex found %d creds in CREDENTIALS block (pattern: %s)",
                                len(parsed), pattern[:35])
                except _json.JSONDecodeError:
                    continue

        # ── Strategy B: extract from data-copy attributes ──
        # Non-Tidal services have inline HTML like:
        #   <button data-copy="user@domain.com">📋</button>
        #   Password ➜ SomePass123
        # We pair each email data-copy with the nearest password data-copy or text.
        data_copy_emails = _re.findall(
            r'data-copy="([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"',
            html,
        )
        data_copy_passwords = _re.findall(
            r'data-copy="([^"@]{3,60})"',
            html,
        )
        # Pair them: find Email ➜ ... Password ➜ blocks in sequence
        inline_blocks = _re.findall(
            r'Email[^<]*➜[^<]*<[^>]*data-copy="([^"]+)"[^>]*>.*?'
            r'Password[^<]*➜\s*([^\s<]{3,60})',
            html, _re.DOTALL,
        )
        for email_val, pass_val in inline_blocks:
            email_val = email_val.strip()
            pass_val = pass_val.strip()
            if "@" in email_val and email_val not in seen_emails and len(pass_val) >= 3:
                seen_emails.add(email_val)
                all_creds.append({"email": email_val, "password": pass_val})
        if inline_blocks:
            logger.info("Oxaam: extracted %d creds from inline Email/Password patterns", len(inline_blocks))

        # ── Strategy C: visible Email ➜ / Password ➜ text patterns ──
        # For services that display credentials as plain text (Cloudflare
        # email-protected addresses get decoded by the browser)
        try:
            body = await page.locator("body").inner_text()
            # Find "Email ➜ user@domain.com" and "Password ➜ pass" pairs
            text_creds = _re.findall(
                r'Email\s*➜\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s*.*?'
                r'Password\s*➜\s*([^\s\n]{3,60})',
                body, _re.DOTALL,
            )
            for email_val, pass_val in text_creds:
                email_val = email_val.strip()
                pass_val = pass_val.strip()
                if email_val not in seen_emails and len(pass_val) >= 3:
                    seen_emails.add(email_val)
                    all_creds.append({"email": email_val, "password": pass_val})
            if text_creds:
                logger.info("Oxaam: extracted %d creds from body text Email/Password patterns", len(text_creds))
        except Exception:
            pass

        # ── Strategy D: generic email:password on same line ──
        generic_matches = _re.findall(
            r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s*[:|]\s*(\S{3,60})',
            html,
        )
        for email_val, pass_val in generic_matches:
            email_val = email_val.strip()
            pass_val = pass_val.strip().rstrip(";\"'<>")
            if email_val not in seen_emails and len(pass_val) >= 3:
                seen_emails.add(email_val)
                all_creds.append({"email": email_val, "password": pass_val})

        if all_creds:
            creds_list = all_creds
            logger.info("Oxaam: TOTAL extracted %d credentials from freeservice.php", len(all_creds))

        # Final fallback: debug dump
        if creds_list is None:
            snippet = ""
            idx = html.find("CREDENTIAL")
            if idx >= 0:
                snippet = html[max(0, idx - 200):idx + 800]
            else:
                body_text = await page.locator("body").inner_text()
                snippet = f"BODY TEXT ({len(body_text)} chars):\n{body_text[:1200]}"
            raise RuntimeError(
                f"No credentials found on freeservice.php "
                f"(URL: {page.url}, HTML: {len(html)} chars)\n"
                f"Auth indicators: {auth_indicators}\n"
                f"Page snippet:\n{snippet[:1500]}"
            )

        # ── 7. BUILD RESULT ────────────────────────────────────────
        result: list[dict] = []
        seen: set[str] = set()
        for cred in creds_list:
            email = str(cred.get("email", "")).strip()
            password = str(cred.get("password", "")).strip()
            if email and password and email not in seen:
                seen.add(email)
                result.append({"email": email, "password": password})

        if not result:
            raise RuntimeError("No valid credentials found in CREDENTIALS block")

        return result

    finally:
        if page is not None:
            with suppress(Exception):
                await page.close()


async def _tidal_http_auto_approve(verify_url: str, email: str, password: str, browser=None) -> bool:
    """Auto-approve a Tidal device link using pure HTTP (curl_cffi).

    Replicates the exact API payloads from ``offer.tidal.com.har``.
    When ``browser`` is a running Camoufox instance, DataDome cookies are
    extracted from the browser context and injected into curl_cffi requests,
    giving us browser-grade WAF bypass with HTTP speed.

    Returns True if the device link was successfully submitted.
    """
    if not HAS_CURL_CFFI:
        return False

    # Extract device code from verify_url (e.g. "link.tidal.com/ABUYN" → "ABUYN")
    device_code = verify_url.rstrip("/").rsplit("/", 1)[-1]
    full_url = verify_url if verify_url.startswith("http") else f"https://{verify_url}"

    # ── Extract DataDome cookies from Camoufox (browser-grade bypass) ──
    injected_cookies: dict[str, str] = {}
    if browser is not None:
        try:
            page = await browser.new_page()
            await page.goto(full_url, timeout=30_000, wait_until="domcontentloaded")
            try:
                await page.wait_for_load_state("networkidle", timeout=15_000)
            except Exception:
                pass
            await asyncio.sleep(1.5)

            # Check if DataDome passed
            try:
                await page.wait_for_selector("#email", timeout=20_000)
            except Exception:
                logger.warning("HTTP auto-approve: DataDome blocked in browser — cannot extract cookies")
                await page.close()
                return False

            # Extract all cookies from browser context
            browser_cookies = await page.context.cookies()
            cookie_header_parts = []
            for c in browser_cookies:
                injected_cookies[c["name"]] = c["value"]
                cookie_header_parts.append(f"{c['name']}={c['value']}")
            cookie_str = "; ".join(cookie_header_parts)

            logger.info(
                "HTTP auto-approve: extracted %d cookies from Camoufox (datadome=%s, dd=%s)",
                len(browser_cookies),
                bool(injected_cookies.get("datadome")),
                bool(injected_cookies.get("dd")),
            )

            # Get the final authorize URL from the browser
            browser_final_url = page.url
            await page.close()
        except Exception as exc:
            logger.warning("HTTP auto-approve: cookie extraction failed: %s", exc)
            injected_cookies = {}
            browser_final_url = None
    else:
        browser_final_url = None

    try:
        async with _CurlSession(impersonate="safari17_0") as session:
            # 1. Follow redirect chain to get cookies + authorize URL
            if injected_cookies:
                # Use browser-extracted cookies directly
                cookie_header = "; ".join(
                    f"{k}={v}" for k, v in injected_cookies.items()
                )
                session.headers.update({"Cookie": cookie_header})
                final_url = browser_final_url or full_url
            else:
                # No browser — try bare curl_cffi (may hit DataDome)
                resp = await session.get(
                    full_url,
                    timeout=15,
                    allow_redirects=True,
                )
                final_url = str(resp.url)

            logger.info("HTTP auto-approve: final authorize URL: %s", final_url[:120] if final_url else "?")

            # Extract query string
            qs = ""
            if final_url and "?" in final_url:
                qs = final_url.split("?", 1)[1]

            if not final_url or "login.tidal.com" not in final_url or not qs:
                logger.warning("HTTP auto-approve: unexpected redirect target: %s", (final_url or "?")[:120])
                return False

            # 2. POST /api/email — HAR entry #64/#69/#74
            email_check = await session.post(
                f"https://login.tidal.com/api/email?{qs}",
                json={"email": email},
                headers={
                    "Accept": "application/json, text/plain, */*",
                    "Origin": "https://login.tidal.com",
                    "Referer": final_url,
                },
                timeout=15,
            )
            if email_check.status_code != 200:
                logger.warning(
                    "HTTP auto-approve: /api/email returned %d for %s",
                    email_check.status_code, email,
                )
                return False

            logger.info("HTTP auto-approve: /api/email OK for %s", email)

            # 3. POST /api/email/user/existing — HAR entry #76
            login_resp = await session.post(
                f"https://login.tidal.com/api/email/user/existing?{qs}",
                json={"email": email, "password": password},
                headers={
                    "Accept": "application/json, text/plain, */*",
                    "Origin": "https://login.tidal.com",
                    "Referer": final_url,
                },
                timeout=15,
                allow_redirects=True,
            )
            if login_resp.status_code not in (200, 302):
                if login_resp.status_code in (401, 403):
                    _oxaam_invalid_tidal_emails.add(email)
                    logger.warning(
                        "HTTP auto-approve: Tidal rejected %s (status=%d)", email, login_resp.status_code,
                    )
                else:
                    logger.warning(
                        "HTTP auto-approve: login returned %d for %s", login_resp.status_code, email,
                    )
                return False

            logger.info("HTTP auto-approve: login OK for %s", email)

            # 4. Follow /success → offer.tidal.com redirect chain
            success_resp = await session.get(
                "https://login.tidal.com/success",
                timeout=15,
                allow_redirects=True,
            )
            logger.info("HTTP auto-approve: post-login URL: %s", str(success_resp.url)[:120])

            # 5. POST /api/device/link — HAR entry #104
            link_resp = await session.post(
                "https://offer.tidal.com/api/device/link",
                json={"deviceCode": device_code},
                headers={
                    "Accept": "application/json, text/plain, */*",
                    "Origin": "https://offer.tidal.com",
                    "Referer": "https://offer.tidal.com/device/link",
                },
                timeout=15,
            )

            if link_resp.status_code in (200, 201, 204):
                logger.info("HTTP auto-approve: device linked successfully for %s", email)
                return True

            logger.info(
                "HTTP auto-approve: /api/device/link returned %d (login still succeeded for %s)",
                link_resp.status_code, email,
            )
            return True

    except Exception as exc:
        logger.warning("HTTP auto-approve failed for %s: %s", email, exc)
        return False


async def _camoufox_full_approve(full_url: str, email: str, password: str,
                                 proxy_url: str | None = None) -> bool:
    """Auto-approve a Tidal device link inside Camoufox.

    Uses the proven form-interaction flow: fill + Tab to trigger Vue.js
    validation, wait_for_function for submit button enabled, Enter fallback,
    cookie banner dismissal, and multi-step consent/approval button clicking.
    """
    if not HAS_CAMOUFOX:
        return False

    label = "direct" if not proxy_url else (
        proxy_url.split("@")[-1] if "@" in proxy_url else proxy_url
    )

    # ── Helpers (battle-tested form-interaction flow) ───────────────────────
    async def _body_text(page) -> str:
        try:
            return await page.locator("body").inner_text()
        except Exception:
            return ""

    async def _visible_button_texts(page) -> list[str]:
        try:
            texts = await page.locator("button").all_text_contents()
        except Exception:
            return []
        return [" ".join(t.split()) for t in texts if t and t.strip()]

    async def _dismiss_cookie_banner(page) -> bool:
        try:
            reject = page.locator(
                "button:has-text('Reject'), button:has-text('REJECT'), "
                "button:has-text('Decline')"
            )
            if await reject.count() > 0:
                for ct in ("Accept", "ACCEPT", "OK", "Got it", "Accept all"):
                    loc = page.locator(f"button:has-text('{ct}')")
                    if await loc.count() > 0:
                        await loc.first.click()
                        return True
        except Exception:
            pass
        return False

    async def _click_first_match(page, texts: list[str]) -> str | None:
        for button_text in texts:
            for target in [page.locator("button"), page.locator("a"),
                           page.locator("[role='button']")]:
                try:
                    count = await target.count()
                    for idx in range(min(count, 12)):
                        candidate = target.nth(idx)
                        raw = await candidate.inner_text()
                        if " ".join(raw.split()).lower() == button_text.lower():
                            await candidate.scroll_into_view_if_needed(timeout=2_000)
                            await candidate.click(force=True, timeout=5_000)
                            return button_text
                except Exception:
                    continue
            for loc in [
                page.get_by_role("button", name=button_text, exact=False),
                page.get_by_role("link", name=button_text, exact=False),
                page.get_by_text(button_text, exact=False),
                page.locator(f"button:has-text('{button_text}')"),
                page.locator(f"a:has-text('{button_text}')"),
                page.locator(f"[role='button']:has-text('{button_text}')"),
            ]:
                try:
                    if await loc.count() > 0:
                        await loc.first.scroll_into_view_if_needed(timeout=2_000)
                        await loc.first.click(force=True, timeout=5_000)
                        return button_text
                except Exception:
                    continue
        return None

    async def _has_invalid_login_msg(page) -> bool:
        return "username or password is incorrect" in (await _body_text(page)).lower()

    # ── Email stage (old flow: fill → Tab → wait for enabled → click / Enter) ──
    async def _submit_email_stage(page) -> str:
        await page.wait_for_selector("#email", timeout=30_000)
        logger.info("Camoufox [%s]: DataDome passed — login page loaded", label)

        email_input = page.locator("#email")
        await email_input.fill(email)
        try:
            await email_input.press("Tab")
        except Exception:
            pass

        try:
            await page.wait_for_function(
                """() => {
                    const btn = document.querySelector("button[type='submit']");
                    return !!btn && !btn.disabled;
                }""",
                timeout=10_000,
            )
        except Exception:
            pass

        submit_button = page.locator("button[type='submit']").first
        try:
            await submit_button.click(timeout=5_000)
        except Exception:
            try:
                await email_input.press("Enter")
            except Exception:
                await submit_button.click(force=True, timeout=5_000)

        for attempt in range(20):
            password_field = page.locator("#password, input[type='password']")
            try:
                if await password_field.count() > 0 and await password_field.first.is_visible():
                    return "password"
            except Exception:
                if await password_field.count() > 0:
                    return "password"

            body_text = (await _body_text(page)).lower()
            if "username or password is incorrect" in body_text:
                return "invalid_credentials"
            if "login.tidal.com" not in page.url:
                return "redirected"

            try:
                email_visible = await email_input.is_visible()
            except Exception:
                email_visible = False
            if not email_visible:
                buttons = [t.lower() for t in await _visible_button_texts(page)]
                if any("sign up" in t for t in buttons) and not any(
                    kw in t for t in buttons
                    for kw in ("continue", "allow", "authorize", "log in")
                ):
                    return "invalid_credentials"
                return "advanced"

            if attempt == 5:
                with suppress(Exception):
                    await email_input.press("Enter")
            await asyncio.sleep(1)

        btns = await _visible_button_texts(page)
        logger.warning("Camoufox [%s]: email step stalled for %s. URL: %s  Buttons: %s",
                       label, email, page.url, btns)
        return "stuck"

    # ── Main flow ──────────────────────────────────────────────────────────
    try:
        kw = _camoufox_kwargs()
        kw["window"] = (1440, 900)
        kw["webgl_config"] = _VALID_WEBGL_CONFIGS.get(
            "linux" if _IS_LINUX else "windows",
            _VALID_WEBGL_CONFIGS["windows"],
        )
        if proxy_url:
            proxy_cfg = _parse_proxy_for_browser(proxy_url)
            kw["proxy"] = {
                "server": proxy_cfg["server"],
                "username": proxy_cfg["username"] or "",
                "password": proxy_cfg["password"] or "",
            }

        async with AsyncCamoufox(**kw) as browser:
            page = await browser.new_page()
            try:
                await page.goto(full_url, timeout=30_000, wait_until="domcontentloaded")
                try:
                    await page.wait_for_load_state("networkidle", timeout=15_000)
                except Exception:
                    pass
                await asyncio.sleep(2)

                # ── If on device page, logout for fresh login ──────────
                if "offer.tidal.com/device/" in page.url:
                    logger.info("Camoufox [%s]: existing session — logging out", label)
                    await page.goto("https://login.tidal.com/logout",
                                    timeout=15_000, wait_until="domcontentloaded")
                    await asyncio.sleep(1.5)
                    await page.goto(full_url, timeout=30_000, wait_until="domcontentloaded")
                    try:
                        await page.wait_for_load_state("networkidle", timeout=15_000)
                    except Exception:
                        pass
                    await asyncio.sleep(2)

                # ── Step 1: Email ─────────────────────────────────────
                try:
                    email_state = await _submit_email_stage(page)
                except Exception as exc:
                    logger.warning("Camoufox [%s]: email step failed: %s", label, exc)
                    return False

                if email_state == "invalid_credentials":
                    _oxaam_invalid_tidal_emails.add(email)
                    logger.warning("Camoufox [%s]: Tidal rejected %s", label, email)
                    return False
                if email_state == "stuck":
                    logger.warning("Camoufox [%s]: email step stalled for %s", label, email)
                    return False

                # ── Step 2: Password (only if email step showed the field) ──
                if email_state == "password":
                    try:
                        await page.locator(
                            "#password, input[type='password']"
                        ).first.fill(password)
                        await page.locator(
                            "button:has-text('Log In')"
                        ).first.click()
                        logger.info("Camoufox [%s]: password submitted", label)
                    except Exception as exc:
                        logger.warning("Camoufox [%s]: password step failed: %s", label, exc)
                        return False
                else:
                    logger.info("Camoufox [%s]: password skipped (state=%s, url=%s)",
                                label, email_state, page.url[:120])

                # ── Step 3: Unified consent / approval loop ─────────────
                # After email (or email+password), the page may be on:
                #   a) login.tidal.com/authorize — OAuth consent (click Continue/Allow)
                #   b) offer.tidal.com/device/link — final approval (click Allow/Approve)
                #   c) Some other intermediate page
                # This loop handles ALL states instead of the old rigid sequence
                # that deadlocked when the redirect never fired.
                CONSENT_BTNS = [
                    "Continue", "CONTINUE", "Allow", "ALLOW",
                    "Authorize", "Confirm", "OK", "Yes",
                    "Agree", "Accept", "ACCEPT",
                ]
                APPROVE_BTNS = [
                    "Allow", "ALLOW", "Approve", "APPROVE",
                    "Authorize", "Yes, allow", "Grant access",
                    "Allow access", "Link device", "Continue", "CONTINUE",
                    "OK", "Confirm", "Accept", "ACCEPT",
                ]

                clicked = False
                for _round in range(8):
                    current_url = page.url
                    btns = await _visible_button_texts(page)
                    logger.info("Camoufox [%s]: round %d — URL: %s  buttons: %s",
                                label, _round + 1,
                                current_url[:120], btns[:8] if btns else "(none)")

                    # Always dismiss cookie banners first
                    await _dismiss_cookie_banner(page)

                    # Check for invalid login (wrong password / rejected email)
                    if await _has_invalid_login_msg(page):
                        _oxaam_invalid_tidal_emails.add(email)
                        logger.warning("Camoufox [%s]: Tidal rejected %s", label, email)
                        return False

                    if "login.tidal.com" in current_url:
                        # On OAuth consent screen — click Continue / Allow
                        btn = await _click_first_match(page, CONSENT_BTNS)
                        if btn:
                            logger.info("Camoufox [%s]: clicked '%s' on consent page", label, btn)
                            try:
                                await page.wait_for_function(
                                    "() => !window.location.href.includes('login.tidal.com')",
                                    timeout=15_000,
                                )
                                logger.info("Camoufox [%s]: left login.tidal.com → %s",
                                            label, page.url[:100])
                            except Exception:
                                await page.wait_for_load_state("networkidle", timeout=10_000)
                            continue
                        else:
                            # No consent button found — page may still be loading
                            logger.info("Camoufox [%s]: on login page, no consent btn yet", label)

                    elif "offer.tidal.com" in current_url:
                        # On device approval page — click Allow / Approve
                        btn = await _click_first_match(page, APPROVE_BTNS)
                        if btn:
                            logger.info("Camoufox [%s]: clicked approval '%s'", label, btn)
                            clicked = True
                            break
                        else:
                            logger.info("Camoufox [%s]: on offer page, no approve btn yet", label)
                    else:
                        logger.info("Camoufox [%s]: unknown page — waiting for navigation", label)

                    # Settle and retry
                    try:
                        await page.wait_for_load_state("networkidle", timeout=5_000)
                    except Exception:
                        pass
                    await asyncio.sleep(1.5)

                if not clicked:
                    btns = await _visible_button_texts(page)
                    logger.warning("Camoufox [%s]: no approval btn after %d rounds. "
                                   "URL: %s  Buttons: %s",
                                   label, _round + 1, page.url[:120], btns)

                await asyncio.sleep(1)
                logger.info("Camoufox [%s]: browser done — clicked=%s for %s",
                            label, clicked, email)
                return clicked

            finally:
                await page.close()
    except Exception as exc:
        logger.warning("Camoufox [%s]: approve failed for %s: %s", label, email, exc)
        return False


async def _playwright_auto_approve(full_url: str, email: str, password: str,
                                   proxy_url: str | None = None) -> bool:
    """Playwright (Chromium) fallback for Tidal device link approval.

    Uses the same battle-tested form-interaction flow as Camoufox but
    with Chromium's anti-detection flags for sites that fingerprint Firefox.
    """
    if not HAS_PLAYWRIGHT:
        return False

    label = "direct" if not proxy_url else (
        proxy_url.split("@")[-1] if "@" in proxy_url else proxy_url
    )

    # ── Helpers (same pattern as Camoufox) ────────────────────────────────
    async def _body_text(page) -> str:
        try:
            return await page.locator("body").inner_text()
        except Exception:
            return ""

    async def _visible_button_texts(page) -> list[str]:
        try:
            texts = await page.locator("button").all_text_contents()
        except Exception:
            return []
        return [" ".join(t.split()) for t in texts if t and t.strip()]

    async def _dismiss_cookie_banner(page) -> bool:
        try:
            reject = page.locator(
                "button:has-text('Reject'), button:has-text('REJECT'), "
                "button:has-text('Decline')"
            )
            if await reject.count() > 0:
                for ct in ("Accept", "ACCEPT", "OK", "Got it", "Accept all"):
                    loc = page.locator(f"button:has-text('{ct}')")
                    if await loc.count() > 0:
                        await loc.first.click()
                        return True
        except Exception:
            pass
        return False

    async def _click_first_match(page, texts: list[str]) -> str | None:
        for button_text in texts:
            for target in [page.locator("button"), page.locator("a"),
                           page.locator("[role='button']")]:
                try:
                    count = await target.count()
                    for idx in range(min(count, 12)):
                        candidate = target.nth(idx)
                        raw = await candidate.inner_text()
                        if " ".join(raw.split()).lower() == button_text.lower():
                            await candidate.scroll_into_view_if_needed(timeout=2_000)
                            await candidate.click(force=True, timeout=5_000)
                            return button_text
                except Exception:
                    continue
            for loc in [
                page.get_by_role("button", name=button_text, exact=False),
                page.get_by_role("link", name=button_text, exact=False),
                page.get_by_text(button_text, exact=False),
                page.locator(f"button:has-text('{button_text}')"),
                page.locator(f"a:has-text('{button_text}')"),
                page.locator(f"[role='button']:has-text('{button_text}')"),
            ]:
                try:
                    if await loc.count() > 0:
                        await loc.first.scroll_into_view_if_needed(timeout=2_000)
                        await loc.first.click(force=True, timeout=5_000)
                        return button_text
                except Exception:
                    continue
        return None

    async def _has_invalid_login_msg(page) -> bool:
        return "username or password is incorrect" in (await _body_text(page)).lower()

    # ── Email stage ───────────────────────────────────────────────────────
    async def _submit_email_stage(page) -> str:
        await page.wait_for_selector("#email", timeout=30_000)
        logger.info("Playwright [%s]: DataDome passed — login page loaded", label)

        email_input = page.locator("#email")
        await email_input.fill(email)
        try:
            await email_input.press("Tab")
        except Exception:
            pass

        try:
            await page.wait_for_function(
                """() => {
                    const btn = document.querySelector("button[type='submit']");
                    return !!btn && !btn.disabled;
                }""",
                timeout=10_000,
            )
        except Exception:
            pass

        submit_button = page.locator("button[type='submit']").first
        try:
            await submit_button.click(timeout=5_000)
        except Exception:
            try:
                await email_input.press("Enter")
            except Exception:
                await submit_button.click(force=True, timeout=5_000)

        for attempt in range(20):
            password_field = page.locator("#password, input[type='password']")
            try:
                if await password_field.count() > 0 and await password_field.first.is_visible():
                    return "password"
            except Exception:
                if await password_field.count() > 0:
                    return "password"

            body_text = (await _body_text(page)).lower()
            if "username or password is incorrect" in body_text:
                return "invalid_credentials"
            if "login.tidal.com" not in page.url:
                return "redirected"

            try:
                email_visible = await email_input.is_visible()
            except Exception:
                email_visible = False
            if not email_visible:
                buttons = [t.lower() for t in await _visible_button_texts(page)]
                if any("sign up" in t for t in buttons) and not any(
                    kw in t for t in buttons
                    for kw in ("continue", "allow", "authorize", "log in")
                ):
                    return "invalid_credentials"
                return "advanced"

            if attempt == 5:
                with suppress(Exception):
                    await email_input.press("Enter")
            await asyncio.sleep(1)

        btns = await _visible_button_texts(page)
        logger.warning("Playwright [%s]: email step stalled for %s. URL: %s  Buttons: %s",
                       label, email, page.url, btns)
        return "stuck"

    # ── Main flow ──────────────────────────────────────────────────────────
    try:
        async with async_playwright() as pw:
            launch_kwargs: dict = {
                "headless": True,
                "args": [
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-blink-features=AutomationControlled",
                ],
            }
            if proxy_url:
                proxy_cfg = _parse_proxy_for_browser(proxy_url)
                launch_kwargs["proxy"] = {
                    "server": proxy_cfg["server"],
                    "username": proxy_cfg.get("username") or None,
                    "password": proxy_cfg.get("password") or None,
                }

            browser = await pw.chromium.launch(**launch_kwargs)
            context = await browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/136.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1440, "height": 900},
            )
            page = await context.new_page()
            # Strip webdriver detection
            await page.add_init_script(
                "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
            )

            try:
                await page.goto(full_url, timeout=30_000, wait_until="domcontentloaded")
                try:
                    await page.wait_for_load_state("networkidle", timeout=15_000)
                except Exception:
                    pass
                await asyncio.sleep(2)

                # ── If on device page, logout for fresh login ──────────
                if "offer.tidal.com/device/" in page.url:
                    logger.info("Playwright [%s]: existing session — logging out", label)
                    await page.goto("https://login.tidal.com/logout",
                                    timeout=15_000, wait_until="domcontentloaded")
                    await asyncio.sleep(1.5)
                    await page.goto(full_url, timeout=30_000, wait_until="domcontentloaded")
                    try:
                        await page.wait_for_load_state("networkidle", timeout=15_000)
                    except Exception:
                        pass
                    await asyncio.sleep(2)

                # ── Step 1: Email ─────────────────────────────────────
                try:
                    email_state = await _submit_email_stage(page)
                except Exception as exc:
                    logger.warning("Playwright [%s]: email step failed: %s", label, exc)
                    return False

                if email_state == "invalid_credentials":
                    _oxaam_invalid_tidal_emails.add(email)
                    logger.warning("Playwright [%s]: Tidal rejected %s", label, email)
                    return False
                if email_state == "stuck":
                    logger.warning("Playwright [%s]: email step stalled for %s", label, email)
                    return False

                # ── Step 2: Password ──────────────────────────────────
                if email_state == "password":
                    try:
                        await page.locator(
                            "#password, input[type='password']"
                        ).first.fill(password)
                        await page.locator(
                            "button:has-text('Log In')"
                        ).first.click()
                        logger.info("Playwright [%s]: password submitted", label)
                    except Exception as exc:
                        logger.warning("Playwright [%s]: password step failed: %s", label, exc)
                        return False
                else:
                    logger.info("Playwright [%s]: password skipped (state=%s, url=%s)",
                                label, email_state, page.url[:120])

                # ── Step 3: Unified consent / approval loop ────────────
                CONSENT_BTNS = [
                    "Continue", "CONTINUE", "Allow", "ALLOW",
                    "Authorize", "Confirm", "OK", "Yes",
                    "Agree", "Accept", "ACCEPT",
                ]
                APPROVE_BTNS = [
                    "Allow", "ALLOW", "Approve", "APPROVE",
                    "Authorize", "Yes, allow", "Grant access",
                    "Allow access", "Link device", "Continue", "CONTINUE",
                    "OK", "Confirm", "Accept", "ACCEPT",
                ]

                clicked = False
                for _round in range(8):
                    current_url = page.url
                    btns = await _visible_button_texts(page)
                    logger.info("Playwright [%s]: round %d — URL: %s  buttons: %s",
                                label, _round + 1,
                                current_url[:120], btns[:8] if btns else "(none)")

                    await _dismiss_cookie_banner(page)

                    if await _has_invalid_login_msg(page):
                        _oxaam_invalid_tidal_emails.add(email)
                        logger.warning("Playwright [%s]: Tidal rejected %s", label, email)
                        return False

                    if "login.tidal.com" in current_url:
                        btn = await _click_first_match(page, CONSENT_BTNS)
                        if btn:
                            logger.info("Playwright [%s]: clicked '%s' on consent page", label, btn)
                            try:
                                await page.wait_for_function(
                                    "() => !window.location.href.includes('login.tidal.com')",
                                    timeout=15_000,
                                )
                                logger.info("Playwright [%s]: left login.tidal.com → %s",
                                            label, page.url[:100])
                            except Exception:
                                await page.wait_for_load_state("networkidle", timeout=10_000)
                            continue
                        else:
                            logger.info("Playwright [%s]: on login page, no consent btn yet", label)

                    elif "offer.tidal.com" in current_url:
                        btn = await _click_first_match(page, APPROVE_BTNS)
                        if btn:
                            logger.info("Playwright [%s]: clicked approval '%s'", label, btn)
                            clicked = True
                            break
                        else:
                            logger.info("Playwright [%s]: on offer page, no approve btn yet", label)
                    else:
                        logger.info("Playwright [%s]: unknown page — waiting", label)

                    try:
                        await page.wait_for_load_state("networkidle", timeout=5_000)
                    except Exception:
                        pass
                    await asyncio.sleep(1.5)

                if not clicked:
                    btns = await _visible_button_texts(page)
                    logger.warning("Playwright [%s]: no approval btn after %d rounds. "
                                   "URL: %s  Buttons: %s",
                                   label, _round + 1, page.url[:120], btns)

                await asyncio.sleep(1)
                logger.info("Playwright [%s]: browser done — clicked=%s for %s",
                            label, clicked, email)
                return clicked

            finally:
                await context.close()
                await browser.close()
    except Exception as exc:
        logger.warning("Playwright [%s]: approve failed for %s: %s", label, email, exc)
        return False


async def _auto_approve_device_link(verify_url: str, email: str, password: str) -> bool:
    """Auto-approve a Tidal device link using ALL available browser engines.

    Phase 1: Camoufox direct → Phase 2: Camoufox + proxies (x3)
    Phase 3: Playwright direct → Phase 4: Playwright + proxies (x3)
    Phase 5: curl_cffi bare HTTP (last resort, usually blocked by DataDome).
    """
    if not HAS_CAMOUFOX and not HAS_PLAYWRIGHT:
        logger.warning("No browser engine available — falling back to curl_cffi")
        return await _tidal_http_auto_approve(verify_url, email, password, None)

    full_url = verify_url if verify_url.startswith("http") else f"https://{verify_url}"

    # ── Phase 1: Camoufox direct (no proxy) ────────────────────────────
    if HAS_CAMOUFOX:
        logger.info("Camoufox [direct]: → %s", email)
        if await _camoufox_full_approve(full_url, email, password, proxy_url=None):
            return True

    # ── Phase 2: Camoufox + proxy rotation (3 unique proxies) ──────────
    tried_proxies: set[str] = set()
    if HAS_CAMOUFOX:
        for attempt in range(3):
            proxy_url = _random_proxy()
            if proxy_url is None:
                break  # no proxies in pool
            proxy_key = proxy_url.split("@")[-1] if "@" in proxy_url else proxy_url
            if proxy_key in tried_proxies:
                continue
            tried_proxies.add(proxy_key)
            logger.info("Camoufox [proxy %d/3]: %s → %s", attempt + 1, proxy_key, email)
            if await _camoufox_full_approve(full_url, email, password, proxy_url=proxy_url):
                return True

    # ── Phase 3: Playwright direct (no proxy) ──────────────────────────
    if HAS_PLAYWRIGHT:
        logger.info("Playwright [direct]: → %s", email)
        if await _playwright_auto_approve(full_url, email, password, proxy_url=None):
            return True

    # ── Phase 4: Playwright + proxy rotation (3 unique proxies) ────────
    if HAS_PLAYWRIGHT:
        for attempt in range(3):
            proxy_url = _random_proxy()
            if proxy_url is None:
                break  # no proxies in pool
            proxy_key = proxy_url.split("@")[-1] if "@" in proxy_url else proxy_url
            if proxy_key in tried_proxies:
                continue
            tried_proxies.add(proxy_key)
            logger.info("Playwright [proxy %d/3]: %s → %s", attempt + 1, proxy_key, email)
            if await _playwright_auto_approve(full_url, email, password, proxy_url=proxy_url):
                return True

    # ── Phase 5: curl_cffi bare HTTP (last resort, usually DataDome-blocked)
    logger.info("curl_cffi fallback → %s", email)
    return await _tidal_http_auto_approve(verify_url, email, password, None)


async def _password_login() -> bool:
    """Attempt to refresh auth via device-code flow.

    1. Fetch Oxaam Tidal credentials (curl_cffi fast-path, Camoufox fallback).
    2. Start a Tidal device-code authorization for each candidate.
    3. Auto-approve via Camoufox → Playwright → proxy rotation → curl_cffi.
    4. Poll for token completion.
    5. Store the new refresh_token in TOKEN_FILE.
    """
    if not OXAAM_EMAIL or not OXAAM_PASSWORD:
        return False

    _cid = CLIENT_ID or "fX2JxdmntZWK0ixT"
    _csec = CLIENT_SECRET or "1Nm5AfDAjxrgJFJbKNWLeAyKGVGmINuXPPLHVXAvxAg="
    # Limit candidates per login attempt to avoid runaway time
    _max_candidates = int(os.getenv("MAX_CANDIDATES", "5"))

    # 1. Fetch fresh Oxaam Tidal credentials (curl_cffi → Camoufox fallback)
    try:
        creds_list = await _fetch_oxaam_tidal_creds()  # no browser = own browser lifecycle
    except Exception as e:
        logger.warning(
            "Could not fetch fresh Oxaam creds after 3 retries: %s — "
            "falling back to cached pool (%d entries)",
            e, len(_oxaam_observed_cred_pool),
        )
        creds_list = None

    # 2. Build candidate pool: prefer fresh, fall back to cached
    candidate_pool: list[dict] = []
    seen_emails: set[str] = set()
    all_candidates = creds_list or _oxaam_observed_cred_pool
    for candidate in all_candidates:
        email = str(candidate.get("email", "")).strip()
        password = str(candidate.get("password", "")).strip()
        if not email or not password or email in seen_emails or email in _oxaam_invalid_tidal_emails:
            continue
        seen_emails.add(email)
        candidate_pool.append({"email": email, "password": password})

    if not candidate_pool:
        logger.warning("Oxaam did not provide any usable Tidal credential candidates")
        return False

    # Cap candidates so we don't run forever
    candidate_pool = candidate_pool[:_max_candidates]
    logger.info(
        "Testing up to %d Tidal candidates (pool size: %d total)",
        _max_candidates, len(all_candidates),
    )

    # 3. Try each candidate in sequence
    for attempt_idx, candidate in enumerate(candidate_pool, start=1):
        tidal_user = candidate["email"]
        tidal_pass = candidate["password"]

        async with httpx.AsyncClient(headers=_tidal_headers(), timeout=httpx.Timeout(10.0)) as client:
            dev_res = await client.post(
                "https://auth.tidal.com/v1/oauth2/device_authorization",
                data={"client_id": _cid, "scope": "r_usr+w_usr+w_sub"},
            )
            dev_res.raise_for_status()
            dev_data = dev_res.json()

        device_code = dev_data["deviceCode"]
        verify_url = dev_data.get("verificationUriComplete", dev_data.get("verificationUri"))
        expires_in = dev_data.get("expiresIn", 300)
        interval = max(dev_data.get("interval", 5), 2)

        logger.info(
            "Tidal device code obtained — auto-approving via Camoufox "
            "(candidate %d/%d, account: %s, url: https://%s)",
            attempt_idx, len(candidate_pool), tidal_user, verify_url,
        )

        # Launch auto-approval task (Camoufox → Playwright → proxies → curl_cffi)
        approval_task = asyncio.create_task(
            _auto_approve_device_link(verify_url, tidal_user, tidal_pass)
        )

        deadline = time.time() + expires_in
        approval_result: Optional[bool] = None
        approval_succeeded_at: Optional[float] = None

        async with httpx.AsyncClient(headers=_tidal_headers(), timeout=httpx.Timeout(10.0)) as client:
            while time.time() < deadline:
                await asyncio.sleep(interval)

                if approval_task.done() and approval_result is None:
                    try:
                        approval_result = approval_task.result()
                    except Exception as approval_exc:
                        logger.warning("Auto-approval task failed for %s: %s", tidal_user, approval_exc)
                        approval_result = False

                    if approval_result:
                        approval_succeeded_at = time.time()
                    elif tidal_user in _oxaam_invalid_tidal_emails:
                        logger.warning("Tidal rejected Oxaam account %s; trying next candidate", tidal_user)
                        break
                    else:
                        logger.warning("Auto-approval failed for %s; trying next candidate", tidal_user)
                        break

                poll = await client.post(
                    "https://auth.tidal.com/v1/oauth2/token",
                    data={
                        "client_id": _cid,
                        "device_code": device_code,
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                        "scope": "r_usr+w_usr+w_sub",
                    },
                    auth=(_cid, _csec),
                )
                if poll.status_code == 200:
                    data = poll.json()
                    cred = {
                        "client_id": _cid,
                        "client_secret": _csec,
                        "refresh_token": data["refresh_token"],
                        "user_id": str(data["user"]["userId"]),
                        "access_token": data["access_token"],
                        "expires_at": time.time() + data.get("expires_in", 3600) - 60,
                        "subscription_limited": False,
                    }
                    _creds.append(cred)
                    entry = {
                        "access_token": data["access_token"],
                        "refresh_token": data["refresh_token"],
                        "userID": data["user"]["userId"],
                        "client_ID": _cid,
                        "client_secret": _csec,
                    }
                    existing: list = []
                    if os.path.exists(TOKEN_FILE):
                        try:
                            with open(TOKEN_FILE, "r") as f:
                                existing = json.load(f)
                            if isinstance(existing, dict):
                                existing = [existing]
                        except (ValueError, OSError):
                            existing = []
                    existing = [t for t in existing if t.get("client_ID") != _cid]
                    existing.append(entry)
                    with open(TOKEN_FILE, "w") as f:
                        json.dump(existing, f, indent=4)
                    logger.info("Device-code authorization succeeded (user_id=%s)", data["user"]["userId"])
                    if not approval_task.done():
                        approval_task.cancel()
                        with suppress(asyncio.CancelledError):
                            await approval_task
                    return True

                try:
                    err = poll.json().get("error", "")
                except ValueError:
                    err = ""

                if err == "expired_token":
                    logger.warning("Device code expired for %s", tidal_user)
                    break

                if approval_succeeded_at and time.time() - approval_succeeded_at > 30:
                    logger.error("Authorization never completed after approval for %s", tidal_user)
                    return False

        if not approval_task.done():
            approval_task.cancel()
            with suppress(asyncio.CancelledError):
                await approval_task

    logger.error("No Oxaam Tidal credential candidate produced a token.")
    return False


async def refresh_tidal_token(cred: Optional[dict] = None):
    """Refresh a token for the provided credential set."""
    cred = cred or _pick_credential()

    async with _lock_for_cred(cred):
        if cred["access_token"] and time.time() < cred["expires_at"]:
            return cred["access_token"]

        if USE_PROXIES and ROTATE_PROXIES_ON_REFRESH:
            await update_global_client(force_new_proxy=True)

        max_retries = MAX_RETRIES if USE_PROXIES else 1
        for attempt in range(max_retries):
            try:
                client = await get_http_client()
                res = await client.post(
                    "https://auth.tidal.com/v1/oauth2/token",
                    data={
                        "client_id": cred["client_id"],
                        "refresh_token": cred["refresh_token"],
                        "grant_type": "refresh_token",
                        "scope": "r_usr+w_usr+w_sub",
                    },
                    auth=(cred["client_id"], cred["client_secret"]),
                )
                _log_response("POST", "https://auth.tidal.com/v1/oauth2/token", res)

                if res.status_code in [400, 401]:
                    try:
                        error_data = res.json()
                        if error_data.get("error") in ["invalid_client", "invalid_grant"]:
                            # If the refresh token was revoked and we have password creds,
                            # re-authenticate automatically so the API self-heals.
                            if error_data.get("error") == "invalid_grant" and OXAAM_EMAIL and OXAAM_PASSWORD:
                                logger.warning("Refresh token revoked; re-authenticating via password grant...")
                                if await _password_login():
                                    return _creds[-1]["access_token"]
                            logger.error(f"Tidal Auth Error: {error_data}")
                            raise HTTPException(status_code=401, detail=f"Tidal Auth Error: {error_data.get('error_description')}")
                    except ValueError:
                        pass

                res.raise_for_status()
                data = res.json()
                new_token = data["access_token"]
                expires_in = data.get("expires_in", 3600)

                cred["access_token"] = new_token
                cred["expires_at"] = time.time() + expires_in - 60
                cred["subscription_limited"] = False

                return new_token
            except httpx.RequestError as e:
                if USE_PROXIES and attempt < max_retries - 1:
                    logger.warning(f"Proxy failed during token refresh: {e}. Healing proxy...")
                    await update_global_client(force_new_proxy=True)
                    continue
                raise HTTPException(status_code=401, detail=f"Token refresh failed: {str(e)}")
            except httpx.HTTPStatusError as e:
                if USE_PROXIES and e.response.status_code in [403, 429] and attempt < max_retries - 1:
                    logger.warning(f"Proxy blocked during token refresh ({e.response.status_code}). Healing proxy...")
                    await update_global_client(force_new_proxy=True)
                    continue
                raise HTTPException(status_code=401, detail=f"Token refresh failed: {str(e)}")


async def get_tidal_token(force_refresh: bool = False):
    return await get_tidal_token_for_cred(force_refresh=force_refresh)


async def get_tidal_token_for_cred(force_refresh: bool = False, cred: Optional[dict] = None):
    """Retrieve an access token for a specific credential; pick random if not provided."""
    cred = cred or _pick_credential()

    if not force_refresh and cred["access_token"] and time.time() < cred["expires_at"]:
        return cred["access_token"], cred

    token = await refresh_tidal_token(cred)
    return token, cred


def _is_subscription_limited(body: dict) -> bool:
    """Return True when Tidal signals the token lacks full subscription access.

    Tidal uses several signals:
    - assetPresentation == "PREVIEW"  (track is playing as a 30-s clip)
    - audioQuality == "PREVIEW"
    - subStatus 4005 / 4006  (subscription required / not entitled)
    - trackPresentation == "PREVIEW"
    - previewReason == "FULL_REQUIRES_SUBSCRIPTION"
    Any of these means the current credential is a free/expired account.
    """
    if not isinstance(body, dict):
        return False

    stack = [body]
    while stack:
        current = stack.pop()
        if not isinstance(current, dict):
            continue

        if current.get("assetPresentation") == "PREVIEW":
            return True
        if current.get("audioQuality") == "PREVIEW":
            return True
        if current.get("trackPresentation") == "PREVIEW":
            return True
        if current.get("previewReason") == "FULL_REQUIRES_SUBSCRIPTION":
            return True

        sub_status = current.get("subStatus")
        if sub_status in (4005, 4006):
            return True

        for value in current.values():
            if isinstance(value, dict):
                stack.append(value)
            elif isinstance(value, list):
                stack.extend(item for item in value if isinstance(item, dict))

    return False


async def _recover_subscription_limited_credential(url: str, cred: Optional[dict]) -> tuple[str, Optional[dict]]:
    """Handle a subscription-limited credential by rotating to a fresh account.

    1. Marks the current credential as limited so it won't be re-picked.
    2. Tries to obtain a brand-new credential via Oxaam → device-code flow.
    3. If that fails, picks any other non-limited credential from the pool.
    4. Last resort: retries the original credential (still likely limited).
    """
    if cred is not None:
        cred["subscription_limited"] = True

    # Try to get a fresh credential via Oxaam
    newest_cred = None
    if OXAAM_EMAIL and OXAAM_PASSWORD:
        logger.warning(
            "Subscription-limited response for %s — rotating account via Oxaam",
            url,
        )
        if await _password_login():
            newest_cred = _creds[-1]
            logger.info("Oxaam rotation succeeded — new account: user_id=%s", newest_cred.get("user_id"))

    # If Oxaam failed, try any other non-limited credential in the pool
    if newest_cred is None:
        active = [c for c in _creds if not c.get("subscription_limited")]
        if active:
            newest_cred = random.choice(active)
            logger.info(
                "Oxaam rotation failed — falling back to another pool credential (user_id=%s)",
                newest_cred.get("user_id"),
            )

    # Last resort: retry the original credential
    target_cred = newest_cred or cred
    token, refreshed_cred = await get_tidal_token_for_cred(force_refresh=True, cred=target_cred)
    refreshed_cred["subscription_limited"] = False
    return token, refreshed_cred


async def make_request(url: str, token: Optional[str] = None, params: Optional[dict] = None, cred: Optional[dict] = None):
    if token is None:
        token, cred = await get_tidal_token_for_cred(cred=cred)
    client = await get_http_client()
    headers = {"authorization": f"Bearer {token}"}

    try:
        for attempt in range(_RATE_LIMIT_MAX_RETRIES + 1):
            resp = await client.get(url, headers=headers, params=params)
            _log_response("GET", url, resp)

            if resp.status_code == 401:
                token, cred = await get_tidal_token_for_cred(force_refresh=True, cred=cred)
                headers = {"authorization": f"Bearer {token}"}
                resp = await client.get(url, headers=headers, params=params)
                _log_response("GET (retry after 401)", url, resp)

            if resp.status_code == 429 and attempt < _RATE_LIMIT_MAX_RETRIES:
                delay = min(_RATE_LIMIT_BASE_DELAY * (2 ** attempt), _RATE_LIMIT_MAX_DELAY)
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    try:
                        delay = min(delay, max(float(retry_after), 0))
                    except ValueError:
                        pass
                delay = min(delay, _RATE_LIMIT_MAX_DELAY)
                logger.warning("Upstream 429 for %s, retrying in %.1fs (attempt %d/%d)", url, delay, attempt + 1, _RATE_LIMIT_MAX_RETRIES)
                await asyncio.sleep(delay)
                continue

            if resp.status_code == 404:
                fresh_token, fresh_cred = await get_tidal_token_for_cred(force_refresh=True, cred=cred)
                if fresh_token != token:
                    headers = {"authorization": f"Bearer {fresh_token}"}
                    resp = await client.get(url, headers=headers, params=params)
                    _log_response("GET (retry after 404 token refresh)", url, resp)
                    token, cred = fresh_token, fresh_cred

            break

        resp.raise_for_status()
        body = resp.json()

        # If Tidal returns PREVIEW/subscription-limited content, force-refresh the token
        # and retry once — the credential may be stale or the account may no longer
        # have subscription entitlements.
        if _is_subscription_limited(body):
            token, cred = await _recover_subscription_limited_credential(url, cred)
            headers = {"authorization": f"Bearer {token}"}
            retry_resp = await client.get(url, headers=headers, params=params)
            _log_response("GET (retry after subscription-limited)", url, retry_resp)
            retry_resp.raise_for_status()
            body = retry_resp.json()

        return {"version": API_VERSION, "data": body}
    except httpx.HTTPStatusError as e:
        logger.error(
            "Upstream API error %s %s %s",
            e.response.status_code,
            url,
            e.response.text[:1000],
            exc_info=e,
        )
        raise HTTPException(status_code=e.response.status_code, detail="Upstream API error")
    except httpx.RequestError as e:
        if isinstance(e, httpx.TimeoutException):
            raise HTTPException(status_code=429, detail="Upstream timeout")
        raise HTTPException(status_code=503, detail="Connection error to Tidal")


async def authed_get_json(
    url: str,
    *,
    params: Optional[dict] = None,
    token: Optional[str] = None,
    cred: Optional[dict] = None,
):
    """Perform an authenticated GET, retrying once on 401. Returns payload with updated token/cred."""

    if token is None:
        token, cred = await get_tidal_token_for_cred(cred=cred)

    client = await get_http_client()
    headers = {"authorization": f"Bearer {token}"}

    try:
        for attempt in range(_RATE_LIMIT_MAX_RETRIES + 1):
            resp = await client.get(url, headers=headers, params=params)
            _log_response("GET", url, resp)

            if resp.status_code == 401:
                token, cred = await get_tidal_token_for_cred(force_refresh=True, cred=cred)
                headers["authorization"] = f"Bearer {token}"
                resp = await client.get(url, headers=headers, params=params)
                _log_response("GET (retry after 401)", url, resp)

            if resp.status_code == 429 and attempt < _RATE_LIMIT_MAX_RETRIES:
                delay = min(_RATE_LIMIT_BASE_DELAY * (2 ** attempt), _RATE_LIMIT_MAX_DELAY)
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    try:
                        delay = min(delay, max(float(retry_after), 0))
                    except ValueError:
                        pass
                delay = min(delay, _RATE_LIMIT_MAX_DELAY)
                logger.warning("Upstream 429 for %s, retrying in %.1fs (attempt %d/%d)", url, delay, attempt + 1, _RATE_LIMIT_MAX_RETRIES)
                await asyncio.sleep(delay)
                continue

            if resp.status_code == 404:
                fresh_token, fresh_cred = await get_tidal_token_for_cred(force_refresh=True, cred=cred)
                if fresh_token != token:
                    headers["authorization"] = f"Bearer {fresh_token}"
                    resp = await client.get(url, headers=headers, params=params)
                    _log_response("GET (retry after 404 token refresh)", url, resp)
                    token, cred = fresh_token, fresh_cred

            break

        resp.raise_for_status()
        body = resp.json()

        # If Tidal returns PREVIEW/subscription-limited content, force-refresh the token
        # and retry once — the credential may be stale or the account may no longer
        # have subscription entitlements.
        if _is_subscription_limited(body):
            token, cred = await _recover_subscription_limited_credential(url, cred)
            headers["authorization"] = f"Bearer {token}"
            retry_resp = await client.get(url, headers=headers, params=params)
            _log_response("GET (retry after subscription-limited)", url, retry_resp)
            retry_resp.raise_for_status()
            body = retry_resp.json()

        return body, token, cred
    except httpx.HTTPStatusError as e:
        logger.error(
            "Upstream API error %s %s %s",
            e.response.status_code,
            url,
            e.response.text[:1000],
            exc_info=e,
        )
        raise HTTPException(status_code=e.response.status_code, detail="Upstream API error")
    except httpx.RequestError as e:
        if isinstance(e, httpx.TimeoutException):
            raise HTTPException(status_code=429, detail="Upstream timeout")
        raise HTTPException(status_code=503, detail="Connection error to Tidal")

@app.get("/")
async def index():
    return {"version": API_VERSION, "Repo": "https://github.com/binimum/hifi-api"}

@app.get("/info/")
async def get_info(id: int):
    url = f"https://api.tidal.com/v1/tracks/{id}/"
    return await make_request(url, params={"countryCode": COUNTRY_CODE})

@app.get("/track/")
async def get_track(id: int, quality: str = "HI_RES_LOSSLESS", immersiveaudio: bool = False):
    track_url = f"https://api.tidal.com/v1/tracks/{id}/playbackinfo"
    params = {
        "audioquality": quality,
        "playbackmode": "STREAM",
        "assetpresentation": "FULL",
        "immersiveaudio": immersiveaudio
    }
    return await make_request(track_url, params=params)


@app.get("/trackManifests/")
async def get_track_manifests(
    id: str,
    request: Request,
    formats: List[str] = Query(default=["HEAACV1", "AACLC", "FLAC", "FLAC_HIRES", "EAC3_JOC"]),
    adaptive: str = Query(default="true"),
    manifestType: str = Query(default="MPEG_DASH"),
    uriScheme: str = Query(default="HTTPS"),
    usage: str = Query(default="PLAYBACK")
):
    url = f"https://openapi.tidal.com/v2/trackManifests/{id}"
    params = [
        ("adaptive", adaptive),
        ("manifestType", manifestType),
        ("uriScheme", uriScheme),
        ("usage", usage),
    ]
    for f in formats:
        params.append(("formats", f))
    res = await make_request(url, params=params)
    try:
        drm_data = res["data"]["data"]["attributes"]["drmData"]
        if drm_data:
            proxy_url = str(request.base_url).rstrip("/") + "/widevine"
            drm_data["licenseUrl"] = proxy_url
            drm_data["certificateUrl"] = proxy_url
    except (KeyError, TypeError):
        pass
    return res

# Not really necessary but I'm including it anyway
@app.api_route("/widevine", methods=["GET", "POST"])
async def widevine_proxy(request: Request):
    client = await get_http_client()
    body = await request.body()
    url = "https://api.tidal.com/v2/widevine"

    token, cred = await get_tidal_token_for_cred()
    headers = {
        "authorization": f"Bearer {token}",
        "Content-Type": request.headers.get("Content-Type", "application/octet-stream")
    }

    try:
        resp = await client.request(request.method, url, headers=headers, content=body)
        _log_response(request.method, url, resp)

        if resp.status_code == 401:
            token, cred = await get_tidal_token_for_cred(force_refresh=True, cred=cred)
            headers["authorization"] = f"Bearer {token}"
            resp = await client.request(request.method, url, headers=headers, content=body)
            _log_response(f"{request.method} (retry)", url, resp)

        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers={"Content-Type": resp.headers.get("Content-Type", "application/json")}
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail="Error communicating with widevine server")


@app.get("/recommendations/")
async def get_recommendations(id: int):
    recommendations_url = f"https://api.tidal.com/v1/tracks/{id}/recommendations"
    params = {"limit": "20", "countryCode": COUNTRY_CODE}
    return await make_request(recommendations_url, params=params)


@app.api_route("/search/", methods=["GET"])
async def search(
    s: Union[str, None] = Query(default=None),
    a: Union[str, None] = Query(default=None),
    al: Union[str, None] = Query(default=None),
    v: Union[str, None] = Query(default=None),
    p: Union[str, None] = Query(default=None),
    i: Union[str, None] = Query(default=None, description="ISRC query"),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=25, ge=1, le=500),
):
    """Search endpoint supporting track/artist/album/video/playlist queries via distinct params."""
    isrc_query = i.strip() if isinstance(i, str) else None
    if isrc_query:
        return await make_request(
            "https://api.tidal.com/v1/tracks",
            params={
                "isrc": isrc_query,
                "limit": limit,
                "offset": offset,
                "countryCode": COUNTRY_CODE,
            },
        )

    queries = (
        (s, "https://api.tidal.com/v1/search/tracks", {
            "query": s,
            "limit": limit,
            "offset": offset,
            "countryCode": COUNTRY_CODE,
        }),
        (a, "https://api.tidal.com/v1/search/top-hits", {
            "query": a,
            "limit": limit,
            "offset": offset,
            "types": "ARTISTS,TRACKS",
            "countryCode": COUNTRY_CODE,
        }),
        (al, "https://api.tidal.com/v1/search/top-hits", {
            "query": al,
            "limit": limit,
            "offset": offset,
            "types": "ALBUMS",
            "countryCode": COUNTRY_CODE,
        }),
        (v, "https://api.tidal.com/v1/search/top-hits", {
            "query": v,
            "limit": limit,
            "offset": offset,
            "types": "VIDEOS",
            "countryCode": COUNTRY_CODE,
        }),
        (p, "https://api.tidal.com/v1/search/top-hits", {
            "query": p,
            "limit": limit,
            "offset": offset,
            "types": "PLAYLISTS",
            "countryCode": COUNTRY_CODE,
        }),
    )

    for value, url, params in queries:
        if value:
            return await make_request(url, params=params)

    raise HTTPException(status_code=400, detail="Provide one of s, a, al, v, p, or i")

@app.get("/album/")
async def get_album(
    id: int = Query(..., description="Album ID"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    token, cred = await get_tidal_token_for_cred()

    album_url = f"https://api.tidal.com/v1/albums/{id}"
    items_url = f"https://api.tidal.com/v1/albums/{id}/items"

    async def fetch(url: str, params: Optional[dict] = None):
        payload, _, _ = await authed_get_json(
            url,
            params=params,
            token=token,
            cred=cred,
        )
        return payload

    tasks = [fetch(album_url, {"countryCode": COUNTRY_CODE})]

    max_chunk = 100
    current_offset = offset
    remaining_limit = limit

    while remaining_limit > 0:
        chunk_size = min(remaining_limit, max_chunk)
        tasks.append(
            fetch(items_url, {"countryCode": COUNTRY_CODE, "limit": chunk_size, "offset": current_offset})
        )
        current_offset += chunk_size
        remaining_limit -= chunk_size

    results = await asyncio.gather(*tasks)

    album_data = results[0]
    items_pages = results[1:]

    all_items = []
    for page in items_pages:
        page_items = page.get("items", page) if isinstance(page, dict) else page
        if isinstance(page_items, list):
            all_items.extend(page_items)

    album_data["items"] = all_items

    return {
        "version": API_VERSION,
        "data": album_data,
    }


@app.get("/mix/")
async def get_mix(
    id: str = Query(..., description="Mix ID")
):
    """Fetch items from a Tidal mix by its ID."""
    token, cred = await get_tidal_token_for_cred()
    url = "https://api.tidal.com/v1/pages/mix"
    params = {
        "mixId": id,
        "countryCode": COUNTRY_CODE,
        "deviceType": "BROWSER",
    }

    data, _, _ = await authed_get_json(
        url,
        params=params,
        token=token,
        cred=cred,
    )

    header = {}
    items = []

    rows = data.get("rows", [])
    for row in rows:
        modules = row.get("modules", [])
        for module in modules:
            if module.get("type") == "MIX_HEADER":
                header = module.get("mix", {})
            elif module.get("type") == "TRACK_LIST":
                paged_list = module.get("pagedList", {})
                items = paged_list.get("items", [])

    return {
        "version": API_VERSION,
        "mix": header,
        "items": [item.get("item", item) if isinstance(item, dict) else item for item in items],
    }


@app.get("/playlist/")
async def get_playlist(
    id: str = Query(..., min_length=1),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Fetch playlist metadata plus items concurrently, using shared client and single token."""

    token, cred = await get_tidal_token_for_cred()

    playlist_url = f"https://api.tidal.com/v1/playlists/{id}"
    items_url = f"https://api.tidal.com/v1/playlists/{id}/items"

    async def fetch(url: str, params: Optional[dict] = None):
        payload, _, _ = await authed_get_json(
            url,
            params=params,
            token=token,
            cred=cred,
        )
        return payload

    playlist_data, items_data = await asyncio.gather(
        fetch(playlist_url, {"countryCode": COUNTRY_CODE}),
        fetch(items_url, {"countryCode": COUNTRY_CODE, "limit": limit, "offset": offset}),
    )

    return {
        "version": API_VERSION,
        "playlist": playlist_data,
        "items": items_data.get("items", items_data) if isinstance(items_data, dict) else items_data,
    }


def _extract_uuid_from_tidal_url(href: str) -> Optional[str]:
    """Extract and reconstruct a hyphenated UUID from a Tidal resource URL."""
    parts = href.split("/") if href else []
    return "-".join(parts[4:9]) if len(parts) >= 9 else None


@app.get("/artist/similar/")
async def get_similar_artists(
    id: int = Query(..., description="Artist ID"),
    cursor: Union[int, str, None] = None
):
    """Fetch artists similar to another by its ID using V2 API."""
    url = f"https://openapi.tidal.com/v2/artists/{id}/relationships/similarArtists"
    params = {
        "page[cursor]": cursor,
        "countryCode": COUNTRY_CODE,
        "include": "similarArtists,similarArtists.profileArt"
    }

    payload, _, _ = await authed_get_json(url, params=params)
    included = payload.get("included", [])
    artists_map = {i["id"]: i for i in included if i["type"] == "artists"}
    artworks_map = {i["id"]: i for i in included if i["type"] == "artworks"}

    def resolve_artist(entry):
        aid = entry["id"]
        inc = artists_map.get(aid, {})
        attr = inc.get("attributes", {})

        pic_id = None
        if art_data := inc.get("relationships", {}).get("profileArt", {}).get("data"):
            if artwork := artworks_map.get(art_data[0].get("id")):
                if files := artwork.get("attributes", {}).get("files"):
                    pic_id = _extract_uuid_from_tidal_url(files[0].get("href"))

        return {
            **attr,
            "id": int(aid) if str(aid).isdigit() else aid,
            "picture": pic_id or attr.get("selectedAlbumCoverFallback"),
            "url": f"http://www.tidal.com/artist/{aid}",
            "relationType": "SIMILAR_ARTIST"
        }

    return {
        "version": API_VERSION,
        "artists": [resolve_artist(e) for e in payload.get("data", [])]
    }


@app.get("/album/similar/")
async def get_similar_albums(
    id: int = Query(..., description="Album ID"),
    cursor: Union[int, str, None] = None
):
    """Fetch albums similar to another by its ID using V2 API."""
    url = f"https://openapi.tidal.com/v2/albums/{id}/relationships/similarAlbums"
    params = {
        "page[cursor]": cursor,
        "countryCode": COUNTRY_CODE,
        "include": "similarAlbums,similarAlbums.coverArt,similarAlbums.artists"
    }

    payload, _, _ = await authed_get_json(url, params=params)
    included = payload.get("included", [])
    albums_map = {i["id"]: i for i in included if i["type"] == "albums"}
    artworks_map = {i["id"]: i for i in included if i["type"] == "artworks"}
    artists_map = {i["id"]: i for i in included if i["type"] == "artists"}

    def resolve_album(entry):
        aid = entry["id"]
        inc = albums_map.get(aid, {})
        attr = inc.get("attributes", {})

        cover_id = None
        if art_data := inc.get("relationships", {}).get("coverArt", {}).get("data"):
            if artwork := artworks_map.get(art_data[0].get("id")):
                if files := artwork.get("attributes", {}).get("files"):
                    cover_id = _extract_uuid_from_tidal_url(files[0].get("href"))

        artist_list = []
        if art_data := inc.get("relationships", {}).get("artists", {}).get("data"):
             for a_entry in art_data:
                 if a_obj := artists_map.get(a_entry["id"]):
                     a_id = a_obj["id"]
                     artist_list.append({
                         "id": int(a_id) if str(a_id).isdigit() else a_id,
                         "name": a_obj["attributes"]["name"]
                     })

        return {
            **attr,
            "id": int(aid) if str(aid).isdigit() else aid,
            "cover": cover_id,
            "artists": artist_list,
            "url": f"http://www.tidal.com/album/{aid}"
        }

    return {
        "version": API_VERSION,
        "albums": [resolve_album(e) for e in payload.get("data", [])]
    }


@app.get("/artist/")
async def get_artist(
    id: Optional[int] = Query(default=None),
    f: Optional[int] = Query(default=None),
    skip_tracks: bool = Query(default=False),
):
    """Artist detail or album+track aggregation.

    - id: basic artist metadata + cover URLs
    - f: fetch artist albums page and aggregate tracks across albums (capped concurrency)
    - skip_tracks: if true, returns only albums without aggregating tracks (when using 'f')
    """

    if id is None and f is None:
        raise HTTPException(status_code=400, detail="Provide id or f query param")

    token, cred = await get_tidal_token_for_cred()

    if id is not None:
        artist_url = f"https://api.tidal.com/v1/artists/{id}"
        artist_data, token, cred = await authed_get_json(
            artist_url,
            params={"countryCode": COUNTRY_CODE},
            token=token,
            cred=cred,
        )

        picture = artist_data.get("picture")
        fallback = artist_data.get("selectedAlbumCoverFallback")

        if not picture and fallback:
            artist_data["picture"] = fallback
            picture = fallback

        cover = None
        if picture:
            slug = picture.replace("-", "/")
            cover = {
                "id": artist_data.get("id"),
                "name": artist_data.get("name"),
                "750": f"https://resources.tidal.com/images/{slug}/750x750.jpg",
            }

        return {"version": API_VERSION, "artist": artist_data, "cover": cover}

    # Fetch albums and singles/EPs directly in parallel
    albums_url = f"https://api.tidal.com/v1/artists/{f}/albums"
    common_params = {"countryCode": COUNTRY_CODE, "limit": 100}

    tasks = [
        authed_get_json(albums_url, params=common_params, token=token, cred=cred),
        authed_get_json(albums_url, params={**common_params, "filter": "EPSANDSINGLES"}, token=token, cred=cred),
    ]

    if skip_tracks:
        tasks.append(
            authed_get_json(
                f"https://api.tidal.com/v1/artists/{f}/toptracks",
                params={"countryCode": COUNTRY_CODE, "limit": 15},
                token=token,
                cred=cred
            )
        )

    results = await asyncio.gather(*tasks, return_exceptions=True)

    unique_releases = []
    seen_ids = set()

    # Process albums (first 2 results)
    for res in results[:2]:
        if isinstance(res, tuple) and len(res) > 0:
            data = res[0]
            items = data.get("items", []) if isinstance(data, dict) else data
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict) and item.get("id") and item["id"] not in seen_ids:
                        unique_releases.append(item)
                        seen_ids.add(item["id"])
        elif isinstance(res, Exception):
            logger.warning("Error fetching artist releases: %s", res)

    album_ids: List[int] = [item["id"] for item in unique_releases]
    page_data = {"items": unique_releases}

    if skip_tracks:
        top_tracks = []
        if len(results) > 2:
            res = results[2]
            if isinstance(res, tuple) and len(res) > 0:
                data = res[0]
                top_tracks = data.get("items", []) if isinstance(data, dict) else data
            elif isinstance(res, Exception):
                logger.warning("Error fetching top tracks: %s", res)

        return {"version": API_VERSION, "albums": page_data, "tracks": top_tracks}

    if not album_ids:
        return {"version": API_VERSION, "albums": page_data, "tracks": []}

    async def fetch_album_tracks(album_id: int):
        async with _album_tracks_sem:
            album_data, _, _ = await authed_get_json(
                "https://api.tidal.com/v1/pages/album",
                params={
                    "albumId": album_id,
                    "countryCode": COUNTRY_CODE,
                    "deviceType": "BROWSER",
                },
                token=token,
                cred=cred,
            )

            rows = album_data.get("rows", [])
            if len(rows) < 2:
                return []
            modules = rows[1].get("modules", [])
            if not modules:
                return []
            paged_list = modules[0].get("pagedList", {})
            items = paged_list.get("items", [])
            tracks = [track.get("item", track) if isinstance(track, dict) else track for track in items]
            return tracks

    results = await asyncio.gather(
        *(fetch_album_tracks(album_id) for album_id in album_ids),
        return_exceptions=True,
    )

    tracks: List[dict] = []
    for res in results:
        if isinstance(res, Exception):
            continue
        tracks.extend(res)

    return {"version": API_VERSION, "albums": page_data, "tracks": tracks}


@app.get("/cover/")
async def get_cover(
    id: Optional[int] = Query(default=None),
    q: Optional[str] = Query(default=None),
):
    """Fetch album cover data for a track id or search query."""

    if id is None and q is None:
        raise HTTPException(status_code=400, detail="Provide id or q query param")

    token, cred = await get_tidal_token_for_cred()

    def build_cover_entry(cover_slug: str, name: Optional[str], track_id: Optional[int]):
        slug = cover_slug.replace("-", "/")
        return {
            "id": track_id,
            "name": name,
            "1280": f"https://resources.tidal.com/images/{slug}/1280x1280.jpg",
            "640": f"https://resources.tidal.com/images/{slug}/640x640.jpg",
            "80": f"https://resources.tidal.com/images/{slug}/80x80.jpg",
        }

    if id is not None:
        track_data, token, cred = await authed_get_json(
            f"https://api.tidal.com/v1/tracks/{id}/",
            params={"countryCode": COUNTRY_CODE},
            token=token,
            cred=cred,
        )

        album = track_data.get("album") or {}
        cover_slug = album.get("cover")
        if not cover_slug:
            raise HTTPException(status_code=404, detail="Cover not found")

        entry = build_cover_entry(
            cover_slug,
            album.get("title") or track_data.get("title"),
            album.get("id") or id,
        )
        return {"version": API_VERSION, "covers": [entry]}

    search_data, token, cred = await authed_get_json(
        "https://api.tidal.com/v1/search/tracks",
        params={"countryCode": COUNTRY_CODE, "query": q, "limit": 10},
        token=token,
        cred=cred,
    )

    items = search_data.get("items", [])[:10]
    if not items:
        raise HTTPException(status_code=404, detail="Cover not found")

    covers = []
    for track in items:
        album = track.get("album") or {}
        cover_slug = album.get("cover")
        if not cover_slug:
            continue
        covers.append(
            build_cover_entry(
                cover_slug,
                track.get("title"),
                track.get("id"),
            )
        )

    if not covers:
        raise HTTPException(status_code=404, detail="Cover not found")

    return {"version": API_VERSION, "covers": covers}


@app.get("/lyrics/")
async def get_lyrics(id: int):
    url = f"https://api.tidal.com/v1/tracks/{id}/lyrics"
    data, token, cred = await authed_get_json(
        url,
        params={"countryCode": COUNTRY_CODE, "locale": "en_US", "deviceType": "BROWSER"},
    )

    if not data:
        raise HTTPException(status_code=404, detail="Lyrics not found")

    return {"version": API_VERSION, "lyrics": data}


@app.get("/topvideos/")
async def get_top_videos(
    countryCode: str = Query(default="US"),
    locale: str = Query(default="en_US"),
    deviceType: str = Query(default="BROWSER"),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    """Fetch recommended videos from Tidal."""
    token, cred = await get_tidal_token_for_cred()
    url = "https://api.tidal.com/v1/pages/mymusic_recommended_videos"
    params = {
        "countryCode": countryCode,
        "locale": locale,
        "deviceType": deviceType,
    }

    data, token, cred = await authed_get_json(
        url,
        params=params,
        token=token,
        cred=cred,
    )

    rows = data.get("rows", [])
    all_videos = []
    for row in rows:
        modules = row.get("modules", [])
        for module in modules:
            module_type = module.get("type")
            if module_type in ("VIDEO_PLAYLIST", "VIDEO_ROW", "PAGED_LIST"):
                paged_list = module.get("pagedList", {})
                if paged_list:
                    items = paged_list.get("items", [])
                    for item in items:
                        video = item.get("item", item) if isinstance(item, dict) else item
                        all_videos.append(video)
            elif module_type == "VIDEO" or (module_type and "video" in module_type.lower()):
                item = module.get("item", module)
                if isinstance(item, dict):
                    all_videos.append(item)

    paginated = all_videos[offset:offset + limit]

    response = {
        "version": API_VERSION,
        "videos": paginated,
        "total": len(all_videos),
    }
    return response

@app.get("/video/")
async def get_video(
    id: int = Query(..., description="Video ID"),
    quality: str = Query(default="HIGH", description="Video quality (HIGH, MEDIUM, LOW)"),
    mode: str = Query(default="STREAM", description="Playback mode (STREAM, OFFLINE)"),
    presentation: str = Query(default="FULL", description="Asset presentation (FULL, PREVIEW)"),
):
    """Fetch video playback info from Tidal."""
    token, cred = await get_tidal_token_for_cred()
    url = f"https://api.tidal.com/v1/videos/{id}/playbackinfo"
    params = {
        "videoquality": quality,
        "playbackmode": mode,
        "assetpresentation": presentation,
    }

    data, token, cred = await authed_get_json(
        url,
        params=params,
        token=token,
        cred=cred,
    )

    return {"version": API_VERSION, "video": data}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
