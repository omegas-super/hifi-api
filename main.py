#!/usr/bin/env python3
import asyncio
import json
import os
import random
import time
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

# Last Oxaam Tiedla account selected; used to avoid sticking to the same shared
# account when Oxaam exposes more than one across reloads or fresh sessions.
_oxaam_last_selected_email: Optional[str] = None
_oxaam_observed_cred_pool: List[dict] = []
_oxaam_invalid_tidal_emails: set[str] = set()


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
OXAAM_BROWSER_SCRAPE = os.getenv("OXAAM_BROWSER_SCRAPE", "False").lower() in ("true", "1", "yes")
OXAAM_RELOAD_ATTEMPTS = max(1, int(os.getenv("OXAAM_RELOAD_ATTEMPTS", "5")))
OXAAM_RELOAD_DELAY_MS = max(0, int(os.getenv("OXAAM_RELOAD_DELAY_MS", "700")))
OXAAM_SESSION_ATTEMPTS = max(1, int(os.getenv("OXAAM_SESSION_ATTEMPTS", "3")))

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


if USE_PROXIES:
    load_proxies()

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


def _fetch_oxaam_tidal_creds_sync() -> tuple:
    """Login to oxaam.com with OXAAM_EMAIL/OXAAM_PASSWORD and scrape the Tidal
    (Tiedla) shared account email and password from the free-services page.

    Uses curl_cffi to mimic a real Chrome TLS fingerprint, bypassing Cloudflare.
    Returns (tidal_email, tidal_password) as strings.
    """
    import html as _html

    from curl_cffi.requests import Session
    global _oxaam_last_selected_email, _oxaam_observed_cred_pool

    default_headers = {
        "Cache-Control": "no-cache, no-store, max-age=0",
        "Pragma": "no-cache",
        "Referer": "https://www.oxaam.com/freeservice.php",
    }

    def _extract_tiedla_creds(page_html: str) -> list[dict]:
        tiedla_idx = page_html.find("Tiedla")
        if tiedla_idx == -1:
            raise RuntimeError("Tiedla section not found on freeservice.php — page layout may have changed")

        block = page_html[tiedla_idx : tiedla_idx + 12000]
        merged_creds: dict[str, dict] = {}

        # Prefer the structured copy-button payloads inside the Tiedla details block.
        # Oxaam renders the visible credentials as buttons with data-copy attributes,
        # which is less brittle than scraping raw text.
        data_copy_values = [
            _html.unescape(value).strip()
            for value in _re.findall(r'data-copy=["\']([^"\']+)["\']', block, _re.IGNORECASE)
        ]
        paired_creds: list[dict] = []
        for idx, value in enumerate(data_copy_values):
            if value.lower().endswith("@oxaam.in") and idx + 1 < len(data_copy_values):
                paired_creds.append({
                    "email": value,
                    "password": data_copy_values[idx + 1],
                })
        for cred in paired_creds:
            merged_creds[cred["email"]] = cred

        visible_email = _re.search(
            r'Email(?:&nbsp;|\s)*➜(?:\s|&nbsp;|<[^>]+>)*([A-Za-z0-9._%+-]+@oxaam\.in)',
            block,
            _re.IGNORECASE,
        )
        visible_password = _re.search(
            r'Password(?:&nbsp;|\s)*➜(?:\s|&nbsp;|<[^>]+>)*([^<\s]+)',
            block,
            _re.IGNORECASE,
        )
        if visible_email and visible_password:
            cred = {
                "email": _html.unescape(visible_email.group(1)).strip(),
                "password": _html.unescape(visible_password.group(1)).strip(),
            }
            merged_creds[cred["email"]] = cred

        match = _re.search(r'const CREDENTIALS\s*=\s*(\[.*?\]);', block, _re.DOTALL)
        if match:
            import json as _json

            creds_list = _json.loads(match.group(1))
            for cred in creds_list:
                email = _html.unescape(str(cred.get("email", "")).strip())
                password = _html.unescape(str(cred.get("password", "")).strip())
                if email and password:
                    merged_creds[email] = {"email": email, "password": password}

        if merged_creds:
            return list(merged_creds.values())

        raise RuntimeError("Could not find visible Tiedla credentials on freeservice.php — page layout may have changed")

    def _freeservice_url() -> str:
        return f"https://www.oxaam.com/freeservice.php?_={int(time.time() * 1000)}_{random.randint(1000, 9999)}"

    def _pick_best_cred(observed_creds: dict[str, dict], observation_order: list[str]) -> dict:
        valid_observed = {
            email: cred for email, cred in observed_creds.items()
            if email not in _oxaam_invalid_tidal_emails
        }
        if valid_observed:
            observed_creds = valid_observed
            observation_order = [email for email in observation_order if email in observed_creds]

        # Prefer a credential that only appeared after at least one reload, since the
        # first response is the most likely to be cached/stale.
        if len(observation_order) > 1:
            reload_candidates = [email for email in observation_order[1:] if email in observed_creds]
            if _oxaam_last_selected_email:
                non_reused = [email for email in reload_candidates if email != _oxaam_last_selected_email]
                if non_reused:
                    return observed_creds[non_reused[-1]]
            if reload_candidates:
                return observed_creds[reload_candidates[-1]]
        if _oxaam_last_selected_email:
            non_reused = [email for email in observation_order if email != _oxaam_last_selected_email and email in observed_creds]
            if non_reused:
                return observed_creds[non_reused[-1]]
        return observed_creds[observation_order[-1]]

    observed_creds: dict[str, dict] = {}
    observation_order: list[str] = []
    for session_idx in range(OXAAM_SESSION_ATTEMPTS):
        with Session(impersonate="chrome131") as session:
            # 1. GET the login page first to pick up any session cookies
            session.get("https://www.oxaam.com/login.php", timeout=20)

            # 2. POST login credentials
            login_res = session.post(
                "https://www.oxaam.com/login.php",
                data={"email": OXAAM_EMAIL, "password": OXAAM_PASSWORD},
                headers={
                    "Origin": "https://www.oxaam.com",
                    "Referer": "https://www.oxaam.com/login.php",
                },
                allow_redirects=True,
                timeout=20,
            )
            if "login.php" in login_res.url:
                raise RuntimeError(
                    "Oxaam login failed — check OXAAM_EMAIL and OXAAM_PASSWORD"
                )

            # 3. Fetch free-services page (session cookie is carried automatically)
            fs_res = session.get(_freeservice_url(), headers=default_headers, timeout=20)
            creds_list = _extract_tiedla_creds(fs_res.text)
            for cred in creds_list:
                observed_creds[cred["email"]] = cred
                observation_order.append(cred["email"])
            previous_email = creds_list[0].get("email", "unknown")

            for reload_idx in range(OXAAM_RELOAD_ATTEMPTS):
                refresh_res = session.get(
                    _freeservice_url(),
                    headers=default_headers,
                    timeout=20,
                )
                refreshed_creds = _extract_tiedla_creds(refresh_res.text)
                if not refreshed_creds:
                    continue

                current_email = refreshed_creds[0].get("email", "unknown")
                logger.info(
                    "Oxaam session %d/%d reload %d/%d: %s -> %s",
                    session_idx + 1,
                    OXAAM_SESSION_ATTEMPTS,
                    reload_idx + 1,
                    OXAAM_RELOAD_ATTEMPTS,
                    previous_email,
                    current_email,
                )
                previous_email = current_email
                for cred in refreshed_creds:
                    observed_creds[cred["email"]] = cred
                    observation_order.append(cred["email"])

                if OXAAM_RELOAD_DELAY_MS:
                    time.sleep((OXAAM_RELOAD_DELAY_MS + random.randint(0, 250)) / 1000.0)

    creds_list = list(observed_creds.values())
    logger.info(
        "Oxaam observed %d Tiedla account(s): %s",
        len(creds_list),
        ", ".join(sorted(cred["email"] for cred in creds_list)),
    )

    selected_cred = _pick_best_cred(observed_creds, observation_order)
    _oxaam_last_selected_email = selected_cred["email"]
    _oxaam_observed_cred_pool = [selected_cred] + [
        cred for email, cred in observed_creds.items() if email != selected_cred["email"]
    ]
    tidal_email = selected_cred["email"]
    tidal_password = selected_cred["password"]
    return tidal_email, tidal_password


async def _fetch_oxaam_tidal_creds_browser() -> tuple:
    """Scrape the live Tiedla credentials from Oxaam using a real browser session."""
    def _parse_creds(text: str) -> Optional[tuple[str, str]]:
        email_match = _re.search(r"Email\s*➜\s*([^\s]+@oxaam\.in)", text, _re.IGNORECASE)
        password_match = _re.search(r"Password\s*➜\s*([^\s]+)", text, _re.IGNORECASE)
        if email_match and password_match:
            return email_match.group(1).strip(), password_match.group(1).strip()
        return None

    async def _collect_with_page(page) -> tuple:
        await page.goto("https://www.oxaam.com/login.php", wait_until="domcontentloaded", timeout=30_000)
        inputs = page.locator("input:not([type='hidden']):visible")
        await inputs.nth(0).fill(OXAAM_EMAIL)
        await inputs.nth(1).fill(OXAAM_PASSWORD)
        sign_in = page.locator("button:has-text('Sign in')")
        if await sign_in.count() == 0:
            sign_in = page.locator("button[type='submit']")
        await sign_in.first.click()
        await page.wait_for_function("() => !location.href.includes('login.php')", timeout=20_000)

        await page.goto("https://www.oxaam.com/freeservice.php", wait_until="domcontentloaded", timeout=30_000)
        more_services = page.locator("button:has-text('Click here for more free services')")
        if await more_services.count() > 0:
            try:
                await more_services.first.click(timeout=5_000)
            except Exception:
                pass

        observed_creds: dict[str, tuple[str, str]] = {}
        previous_email = "unknown"
        for attempt in range(4):
            details = page.locator("details").filter(has_text="Tiedla").first
            await details.wait_for(state="attached", timeout=10_000)
            details_text = (await details.text_content()) or ""
            parsed = _parse_creds(details_text)
            if not parsed:
                raise RuntimeError("Could not parse Tiedla credentials from Oxaam browser page")

            email, password = parsed
            observed_creds[email] = (email, password)
            if attempt > 0:
                logger.info("Oxaam browser reload: %s -> %s", previous_email, email)
            previous_email = email

            if attempt < 3:
                await page.reload(wait_until="domcontentloaded", timeout=30_000)

        emails = sorted(observed_creds)
        logger.info("Oxaam browser observed %d Tiedla account(s): %s", len(emails), ", ".join(emails))
        return random.choice(list(observed_creds.values()))

    try:
        from camoufox.async_api import AsyncCamoufox

        async with AsyncCamoufox(headless=True, os="windows") as browser:
            page = await browser.new_page()
            return await _collect_with_page(page)
    except Exception as camoufox_exc:
        logger.warning("Oxaam camoufox scrape failed: %s — falling back to patchright browser", camoufox_exc)

    from patchright.async_api import async_playwright

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        try:
            page = await browser.new_page(viewport={"width": 1280, "height": 900})
            return await _collect_with_page(page)
        finally:
            await browser.close()


async def _fetch_oxaam_tidal_creds() -> tuple:
    """Async wrapper — runs the blocking curl_cffi scrape in a thread pool, with retries."""
    loop = asyncio.get_event_loop()
    last_exc: Exception = RuntimeError("No attempts made")
    for attempt in range(1, 4):
        try:
            if OXAAM_BROWSER_SCRAPE:
                try:
                    tidal_email, tidal_password = await _fetch_oxaam_tidal_creds_browser()
                except Exception as browser_exc:
                    logger.warning("Oxaam browser scrape failed: %s — falling back to curl session", browser_exc)
                    tidal_email, tidal_password = await loop.run_in_executor(
                        None, _fetch_oxaam_tidal_creds_sync
                    )
            else:
                tidal_email, tidal_password = await loop.run_in_executor(
                    None, _fetch_oxaam_tidal_creds_sync
                )
            logger.info("Fetched Tidal credentials from Oxaam (account: %s)", tidal_email)
            return tidal_email, tidal_password
        except Exception as exc:
            last_exc = exc
            logger.warning("Oxaam fetch attempt %d/3 failed: %s — retrying in 8s", attempt, exc)
            if attempt < 3:
                await asyncio.sleep(8)
    raise last_exc


async def _auto_approve_device_link(verify_url: str, email: str, password: str) -> bool:
    """Auto-approve a Tidal device link fully inside a bot-detection-bypassing browser.

    PRIMARY: camoufox (patched Firefox, true headless, no Xvfb needed)
    ===================================================================
    camoufox patches Firefox's internals to remove all automation signals that
    DataDome, Cloudflare, and similar systems detect. Works in headless=True mode
    on Railway/Linux without any virtual display — no DISPLAY env var, no Xvfb.
    https://github.com/daijro/camoufox

    FALLBACK: patchright (patched Chromium, requires display)
    ==========================================================
    Used if camoufox is not installed. Requires headless=False with either
    Xvfb on Linux (DISPLAY=:99) or an off-screen window on Windows.
    """
    full_url = verify_url if verify_url.startswith("http") else f"https://{verify_url}"

    async def _read_body_text(page) -> str:
        try:
            return await page.locator("body").inner_text()
        except Exception:
            return ""

    async def _visible_button_texts(page) -> list[str]:
        try:
            texts = await page.locator("button").all_text_contents()
        except Exception:
            return []
        return [" ".join(text.split()) for text in texts if text and text.strip()]

    async def _submit_email_stage(page, browser_name: str) -> str:
        await page.wait_for_selector("#email", timeout=30_000)
        logger.info("%s: DataDome passed — login page loaded", browser_name)

        email_input = page.locator("#email")
        await email_input.fill(email)
        try:
            await email_input.press("Tab")
        except Exception:
            pass

        try:
            await page.wait_for_function(
                """
                () => {
                    const button = document.querySelector("button[type='submit']");
                    return !!button && !button.disabled;
                }
                """,
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

            body_text = (await _read_body_text(page)).lower()
            if "username or password is incorrect" in body_text:
                return "invalid_credentials"
            if "login.tidal.com" not in page.url:
                return "redirected"

            try:
                email_visible = await email_input.is_visible()
            except Exception:
                email_visible = False
            if not email_visible:
                buttons = [text.lower() for text in await _visible_button_texts(page)]
                if any("sign up" in text for text in buttons) and not any(
                    keyword in text
                    for text in buttons
                    for keyword in ("continue", "allow", "authorize", "log in")
                ):
                    return "invalid_credentials"
                return "advanced"

            if attempt == 5:
                with suppress(Exception):
                    await email_input.press("Enter")

            await asyncio.sleep(1)

        buttons = await _visible_button_texts(page)
        logger.warning(
            "%s: email step stalled for %s. URL: %s Buttons: %s",
            browser_name,
            email,
            page.url,
            buttons,
        )
        return "stuck"

    # ---- Try camoufox first (true headless, no Xvfb) ----
    try:
        from camoufox.async_api import AsyncCamoufox
        logger.info("Camoufox: starting headless Firefox to approve device link %s", full_url)
        async with AsyncCamoufox(headless=True, os="windows") as browser:
            page = await browser.new_page()
            await page.goto(full_url, timeout=30_000, wait_until="domcontentloaded")
            import asyncio as _asyncio
            # Give DataDome time to run its JS challenge before looking for the form
            try:
                await page.wait_for_load_state("networkidle", timeout=15_000)
            except Exception:
                pass
            await _asyncio.sleep(2)

            # --- Step 1: email ---
            try:
                email_state = await _submit_email_stage(page, "Camoufox")
            except Exception as e:
                logger.warning("Camoufox: email field not found (%s) — falling back to patchright", e)
                raise  # triggers fallback

            if email_state == "invalid_credentials":
                _oxaam_invalid_tidal_emails.add(email)
                logger.warning("Camoufox: Tidal rejected Oxaam credentials for %s", email)
                return False
            if email_state == "stuck":
                raise RuntimeError(f"Camoufox email step stalled for {email}")

            # --- Step 2: password ---
            if email_state == "password":
                try:
                    await page.locator("#password, input[type='password']").first.fill(password)
                    await page.locator("button:has-text('Log In')").first.click()
                    logger.info("Camoufox: password submitted — waiting for redirect")
                except Exception as e:
                    logger.warning("Camoufox: password field not found: %s", e)
                    raise
            else:
                logger.info(
                    "Camoufox: password step skipped after email submit (state=%s, url=%s)",
                    email_state,
                    page.url,
                )

            # --- Step 3: wait for redirect away from login.tidal.com ---
            # The login page is login.tidal.com/authorize. After login it redirects
            # through offer.tidal.com before reaching the device approval page.
            # A cookie banner may block the redirect — dismiss it first if needed.
            async def _dismiss_cookie_banner() -> bool:
                """Click Accept only when Reject is also present (cookie banner pattern)."""
                try:
                    reject = page.locator("button:has-text('Reject'), button:has-text('REJECT'), button:has-text('Decline')")
                    if await reject.count() > 0:
                        for ct in ("Accept", "ACCEPT", "OK", "Got it", "Accept all"):
                            loc = page.locator(f"button:has-text('{ct}')")
                            if await loc.count() > 0:
                                await loc.first.click()
                                logger.info("Camoufox: dismissed cookie banner ('%s')", ct)
                                return True
                except Exception:
                    pass
                return False

            async def _has_invalid_login_message() -> bool:
                body_text = await _read_body_text(page)
                return "username or password is incorrect" in body_text.lower()

            redirected = False
            for _wait_round in range(3):
                try:
                    # wait_for_function polls JS — safe cross-origin check
                    await page.wait_for_function(
                        "() => !window.location.href.includes('login.tidal.com')",
                        timeout=10_000,
                    )
                    redirected = True
                    break
                except Exception:
                    # Still on login.tidal.com — try dismissing cookie banner then retry
                    await _dismiss_cookie_banner()
                    if await _has_invalid_login_message():
                        _oxaam_invalid_tidal_emails.add(email)
                        logger.warning("Camoufox: Tidal rejected Oxaam credentials for %s", email)
                        return False
                    await _asyncio.sleep(1)

            if redirected:
                logger.info("Camoufox: redirected away from login → %s", page.url)
            else:
                if await _has_invalid_login_message():
                    _oxaam_invalid_tidal_emails.add(email)
                    logger.warning("Camoufox: Tidal rejected Oxaam credentials for %s", email)
                    return False
                logger.warning("Camoufox: still on login page after 30s. URL: %s", page.url)
                try:
                    btns = await page.locator("button").all_text_contents()
                    logger.warning("Camoufox: visible buttons: %s", btns)
                except Exception:
                    pass

            # --- Step 4: wait for page to fully settle (multiple hops allowed) ---
            try:
                await page.wait_for_load_state("networkidle", timeout=20_000)
            except Exception:
                pass

            # Dismiss cookie banner on destination page too
            await _dismiss_cookie_banner()
            await _asyncio.sleep(1)

            current_url = page.url
            logger.info("Camoufox: approval page → %s", current_url)

            # --- Step 5: advance through any remaining consent screens until the
            # final device approval page is reached. Continue on login.tidal.com is
            # an intermediate step and must not be treated as completion.
            async def _click_first_match(texts: list[str]) -> Optional[str]:
                for button_text in texts:
                    exact_targets = [
                        page.locator("button"),
                        page.locator("a"),
                        page.locator("[role='button']"),
                    ]
                    for target in exact_targets:
                        try:
                            count = await target.count()
                            for idx in range(min(count, 12)):
                                candidate = target.nth(idx)
                                raw_text = await candidate.inner_text()
                                normalized = " ".join(raw_text.split())
                                if normalized.lower() == button_text.lower():
                                    await candidate.scroll_into_view_if_needed(timeout=2_000)
                                    await candidate.click(force=True, timeout=5_000)
                                    return button_text
                        except Exception:
                            continue

                    locators = [
                        page.get_by_role("button", name=button_text, exact=False),
                        page.get_by_role("link", name=button_text, exact=False),
                        page.get_by_text(button_text, exact=False),
                        page.locator(f"button:has-text('{button_text}')"),
                        page.locator(f"a:has-text('{button_text}')"),
                        page.locator(f"[role='button']:has-text('{button_text}')"),
                    ]
                    for loc in locators:
                        try:
                            if await loc.count() > 0:
                                await loc.first.scroll_into_view_if_needed(timeout=2_000)
                                await loc.first.click(force=True, timeout=5_000)
                                return button_text
                        except Exception:
                            continue
                return None

            clicked = False
            for _step in range(3):
                current_url = page.url
                if "login.tidal.com" in current_url:
                    if await _has_invalid_login_message():
                        _oxaam_invalid_tidal_emails.add(email)
                        logger.warning("Camoufox: Tidal rejected Oxaam credentials for %s", email)
                        return False
                    intermediate = await _click_first_match([
                        "Continue", "CONTINUE", "Allow", "ALLOW", "Authorize", "Confirm", "OK",
                    ])
                    if intermediate:
                        logger.info(
                            "Camoufox: clicked intermediate consent button '%s' on %s",
                            intermediate,
                            current_url,
                        )
                        try:
                            await page.wait_for_function(
                                "() => !window.location.href.includes('login.tidal.com')",
                                timeout=15_000,
                            )
                            logger.info("Camoufox: advanced beyond login → %s", page.url)
                        except Exception:
                            try:
                                await page.wait_for_load_state("networkidle", timeout=10_000)
                            except Exception:
                                pass
                            await _dismiss_cookie_banner()
                            if await _has_invalid_login_message():
                                _oxaam_invalid_tidal_emails.add(email)
                                logger.warning("Camoufox: Tidal rejected Oxaam credentials for %s", email)
                                return False
                        continue

                final_button = await _click_first_match([
                    "Allow", "ALLOW", "Approve", "APPROVE",
                    "Authorize", "Yes, allow", "Grant access",
                    "Allow access", "Link device", "Continue", "CONTINUE",
                    "OK", "Confirm",
                ])
                if final_button:
                    logger.info("Camoufox: clicked approval button '%s'", final_button)
                    clicked = True
                    break

                try:
                    await page.wait_for_load_state("networkidle", timeout=5_000)
                except Exception:
                    pass
                await _dismiss_cookie_banner()

            if not clicked:
                try:
                    btns = await page.locator("button").all_text_contents()
                    logger.warning("Camoufox: no approval button found. Visible buttons: %s  URL: %s", btns, current_url)
                except Exception:
                    logger.warning("Camoufox: no approval button found. URL: %s", current_url)

            await _asyncio.sleep(2)
            logger.info("Camoufox: browser closed for %s", email)
            return clicked

    except ImportError:
        logger.info("camoufox not installed — falling back to patchright")
    except Exception as exc:
        logger.warning("Camoufox failed (%s) — falling back to patchright", exc)

    # ---- Fallback: patchright (non-headless, needs Xvfb on Linux) ----
    try:
        from patchright.async_api import async_playwright, TimeoutError as PlaywrightTimeout
    except ImportError:
        logger.warning("Neither camoufox nor patchright installed — cannot auto-approve")
        return False

    import os as _os
    import random as _random

    fp_binary = _os.environ.get("FINGERPRINT_CHROMIUM_PATH", "")
    using_fp_chrome = fp_binary and _os.path.isfile(fp_binary)
    fp_seed = _random.randint(1000, 99999)

    launch_args = [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--window-position=-32000,-32000",
        "--window-size=1280,800",
    ]
    if using_fp_chrome:
        launch_args += [
            f"--fingerprint={fp_seed}",
            "--fingerprint-platform=windows",
            "--fingerprint-brand=Chrome",
            "--fingerprint-brand-version=136",
        ]
        logger.info("Patchright fallback: using fingerprint-chromium binary (seed=%d)", fp_seed)
    else:
        logger.info("Patchright fallback: using bundled Chromium")

    launch_kwargs: dict = dict(
        headless=False,
        args=launch_args,
    )
    if using_fp_chrome:
        launch_kwargs["executable_path"] = fp_binary

    logger.info("Patchright: starting browser to approve device link %s", full_url)
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(**launch_kwargs)
            ctx = await browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/136.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1280, "height": 800},
            )
            page = await ctx.new_page()
            await page.goto(full_url, timeout=30_000, wait_until="domcontentloaded")
            await asyncio.sleep(3)

            try:
                email_state = await _submit_email_stage(page, "Patchright")
            except PlaywrightTimeout:
                logger.warning("Patchright: email field not found (DataDome blocked)")
                await browser.close()
                return False
            except Exception as exc:
                logger.warning("Patchright: email step failed (%s)", exc)
                await browser.close()
                return False

            if email_state == "invalid_credentials":
                _oxaam_invalid_tidal_emails.add(email)
                logger.warning("Patchright: Tidal rejected Oxaam credentials for %s", email)
                await browser.close()
                return False
            if email_state == "stuck":
                await browser.close()
                return False

            if email_state == "password":
                try:
                    await page.locator("#password, input[type='password']").first.fill(password)
                    await page.locator("button:has-text('Log In')").first.click()
                    await asyncio.sleep(4)
                    logger.info("Patchright: password submitted")
                except PlaywrightTimeout:
                    logger.warning("Patchright: password field not found")
                    await browser.close()
                    return False
            else:
                logger.info(
                    "Patchright: password step skipped after email submit (state=%s, url=%s)",
                    email_state,
                    page.url,
                )

            # --- Step 3: wait for redirect away from login.tidal.com ---
            async def _patchright_dismiss_cookie():
                try:
                    reject = page.locator("button:has-text('Reject'), button:has-text('Decline')")
                    if await reject.count() > 0:
                        for ct in ("Accept", "ACCEPT", "OK", "Got it", "Accept all"):
                            loc = page.locator(f"button:has-text('{ct}')")
                            if await loc.count() > 0:
                                await loc.first.click()
                                logger.info("Patchright: dismissed cookie banner ('%s')", ct)
                                return True
                except Exception:
                    pass
                return False

            async def _patchright_has_invalid_login_message() -> bool:
                body_text = await _read_body_text(page)
                return "username or password is incorrect" in body_text.lower()

            redirected = False
            for _round in range(3):
                try:
                    await page.wait_for_function(
                        "() => !window.location.href.includes('login.tidal.com')",
                        timeout=10_000,
                    )
                    redirected = True
                    break
                except PlaywrightTimeout:
                    await _patchright_dismiss_cookie()
                    if await _patchright_has_invalid_login_message():
                        _oxaam_invalid_tidal_emails.add(email)
                        logger.warning("Patchright: Tidal rejected Oxaam credentials for %s", email)
                        await browser.close()
                        return False
                    await asyncio.sleep(1)

            logger.info("Patchright: post-login page → %s (redirected=%s)", page.url, redirected)

            if not redirected and await _patchright_has_invalid_login_message():
                _oxaam_invalid_tidal_emails.add(email)
                logger.warning("Patchright: Tidal rejected Oxaam credentials for %s", email)
                await browser.close()
                return False

            try:
                await page.wait_for_load_state("networkidle", timeout=15_000)
            except PlaywrightTimeout:
                pass

            # Dismiss cookie banner on destination page
            await _patchright_dismiss_cookie()
            await asyncio.sleep(1)

            logger.info("Patchright: approval page → %s", page.url)

            async def _patchright_click_first_match(texts: list[str]) -> Optional[str]:
                for button_text in texts:
                    exact_targets = [
                        page.locator("button"),
                        page.locator("a"),
                        page.locator("[role='button']"),
                    ]
                    for target in exact_targets:
                        try:
                            count = await target.count()
                            for idx in range(min(count, 12)):
                                candidate = target.nth(idx)
                                raw_text = await candidate.inner_text()
                                normalized = " ".join(raw_text.split())
                                if normalized.lower() == button_text.lower():
                                    await candidate.scroll_into_view_if_needed(timeout=2_000)
                                    await candidate.click(force=True, timeout=5_000)
                                    return button_text
                        except Exception:
                            continue

                    locators = [
                        page.get_by_role("button", name=button_text, exact=False),
                        page.get_by_role("link", name=button_text, exact=False),
                        page.get_by_text(button_text, exact=False),
                        page.locator(f"button:has-text('{button_text}')"),
                        page.locator(f"a:has-text('{button_text}')"),
                        page.locator(f"[role='button']:has-text('{button_text}')"),
                    ]
                    for loc in locators:
                        try:
                            if await loc.count() > 0:
                                await loc.first.scroll_into_view_if_needed(timeout=2_000)
                                await loc.first.click(force=True, timeout=5_000)
                                return button_text
                        except Exception:
                            continue
                return None

            clicked = False
            for _step in range(3):
                current_url = page.url
                if "login.tidal.com" in current_url:
                    if await _patchright_has_invalid_login_message():
                        _oxaam_invalid_tidal_emails.add(email)
                        logger.warning("Patchright: Tidal rejected Oxaam credentials for %s", email)
                        await browser.close()
                        return False
                    intermediate = await _patchright_click_first_match([
                        "Continue", "CONTINUE", "Allow", "ALLOW", "Authorize", "Confirm", "OK",
                    ])
                    if intermediate:
                        logger.info(
                            "Patchright: clicked intermediate consent button '%s' on %s",
                            intermediate,
                            current_url,
                        )
                        try:
                            await page.wait_for_function(
                                "() => !window.location.href.includes('login.tidal.com')",
                                timeout=15_000,
                            )
                            logger.info("Patchright: advanced beyond login → %s", page.url)
                        except PlaywrightTimeout:
                            try:
                                await page.wait_for_load_state("networkidle", timeout=10_000)
                            except PlaywrightTimeout:
                                pass
                            await _patchright_dismiss_cookie()
                            if await _patchright_has_invalid_login_message():
                                _oxaam_invalid_tidal_emails.add(email)
                                logger.warning("Patchright: Tidal rejected Oxaam credentials for %s", email)
                                await browser.close()
                                return False
                        continue

                final_button = await _patchright_click_first_match([
                    "Allow", "ALLOW", "Approve", "APPROVE",
                    "Authorize", "Yes, allow", "Grant access",
                    "Allow access", "Link device", "Continue", "CONTINUE",
                    "OK", "Confirm",
                ])
                if final_button:
                    logger.info("Patchright: clicked approval button '%s'", final_button)
                    clicked = True
                    break

                try:
                    await page.wait_for_load_state("networkidle", timeout=5_000)
                except PlaywrightTimeout:
                    pass
                await _patchright_dismiss_cookie()

            if not clicked:
                try:
                    btns = await page.locator("button").all_text_contents()
                    logger.warning("Patchright: no approve button found. Visible buttons: %s", btns)
                except Exception:
                    logger.warning("Patchright: no approve button found")

            await asyncio.sleep(2)
            await browser.close()
            logger.info("Patchright: browser closed for %s", email)
            return clicked

    except Exception as exc:
        logger.warning("Patchright auto-approval error: %s", exc)
        return False


async def _password_login() -> bool:
    """Attempt to refresh auth via device-code flow.

    1. Scrapes Oxaam to get the Tidal account credentials.
    2. Starts a Tidal device-code authorization.
    3. Launches a headless Playwright browser to auto-approve the link.
    4. Falls back to printing the URL for manual approval if Playwright fails.
    5. Polls for up to 5 minutes for authorization.
    6. On approval, stores the new refresh_token in TOKEN_FILE.

    Returns True if a new token was obtained, False otherwise.
    """
    if not OXAAM_EMAIL or not OXAAM_PASSWORD:
        return False

    # Fetch Tidal credentials from Oxaam (email + password used for auto browser approval)
    tidal_pass = ""
    tidal_user = "unknown"
    try:
        tidal_user, tidal_pass = await _fetch_oxaam_tidal_creds()
    except Exception as e:
        logger.warning("Could not fetch Oxaam creds after 3 retries: %s", e)
        logger.warning("Cannot auto-approve device link without Tidal credentials — aborting login attempt")
        return False

    candidate_pool: list[dict] = []
    seen_emails: set[str] = set()
    for candidate in _oxaam_observed_cred_pool or [{"email": tidal_user, "password": tidal_pass}]:
        email = str(candidate.get("email", "")).strip()
        password = str(candidate.get("password", "")).strip()
        if not email or not password or email in seen_emails or email in _oxaam_invalid_tidal_emails:
            continue
        seen_emails.add(email)
        candidate_pool.append({"email": email, "password": password})

    if not candidate_pool and tidal_user != "unknown" and tidal_pass:
        candidate_pool.append({"email": tidal_user, "password": tidal_pass})

    if not candidate_pool:
        logger.warning("Oxaam did not provide any usable Tidal credential candidates")
        return False

    _cid = CLIENT_ID or "fX2JxdmntZWK0ixT"
    _csec = CLIENT_SECRET or "1Nm5AfDAjxrgJFJbKNWLeAyKGVGmINuXPPLHVXAvxAg="

    try:
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
                "Tidal device code obtained — launching headless browser to auto-approve "
                "(candidate %d/%d, account: %s, url: https://%s)",
                attempt_idx,
                len(candidate_pool),
                tidal_user,
                verify_url,
            )

            approval_task: Optional[asyncio.Task] = None
            if tidal_pass:
                approval_task = asyncio.create_task(
                    _auto_approve_device_link(verify_url, tidal_user, tidal_pass)
                )
            else:
                logger.warning(
                    "\n\n======================================================================\n"
                    "TIDAL RE-AUTH REQUIRED (Oxaam account: %s)\n"
                    "Open this URL in a browser that is already logged in to that account:\n"
                    "  https://%s\n"
                    "Waiting up to %d seconds for authorization...\n"
                    "======================================================================\n",
                    tidal_user, verify_url, expires_in,
                )

            deadline = time.time() + expires_in
            approval_result: Optional[bool] = None
            approval_succeeded_at: Optional[float] = None
            async with httpx.AsyncClient(headers=_tidal_headers(), timeout=httpx.Timeout(10.0)) as client:
                while time.time() < deadline:
                    await asyncio.sleep(interval)

                    if approval_task and approval_task.done() and approval_result is None:
                        try:
                            approval_result = approval_task.result()
                        except Exception as approval_exc:
                            logger.warning("Auto-approval task failed for %s: %s", tidal_user, approval_exc)
                            approval_result = False

                        if approval_result:
                            approval_succeeded_at = time.time()
                        elif tidal_user in _oxaam_invalid_tidal_emails:
                            logger.warning(
                                "Tidal rejected Oxaam account %s; trying the next candidate",
                                tidal_user,
                            )
                            break
                        else:
                            logger.warning(
                                "Auto-approval failed before authorization completed for %s; trying the next candidate",
                                tidal_user,
                            )
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
                        return True

                    try:
                        err = poll.json().get("error", "")
                    except ValueError:
                        err = ""

                    if err == "expired_token":
                        logger.warning("Device code expired before authorization for %s", tidal_user)
                        break

                    if approval_succeeded_at and time.time() - approval_succeeded_at > 30:
                        logger.error(
                            "Authorization never completed after approval for %s",
                            tidal_user,
                        )
                        return False

            if approval_task and not approval_task.done():
                approval_task.cancel()
                with suppress(asyncio.CancelledError):
                    await approval_task

        logger.error("No Oxaam Tidal credential candidate produced a token.")
        return False
    except Exception as e:
        logger.error("Device-code login failed: %s", e)
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
    if cred is not None:
        cred["subscription_limited"] = True

    newest_cred = None
    if OXAAM_EMAIL and OXAAM_PASSWORD:
        logger.warning(
            "Subscription-limited response detected for %s — re-authenticating via Oxaam to rotate account",
            url,
        )
        if await _password_login():
            newest_cred = _creds[-1]

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
