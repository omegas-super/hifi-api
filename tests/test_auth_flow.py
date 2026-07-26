"""
Standalone test: Oxaam credential extraction → Tidal device-code auto-approve.
Uses random accounts from Oxaam pool, Camoufox + proxies, retry on failure.
Run:  python -m tests.test_auth_flow
"""
import asyncio
import json
import os
import random
import sys
import time
import logging

if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("test_auth")

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

from main import (
    OXAAM_EMAIL, OXAAM_PASSWORD,
    _fetch_oxaam_curl_cffi, _fetch_oxaam_tidal_creds,
    _auto_approve_device_link, _password_login,
    _creds, _oxaam_observed_cred_pool,
    _oxaam_invalid_tidal_emails, load_proxies, _proxies,
    USE_PROXIES,
)
import httpx
from main import _tidal_headers

_CID = "fX2JxdmntZWK0ixT"
_CSEC = "1Nm5AfDAjxrgJFJbKNWLeAyKGVGmINuXPPLHVXAvxAg="


async def fetch_oxaam_pool():
    """Step 1: Get ALL Tidal credentials from Oxaam."""
    logger.info("=" * 60)
    logger.info("STEP 1: Fetching Oxaam Tidal credential pool")
    logger.info("=" * 60)

    try:
        creds = await _fetch_oxaam_curl_cffi()
        if creds:
            logger.info("curl_cffi extracted %d credentials:", len(creds))
            for c in creds[:8]:
                logger.info("   %s / %s", c["email"], c["password"][:4] + "****")
            return creds
    except Exception as e:
        logger.warning("curl_cffi failed: %s", e)

    try:
        creds = await _fetch_oxaam_tidal_creds()
        if creds:
            logger.info("Browser extracted %d credentials:", len(creds))
            for c in creds[:8]:
                logger.info("   %s / %s", c["email"], c["password"][:4] + "****")
            return creds
    except Exception as e:
        logger.warning("Browser extraction failed: %s", e)

    return []


async def get_fresh_device_code():
    """Get a fresh Tidal device code."""
    async with httpx.AsyncClient(headers=_tidal_headers(), timeout=httpx.Timeout(10.0)) as client:
        dev_res = await client.post(
            "https://auth.tidal.com/v1/oauth2/device_authorization",
            data={"client_id": _CID, "scope": "r_usr+w_usr+w_sub"},
        )
        dev_res.raise_for_status()
        dev_data = dev_res.json()
        return {
            "deviceCode": dev_data["deviceCode"],
            "verifyUrl": dev_data.get("verificationUriComplete", dev_data.get("verificationUri")),
            "expiresIn": dev_data.get("expiresIn", 300),
            "interval": max(dev_data.get("interval", 5), 2),
        }


async def poll_for_token(device_code, timeout_sec=280):
    """Poll Tidal token endpoint until success or timeout."""
    async with httpx.AsyncClient(headers=_tidal_headers(), timeout=httpx.Timeout(10.0)) as client:
        deadline = time.time() + timeout_sec
        attempt = 0
        while time.time() < deadline:
            await asyncio.sleep(3)
            attempt += 1
            poll = await client.post(
                "https://auth.tidal.com/v1/oauth2/token",
                data={
                    "client_id": _CID,
                    "device_code": device_code,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "scope": "r_usr+w_usr+w_sub",
                },
                auth=(_CID, _CSEC),
            )
            if poll.status_code == 200:
                data = poll.json()
                logger.info("TOKEN OBTAINED! user_id=%s", data["user"]["userId"])
                return data
            try:
                err = poll.json().get("error", "")
            except ValueError:
                err = ""
            if err == "expired_token":
                logger.warning("Device code expired at attempt %d", attempt)
                return None
            if attempt % 5 == 0:
                logger.info("  Poll attempt %d: %s", attempt, err or poll.status_code)
    return None


async def try_single_credential(email, password, proxy_url=None):
    """Try one Tidal credential: device-code → approve → poll token.
    Returns (success, token_data_or_None, error_msg).
    """
    label = proxy_url.split("@")[-1].split(":")[0] if proxy_url and "@" in proxy_url else "direct"

    # 1. Get fresh device code
    dc = await get_fresh_device_code()
    full_url = f"https://{dc['verifyUrl']}"
    logger.info("[%s] Device code for %s: %s → %s", label, email, dc["deviceCode"][:12], full_url)

    # 2. Auto-approve via Camoufox
    t0 = time.time()
    ok = await _auto_approve_device_link(full_url, email, password)
    elapsed = time.time() - t0
    logger.info("[%s] Approval for %s: %s (%.1fs)", label, email, ok, elapsed)

    if ok != "success":
        return False, None, ok

    # 3. Poll for token
    token_data = await poll_for_token(dc["deviceCode"], timeout_sec=120)
    if token_data:
        return True, token_data, None
    return False, None, "poll_timeout"


async def main():
    logger.info("=" * 60)
    logger.info("TIDAL AUTH FLOW TEST — Camoufox + Proxies + Random Accounts")
    logger.info("=" * 60)

    # Load proxies
    if os.path.exists("proxies.txt"):
        load_proxies()
    logger.info("Proxies loaded: %d", len(_proxies))

    # Step 1: Fetch Oxaam credential pool
    pool = await fetch_oxaam_pool()
    if not pool:
        logger.error("No Oxaam credentials available. Aborting.")
        return

    # Filter out previously invalid emails
    valid_pool = [c for c in pool if c["email"] not in _oxaam_invalid_tidal_emails]
    logger.info("Valid pool: %d / %d (filtered %d invalid)",
                len(valid_pool), len(pool), len(pool) - len(valid_pool))

    if not valid_pool:
        logger.error("All credentials are invalid. Aborting.")
        return

    # Shuffle for random selection
    random.shuffle(valid_pool)

    # Step 2: Try up to 5 random credentials
    MAX_ATTEMPTS = min(5, len(valid_pool))
    for attempt_idx in range(MAX_ATTEMPTS):
        cred = valid_pool[attempt_idx % len(valid_pool)]
        email = cred["email"]
        password = cred["password"]

        logger.info("=" * 60)
        logger.info("ATTEMPT %d/%d — Account: %s", attempt_idx + 1, MAX_ATTEMPTS, email)
        logger.info("=" * 60)

        # Pick a random proxy if proxies are available
        proxy_url = None
        if _proxies:
            proxy_url = random.choice(_proxies)
            logger.info("Using proxy: %s", proxy_url.split("@")[-1] if "@" in proxy_url else proxy_url[:60])

        try:
            success, token_data, error = await try_single_credential(email, password, proxy_url)
        except Exception as e:
            logger.error("Exception for %s: %s", email, e, exc_info=True)
            success, token_data, error = False, None, str(e)

        if success:
            logger.info("=" * 60)
            logger.info("SUCCESS! Token obtained from attempt %d", attempt_idx + 1)
            logger.info("  user_id: %s", token_data["user"]["userId"])
            logger.info("  access_token: %s...", token_data["access_token"][:40])
            logger.info("  refresh_token: %s...", token_data["refresh_token"][:40])
            logger.info("=" * 60)

            # Save to token.json
            entry = {
                "access_token": token_data["access_token"],
                "refresh_token": token_data["refresh_token"],
                "userID": token_data["user"]["userId"],
                "client_ID": _CID,
                "client_secret": _CSEC,
            }
            existing = []
            if os.path.exists("token.json"):
                try:
                    with open("token.json") as f:
                        existing = json.load(f)
                    if isinstance(existing, dict):
                        existing = [existing]
                except (ValueError, OSError):
                    existing = []
            existing.append(entry)
            with open("token.json", "w") as f:
                json.dump(existing, f, indent=4)
            logger.info("Saved token to token.json (%d total entries)", len(existing))
            return

        # Mark as invalid and continue
        _oxaam_invalid_tidal_emails.add(email)
        logger.info("Account %s failed (%s). Trying next...", email, error)

        # Brief delay before next attempt
        await asyncio.sleep(2)

    logger.error("=" * 60)
    logger.error("ALL %d ATTEMPTS FAILED", MAX_ATTEMPTS)
    logger.error("Tried: %s", ", ".join(c["email"] for c in valid_pool[:MAX_ATTEMPTS]))
    logger.error("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
