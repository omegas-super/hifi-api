"""
Test script to find the correct header combinations for Tidal API.
Tests both api.tidal.com (V1) and openapi.tidal.com (V2) endpoints.
"""
import asyncio
import json
import os
import sys
import aiohttp

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

# Load token from token.json
TOKEN_FILE = "token.json"
token = None
if os.path.exists(TOKEN_FILE):
    with open(TOKEN_FILE) as f:
        data = json.load(f)
        if isinstance(data, list) and data:
            token = data[0].get("access_token")

if not token:
    print("ERROR: No access token in token.json")
    sys.exit(1)

print(f"Token: {token[:30]}...")

# Test URLs
TEST_V1 = "https://api.tidal.com/v1/tracks/194567102/"  # simple V1 endpoint
TEST_V2 = "https://openapi.tidal.com/v2/artists/9321197/relationships/similarArtists"  # V2 endpoint (similar artists)
TEST_PARAMS_V2 = {"countryCode": "US", "include": "similarArtists,similarArtists.profileArt"}

async def test_request(session, label, url, params=None, headers=None):
    """Make a request and report status."""
    try:
        async with session.get(url, params=params, headers=headers or {}, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            body = await resp.text()
            status = resp.status
            body_preview = body[:200].replace("\n", " ")
            if status == 200:
                print(f"  ✅ {label}: {status} - {body_preview}")
            else:
                print(f"  ❌ {label}: {status} - {body_preview}")
            return status
    except Exception as e:
        print(f"  ❌ {label}: ERROR - {e}")
        return 0


async def main():
    print("\n" + "=" * 70)
    print("TESTING HEADER COMBINATIONS FOR TIDAL API")
    print("=" * 70)

    # ── Test 1: V1 endpoint (api.tidal.com) ──
    print("\n── V1 API (api.tidal.com) ──")
    async with aiohttp.ClientSession() as s:
        await test_request(s, "V1: No headers (just auth)", TEST_V1,
                           params={"countryCode": "US"})

        await test_request(s, "V1: Tidal Android headers", TEST_V1,
                           params={"countryCode": "US"},
                           headers={
                               "authorization": f"Bearer {token}",
                               "User-Agent": "okhttp/5.3.2",
                               "Accept": "*/*",
                               "X-Platform": "android",
                           })

        await test_request(s, "V1: Full headers + Origin", TEST_V1,
                           params={"countryCode": "US"},
                           headers={
                               "authorization": f"Bearer {token}",
                               "User-Agent": "okhttp/5.3.2",
                               "Accept": "*/*",
                               "Accept-Encoding": "gzip",
                               "Accept-Language": "en-US,en;q=0.9",
                               "X-Platform": "android",
                               "X-Tidal-Platform": "android",
                               "Origin": "https://tidal.com",
                               "Referer": "https://tidal.com/",
                           })

    # ── Test 2: V2 endpoint (openapi.tidal.com) — the one that fails ──
    print("\n── V2 API (openapi.tidal.com) — Similar Artists ──")

    header_sets = [
        ("No headers", {
            "authorization": f"Bearer {token}",
        }),
        ("+ User-Agent", {
            "authorization": f"Bearer {token}",
            "User-Agent": "okhttp/5.3.2",
        }),
        ("+ User-Agent + Accept", {
            "authorization": f"Bearer {token}",
            "User-Agent": "okhttp/5.3.2",
            "Accept": "*/*",
        }),
        ("+ User-Agent + Origin", {
            "authorization": f"Bearer {token}",
            "User-Agent": "okhttp/5.3.2",
            "Origin": "https://tidal.com",
        }),
        ("+ User-Agent + Origin + Referer", {
            "authorization": f"Bearer {token}",
            "User-Agent": "okhttp/5.3.2",
            "Origin": "https://tidal.com",
            "Referer": "https://tidal.com/",
        }),
        ("+ User-Agent + Accept + Origin + Referer", {
            "authorization": f"Bearer {token}",
            "User-Agent": "okhttp/5.3.2",
            "Accept": "*/*",
            "Origin": "https://tidal.com",
            "Referer": "https://tidal.com/",
        }),
        ("+ User-Agent + Accept + Origin + Referer + vnd.api+json", {
            "authorization": f"Bearer {token}",
            "User-Agent": "okhttp/5.3.2",
            "Accept": "application/vnd.api+json",
            "Origin": "https://tidal.com",
            "Referer": "https://tidal.com/",
        }),
        ("Full Tidal headers", {
            "authorization": f"Bearer {token}",
            "User-Agent": "okhttp/5.3.2",
            "Accept": "*/*",
            "Accept-Encoding": "gzip",
            "Accept-Language": "en-US,en;q=0.9",
            "X-Platform": "android",
            "X-Tidal-Platform": "android",
            "Origin": "https://tidal.com",
            "Referer": "https://tidal.com/",
        }),
        ("Chrome browser UA + Origin", {
            "authorization": f"Bearer {token}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Accept": "application/vnd.api+json",
            "Origin": "https://tidal.com",
            "Referer": "https://tidal.com/",
        }),
        ("Web client UA + Origin", {
            "authorization": f"Bearer {token}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Accept": "*/*",
            "Origin": "https://tidal.com",
            "Referer": "https://tidal.com/",
        }),
        ("Minimal: auth + Accept + Origin", {
            "authorization": f"Bearer {token}",
            "Accept": "*/*",
            "Origin": "https://tidal.com",
        }),
        ("auth + Origin + Referer (no UA)", {
            "authorization": f"Bearer {token}",
            "Origin": "https://tidal.com",
            "Referer": "https://tidal.com/",
        }),
    ]

    async with aiohttp.ClientSession() as s:
        for label, hdrs in header_sets:
            await test_request(s, f"V2: {label}", TEST_V2, params=TEST_PARAMS_V2, headers=hdrs)

    # ── Test 3: With session (like aiohttp ClientSession) ──
    print("\n── V2 with session-level headers ──")
    session_headers = {
        "User-Agent": "okhttp/5.3.2",
        "Accept": "*/*",
        "Accept-Encoding": "gzip",
        "Accept-Language": "en-US,en;q=0.9",
        "X-Platform": "android",
        "X-Tidal-Platform": "android",
    }
    async with aiohttp.ClientSession(headers=session_headers) as s:
        # Per-request: just auth + Origin (session provides UA, Accept, etc.)
        await test_request(s, "V2: session UA + per-req auth+Origin", TEST_V2,
                           params=TEST_PARAMS_V2,
                           headers={"authorization": f"Bearer {token}", "Origin": "https://tidal.com"})

        # Per-request: auth only (session has UA)
        await test_request(s, "V2: session UA + per-req auth only", TEST_V2,
                           params=TEST_PARAMS_V2,
                           headers={"authorization": f"Bearer {token}"})

    # ── Test 4: Album similar ──
    print("\n── V2: Album Similar ──")
    TEST_ALBUM_V2 = "https://openapi.tidal.com/v2/albums/134858516/relationships/similarAlbums"
    TEST_PARAMS_ALBUM = {"countryCode": "US", "include": "similarAlbums,similarAlbums.coverArt,similarAlbums.artists"}
    async with aiohttp.ClientSession() as s:
        await test_request(s, "V2 Album: session UA + auth + Origin", TEST_ALBUM_V2,
                           params=TEST_PARAMS_ALBUM,
                           headers={
                               "authorization": f"Bearer {token}",
                               "User-Agent": "okhttp/5.3.2",
                               "Accept": "*/*",
                               "Origin": "https://tidal.com",
                               "Referer": "https://tidal.com/",
                           })

    print("\n" + "=" * 70)
    print("DONE")
    print("=" * 70)


asyncio.run(main())
