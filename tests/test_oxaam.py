"""Quick test of Oxaam curl_cffi extraction."""
import asyncio, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

import logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

from main import _fetch_oxaam_curl_cffi, _scrape_oxaam_with_browser, _camoufox_kwargs, OXAAM_EMAIL, OXAAM_PASSWORD

print(f"OXAAM_EMAIL: {OXAAM_EMAIL}")
print(f"OXAAM_PASSWORD: {OXAAM_PASSWORD[:4]}****")

async def test_curl_cffi():
    print("\n=== TEST 1: curl_cffi extraction ===")
    try:
        creds = await _fetch_oxaam_curl_cffi()
        if creds:
            print(f"SUCCESS: {len(creds)} credentials extracted")
            for i, c in enumerate(creds):
                pw = c['password']
                print(f"  [{i+1}] {c['email']} / {pw[:8]}...")
            return creds
        else:
            print("FAILED: No credentials extracted")
            return []
    except Exception as e:
        print(f"ERROR: {e}")
        return []

async def test_browser():
    print("\n=== TEST 2: Browser extraction (Camoufox fallback) ===")
    import json as _json
    try:
        from camoufox.async_api import AsyncCamoufox
        async with AsyncCamoufox(**_camoufox_kwargs(
            fingerprint_preset=True,
            webgl_config=("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 980 Direct3D11 vs_5_0 ps_5_0), or similar")
        )) as browser:
            creds = await _scrape_oxaam_with_browser(browser, _json)
            if creds:
                print(f"SUCCESS: {len(creds)} credentials extracted")
                for i, c in enumerate(creds):
                    pw = c['password']
                    print(f"  [{i+1}] {c['email']} / {pw[:8]}...")
                return creds
            else:
                print("FAILED: No credentials extracted")
                return []
    except Exception as e:
        print(f"ERROR: {e}")
        return []

async def main():
    # Test curl_cffi first
    creds = await test_curl_cffi()

    if not creds:
        # Fallback: browser extraction
        creds = await test_browser()

    if creds:
        print(f"\n=== SUMMARY ===")
        print(f"Total Tidal credentials available: {len(creds)}")
        unique_passwords = set(c['password'] for c in creds)
        print(f"Unique passwords: {len(unique_passwords)}")
        for pw in unique_passwords:
            emails = [c['email'] for c in creds if c['password'] == pw]
            print(f"  Password '{pw[:8]}...' -> {len(emails)} accounts")
    else:
        print("\n=== EXTRACTION FAILED ===")

asyncio.run(main())
