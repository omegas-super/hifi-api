import asyncio
import httpx
from patchright.async_api import async_playwright

CLIENT_ID = "fX2JxdmntZWK0ixT"
CLIENT_SECRET = "1Nm5AfDAjxrgJFJbKNWLeAyKGVGmINuXPPLHVXAvxAg="

async def main():
    # Get a fresh device code first
    async with httpx.AsyncClient(timeout=10) as hx:
        r = await hx.post(
            "https://auth.tidal.com/v1/oauth2/device_authorization",
            data={"client_id": CLIENT_ID, "scope": "r_usr+w_usr+w_sub"},
        )
        r.raise_for_status()
        dev = r.json()
    verify = dev.get("verificationUriComplete", dev.get("verificationUri"))
    device_code = dev["deviceCode"]
    full_url = f"https://{verify}" if not verify.startswith("http") else verify
    print(f"Fresh device URL: {full_url}")
    print(f"Device code: {device_code}")

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=False,   # non-headless bypasses DataDome detection
            args=["--no-sandbox", "--window-position=0,0", "--window-size=1,1"],
        )
        ctx = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            viewport={"width": 1280, "height": 800},
        )
        page = await ctx.new_page()
        await page.goto(full_url, timeout=30000, wait_until="domcontentloaded")
        await asyncio.sleep(5)
        print("URL after load:", page.url)
        print("Title:", await page.title())
        html = await page.content()
        print("HTML snippet:", html[:500])
        inputs = await page.query_selector_all("input")
        for inp in inputs:
            t = await inp.get_attribute("type")
            n = await inp.get_attribute("name")
            pid = await inp.get_attribute("id")
            ph = await inp.get_attribute("placeholder")
            print(f"  input type={t} name={n} id={pid} placeholder={ph}")
        buttons = await page.query_selector_all("button")
        for btn in buttons:
            txt = await btn.inner_text()
            btype = await btn.get_attribute("type")
            bdt = await btn.get_attribute("data-test")
            print(f"  button type={btype} data-test={bdt} text={txt!r}")
        # Try filling the form
        print("Filling email...")
        await page.fill("#email", "teeda1112@oxaam.in")
        await page.locator("button[type='submit']").first.click()
        await asyncio.sleep(4)
        print("After email submit, URL:", page.url)
        inputs2 = await page.query_selector_all("input")
        for inp in inputs2:
            t = await inp.get_attribute("type")
            pid = await inp.get_attribute("id")
            ph = await inp.get_attribute("placeholder")
            print(f"  input type={t} id={pid} placeholder={ph}")
        buttons2 = await page.query_selector_all("button")
        for btn in buttons2:
            txt = await btn.inner_text()
            bdt = await btn.get_attribute("data-test")
            print(f"  button data-test={bdt} text={txt!r}")

asyncio.run(main())

