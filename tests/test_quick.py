"""Quick all-endpoints test."""
import asyncio, aiohttp, json

BASE = "http://localhost:8000"
ENDPOINTS = [
    ("Root",               "/"),
    ("Info",               "/info/?id=194567102"),
    ("Track",              "/track/?id=194567102"),
    ("Search",             "/search/?s=daft+punk"),
    ("Album",              "/album/?id=56681092"),
    ("Artist",             "/artist/?id=9321197"),
    ("Similar Artists",    "/artist/similar/?id=9321197"),
    ("Similar Albums",     "/album/similar/?id=134858516"),
    ("Cover",              "/cover/?id=194567102"),
    ("Recommendations",    "/recommendations/?id=194567102"),
    ("Lyrics",             "/lyrics/?id=194567102"),
]

async def main():
    print("Testing all endpoints against", BASE)
    print("-" * 60)
    async with aiohttp.ClientSession() as s:
        for name, path in ENDPOINTS:
            try:
                url = BASE + path
                async with s.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
                    body = await r.json(content_type=None) if r.status == 200 else {}
                    detail = ""
                    if "data" in body:
                        d = body["data"]
                        if isinstance(d, dict):
                            detail = d.get("title", d.get("name", ""))
                    elif "artists" in body:
                        detail = f"{len(body['artists'])} artists"
                    elif "albums" in body:
                        detail = f"{len(body['albums'])} albums"
                    icon = "OK " if r.status == 200 else f"ERR{r.status}"
                    print(f"  {icon}  {name:20s} {detail}")
            except Exception as e:
                print(f"  ERR   {name:20s} {type(e).__name__}: {e}")

if __name__ == "__main__":
    asyncio.run(main())
