"""Quick test: login + extract article links."""
import asyncio, sys, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from alcove_mcp.store.encrypted_store import EncryptedStore
from alcove_mcp.store.keychain import get_master_key

async def test():
    from playwright.async_api import async_playwright
    store = EncryptedStore(get_master_key())
    entry = store.get("onetrust-blog")
    pw = await async_playwright().start()
    browser = await pw.chromium.launch(headless=True)
    ctx = await browser.new_context()
    page = await ctx.new_page()
    await page.goto("https://my.onetrust.com/login", wait_until="networkidle", timeout=30000)
    u = await page.wait_for_selector('input[name="username"], input[type="email"]', timeout=10000)
    await u.fill(entry.username)
    p = await page.wait_for_selector('input[name="password"], input[type="password"]', timeout=10000)
    await p.fill(entry.secret)
    s = await page.wait_for_selector('button[type="submit"], input[type="submit"]', timeout=10000)
    await s.click()
    await page.wait_for_timeout(5000)
    print("Logged in:", await page.title())
    await page.goto("https://my.onetrust.com/s/topic/0TO1Q000000ItRyWAK/blog", wait_until="domcontentloaded", timeout=30000)
    await page.wait_for_timeout(6000)
    links = await page.evaluate("""() => {
        const r = [];
        document.querySelectorAll('a[href*="/s/article/"]').forEach(a => {
            const h = a.getAttribute("href"); const t = a.textContent.trim();
            if (h && t && !r.some(x => x.href === h)) r.push({href: h, title: t});
        });
        return r;
    }""")
    print(f"Found {len(links)} articles")
    for l in links[:10]:
        print(f"  {l['title']}: {l['href']}")
    if len(links) > 10:
        print(f"  ... and {len(links)-10} more")
    await browser.close()
    await pw.stop()

asyncio.run(test())
