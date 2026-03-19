"""Quick: just extract topic links from the catalog page."""
import asyncio, sys, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from coffer_mcp.store.encrypted_store import EncryptedStore
from coffer_mcp.store.keychain import get_master_key

async def get_topics():
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
    await page.goto("https://my.onetrust.com/s/topiccatalog", wait_until="domcontentloaded", timeout=30000)
    await page.wait_for_timeout(6000)
    topics = await page.evaluate("""() => {
        const r = [];
        document.querySelectorAll('a[href*="/s/topic/"]').forEach(a => {
            const h = a.getAttribute("href");
            const t = a.textContent.trim();
            if (h && t && !r.some(x => x.href === h)) r.push({href: h, title: t});
        });
        return r;
    }""")
    # Save to file
    out = Path.home() / "topic_links.json"
    out.write_text(json.dumps(topics, indent=2), encoding="utf-8")
    print(f"Found {len(topics)} topics, saved to {out}")
    for t in topics:
        print(f"  {t['title']}")
    await browser.close()
    await pw.stop()

asyncio.run(get_topics())
