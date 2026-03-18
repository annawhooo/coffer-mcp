"""
OneTrust Knowledge Base Scraper

Scrapes Cookie Consent articles from my.onetrust.com and saves them as
individual markdown files. Uses Alcove's credential store to authenticate.

Outputs to: ~/OneTrust_KB/cookie_consent/
Each article is saved as: <slug>.md

Usage:
    python scrape_onetrust_kb.py
    python scrape_onetrust_kb.py --upload-gdrive   (also uploads to Google Drive)
"""

from __future__ import annotations

import argparse
import asyncio
import re
import sys
import time
from pathlib import Path

# Add alcove to the import path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from alcove_mcp.store.encrypted_store import EncryptedStore
from alcove_mcp.store.keychain import get_master_key

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

ALIAS = "onetrust-blog"
LOGIN_URL = "https://my.onetrust.com/login"
TOPIC_URL = "https://my.onetrust.com/s/topic/0TO1Q000000ItRyWAK/blog"
OUTPUT_DIR = Path.home() / "OneTrust_KB" / "cookie_consent"

# Username/password selectors for the login form
USERNAME_SEL = 'input[name="username"], input[type="email"], input#username'
PASSWORD_SEL = 'input[name="password"], input[type="password"], input#password'
SUBMIT_SEL = 'button[type="submit"], input[type="submit"], button:has-text("Log In")'


# ---------------------------------------------------------------------------
# Browser helpers
# ---------------------------------------------------------------------------

async def launch_and_login():
    """Launch Playwright, log into OneTrust, and return the authenticated page."""
    from playwright.async_api import async_playwright

    # Get credentials from Alcove vault
    master_key = get_master_key()
    store = EncryptedStore(master_key)
    entry = store.get(ALIAS)

    pw = await async_playwright().start()
    browser = await pw.chromium.launch(headless=True)
    context = await browser.new_context()
    page = await context.new_page()

    print(f"[*] Navigating to login page: {LOGIN_URL}")
    await page.goto(LOGIN_URL, wait_until="networkidle", timeout=30000)

    # Fill credentials
    username_el = await page.wait_for_selector(USERNAME_SEL, timeout=10000)
    await username_el.fill(entry.username)

    password_el = await page.wait_for_selector(PASSWORD_SEL, timeout=10000)
    await password_el.fill(entry.secret)

    submit_el = await page.wait_for_selector(SUBMIT_SEL, timeout=10000)
    await submit_el.click()

    # Wait for login to complete
    await page.wait_for_timeout(5000)
    try:
        await page.wait_for_load_state("networkidle", timeout=15000)
    except Exception:
        pass

    title = await page.title()
    print(f"[+] Logged in. Page title: {title}")
    return pw, browser, context, page


async def extract_article_links(page) -> list[dict]:
    """Navigate to the topic page and extract all article links."""
    print(f"[*] Fetching topic page: {TOPIC_URL}")
    await page.goto(TOPIC_URL, wait_until="domcontentloaded", timeout=30000)
    await page.wait_for_timeout(6000)  # SPA hydration

    # Dismiss cookie banner if present
    for sel in ["#onetrust-accept-btn-handler", "button:has-text('Accept All')", "button:has-text('Essential only')"]:
        try:
            btn = await page.query_selector(sel)
            if btn:
                await btn.click()
                await page.wait_for_timeout(1000)
                break
        except Exception:
            pass

    # Extract all article links from the page
    # OneTrust uses Salesforce Community, links are typically <a> tags
    links = await page.evaluate("""
        () => {
            const results = [];
            const anchors = document.querySelectorAll('a[href*="/s/article/"]');
            for (const a of anchors) {
                const href = a.getAttribute('href');
                const text = a.textContent.trim();
                if (href && text && !results.some(r => r.href === href)) {
                    results.push({ href, title: text });
                }
            }
            return results;
        }
    """)

    print(f"[+] Found {len(links)} article links")
    return links


async def fetch_article(page, url: str, title: str) -> str | None:
    """Fetch a single article and return its content as text."""
    full_url = url if url.startswith("http") else f"https://my.onetrust.com{url}"

    try:
        await page.goto(full_url, wait_until="domcontentloaded", timeout=30000)
        await page.wait_for_timeout(6000)

        # Dismiss cookie banner
        for sel in ["#onetrust-accept-btn-handler", "button:has-text('Accept All')"]:
            try:
                btn = await page.query_selector(sel)
                if btn:
                    await btn.click()
                    await page.wait_for_timeout(500)
                    break
            except Exception:
                pass

        # Extract rendered text from body
        content = await page.inner_text("body")
        return content

    except Exception as e:
        print(f"    [!] Failed to fetch '{title}': {e}")
        return None


def slugify(text: str) -> str:
    """Convert a title to a safe filename slug."""
    text = text.lower().strip()
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'[\s_-]+', '-', text)
    text = text.strip('-')
    return text[:120]  # cap filename length


def save_article(title: str, url: str, content: str) -> Path:
    """Save article content as a markdown file."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    slug = slugify(title)
    filepath = OUTPUT_DIR / f"{slug}.md"

    # Build markdown
    full_url = url if url.startswith("http") else f"https://my.onetrust.com{url}"
    md = f"# {title}\n\n"
    md += f"**Source:** {full_url}\n"
    md += f"**Scraped:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    md += "---\n\n"
    md += content

    filepath.write_text(md, encoding="utf-8")
    return filepath


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def scrape():
    """Main scrape workflow."""
    pw, browser, context, page = await launch_and_login()

    try:
        # Step 1: Get article links
        articles = await extract_article_links(page)

        if not articles:
            print("[!] No articles found. Check the topic URL or login.")
            return

        # Step 2: Fetch each article
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        total = len(articles)
        saved = 0
        failed = 0


        for i, article in enumerate(articles, 1):
            title = article["title"]
            href = article["href"]
            print(f"[{i}/{total}] Fetching: {title}")

            content = await fetch_article(page, href, title)
            if content:
                filepath = save_article(title, href, content)
                print(f"    -> Saved: {filepath.name}")
                saved += 1
            else:
                failed += 1

            # Be polite — small delay between requests
            await page.wait_for_timeout(2000)

        print(f"\n{'='*60}")
        print(f"Scrape complete!")
        print(f"  Saved:  {saved}")
        print(f"  Failed: {failed}")
        print(f"  Output: {OUTPUT_DIR}")
        print(f"{'='*60}")

    finally:
        await page.close()
        await context.close()
        await browser.close()
        await pw.stop()


def main():
    parser = argparse.ArgumentParser(description="Scrape OneTrust Cookie Consent KB")
    parser.parse_args()
    asyncio.run(scrape())


if __name__ == "__main__":
    main()
