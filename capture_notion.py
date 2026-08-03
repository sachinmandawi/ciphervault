import asyncio
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(viewport={'width': 1280, 'height': 800})
        await page.goto('http://localhost:8080')
        await page.wait_for_timeout(2000)
        
        # Click login
        await page.click('.master-pass-item')
        await page.wait_for_timeout(500)
        await page.fill('#master-pass-input', 'admin')
        await page.click('#btn-unlock')
        await page.wait_for_timeout(2000)
        
        await page.screenshot(path='C:\\Users\\smand\\.gemini\\antigravity\\brain\\02ee7fdc-a3c0-4305-8d9a-2997cc8c9e0d\\scratch\\notion_test.png', full_page=True)
        await browser.close()

asyncio.run(main())
