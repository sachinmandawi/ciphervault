import asyncio
from playwright.async_api import async_playwright

async def run_audit():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(viewport={'width': 1280, 'height': 800})
        
        errors = []
        page.on('console', lambda msg: errors.append(f"{msg.type}: {msg.text}"))
        
        await page.goto('http://localhost:8080')
        await page.wait_for_timeout(500)
        
        # Unlock
        await page.evaluate("""
            document.getElementById('unlock-username').value = 'admin';
            document.getElementById('unlock-password').value = 'admin';
            document.querySelector('#unlock-form button[type="button"]').click();
            setTimeout(() => { if(typeof unlockVault === 'function') unlockVault(); }, 500);
        """)
        await page.wait_for_timeout(1000)
        
        # 2. Main Dashboard (Vault)
        await page.screenshot(path='C:\\Users\\smand\\.gemini\\antigravity\\brain\\02ee7fdc-a3c0-4305-8d9a-2997cc8c9e0d\\scratch\\audit_2_dashboard.png')
        
        # 3. Sidebar Collapse Test
        await page.evaluate('document.getElementById("desktop-sidebar-close").click()')
        await page.wait_for_timeout(500)
        await page.screenshot(path='C:\\Users\\smand\\.gemini\\antigravity\\brain\\02ee7fdc-a3c0-4305-8d9a-2997cc8c9e0d\\scratch\\audit_3_collapsed.png')
        
        # Open Sidebar Again
        await page.evaluate('document.getElementById("mobile-menu-toggle").click()')
        await page.wait_for_timeout(500)
        
        # 4. Open Settings
        await page.evaluate('document.getElementById("nav-settings").click()')
        await page.wait_for_timeout(500)
        await page.screenshot(path='C:\\Users\\smand\\.gemini\\antigravity\\brain\\02ee7fdc-a3c0-4305-8d9a-2997cc8c9e0d\\scratch\\audit_4_settings.png')
        
        print('Console errors:', errors)
        await browser.close()

asyncio.run(run_audit())
