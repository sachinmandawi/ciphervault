import time
from playwright.sync_api import sync_playwright

def test_dashboard_cards():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={'width': 1280, 'height': 800})
        page = context.new_page()
        page.goto('file:///d:/appmd/index.html')
        
        page.wait_for_timeout(1000)
        
        # We need to setup a password and unlock first because the vault is empty
        # Wait for the password input
        if page.locator('#unlock-password').is_visible():
            page.fill('#unlock-password', 'testpass')
            page.click('#btn-unlock')
            page.wait_for_timeout(1000)
        
        # Test 1: Hover effect & cursor on card-stat-total
        card_total = page.locator('#card-stat-total')
        card_total.hover(force=True)
        page.wait_for_timeout(200)
        
        cursor = page.evaluate('''(el) => window.getComputedStyle(el).cursor''', card_total.element_handle())
        transform = page.evaluate('''(el) => window.getComputedStyle(el).transform''', card_total.element_handle())
        
        print(f"Total Items Card Cursor on Hover: {cursor}")
        print(f"Total Items Card Transform on Hover: {transform}")
        
        # Test 2: Clicking card-stat-score opens Health Audit
        card_score = page.locator('#card-stat-score')
        card_score.click(force=True)
        page.wait_for_timeout(500)
        
        health_audit_visible = page.evaluate('''(el) => {
            const audit = document.getElementById('view-audit');
            return window.getComputedStyle(audit).display !== 'none';
        }''')
        print(f"Health Audit visible after clicking Score Card: {health_audit_visible}")
        
        # Go back to dashboard (All Items)
        page.locator('#nav-all').click(force=True)
        page.wait_for_timeout(500)
        
        # Go to favorites first
        page.locator('#nav-favorites').click(force=True)
        page.wait_for_timeout(500)
        
        # Click total items card
        card_total.click(force=True)
        page.wait_for_timeout(500)
        
        # Check active nav item
        active_nav = page.evaluate('''() => {
            const active = document.querySelector('.nav-item.active');
            return active ? active.id : 'none';
        }''')
        print(f"Active nav item after clicking Total Items Card: {active_nav}")
        
        browser.close()

if __name__ == "__main__":
    test_dashboard_cards()
