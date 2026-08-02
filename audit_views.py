import time
from playwright.sync_api import sync_playwright

def comprehensive_audit():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        # Test Desktop
        context = browser.new_context(viewport={'width': 1280, 'height': 800})
        page = context.new_page()
        page.goto('file:///d:/appmd/index.html')
        page.wait_for_timeout(1000)
        
        # 1. Unlock Screen
        page.screenshot(path='C:/Users/smand/.gemini/antigravity/brain/02ee7fdc-a3c0-4305-8d9a-2997cc8c9e0d/scratch/audit_1_unlock.png')
        
        if page.locator('#unlock-password').is_visible():
            page.fill('#unlock-password', 'testpass')
            page.click('#btn-unlock')
            page.wait_for_timeout(1000)
            
        # 2. Empty Dashboard
        page.screenshot(path='C:/Users/smand/.gemini/antigravity/brain/02ee7fdc-a3c0-4305-8d9a-2997cc8c9e0d/scratch/audit_2_dashboard_empty.png')
        
        # 3. Add Item Modal
        page.click('#btn-empty-add')
        page.wait_for_timeout(500)
        page.screenshot(path='C:/Users/smand/.gemini/antigravity/brain/02ee7fdc-a3c0-4305-8d9a-2997cc8c9e0d/scratch/audit_3_add_modal.png')
        
        # Add a test item
        page.fill('#item-title-input', 'Test Site')
        page.fill('#item-username', 'testuser')
        page.fill('#item-password', 'supersecret')
        page.click('text="Save Item"')
        page.wait_for_timeout(500)
        
        # 4. Dashboard with Item
        page.screenshot(path='C:/Users/smand/.gemini/antigravity/brain/02ee7fdc-a3c0-4305-8d9a-2997cc8c9e0d/scratch/audit_4_dashboard_item.png')
        
        # 5. Item Preview Modal
        # We need to click the item card
        page.evaluate('''() => {
            document.querySelector('.item-card').click();
        }''')
        page.wait_for_timeout(500)
        page.screenshot(path='C:/Users/smand/.gemini/antigravity/brain/02ee7fdc-a3c0-4305-8d9a-2997cc8c9e0d/scratch/audit_5_preview_modal.png')
        page.click('#close-preview')
        page.wait_for_timeout(500)
        
        # 6. Generator
        page.click('#nav-generator')
        page.wait_for_timeout(500)
        page.screenshot(path='C:/Users/smand/.gemini/antigravity/brain/02ee7fdc-a3c0-4305-8d9a-2997cc8c9e0d/scratch/audit_6_generator.png')
        
        # 7. Health Audit
        page.click('#nav-security')
        page.wait_for_timeout(500)
        page.screenshot(path='C:/Users/smand/.gemini/antigravity/brain/02ee7fdc-a3c0-4305-8d9a-2997cc8c9e0d/scratch/audit_7_health.png')
        
        # 8. Settings
        page.click('#nav-settings')
        page.wait_for_timeout(500)
        page.screenshot(path='C:/Users/smand/.gemini/antigravity/brain/02ee7fdc-a3c0-4305-8d9a-2997cc8c9e0d/scratch/audit_8_settings.png')
        
        browser.close()

if __name__ == "__main__":
    comprehensive_audit()
