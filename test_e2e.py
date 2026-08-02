import time
from playwright.sync_api import sync_playwright

def test_full_app():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto('file:///d:/appmd/index.html')
        
        errors = []
        page.on('console', lambda msg: errors.append(msg.text) if msg.type == 'error' else None)
        page.on('pageerror', lambda exc: errors.append(str(exc)))
        
        # 1. Setup / Unlock Vault
        page.wait_for_timeout(1000)
        
        # Check if setup form is visible
        if page.is_visible('#setup-form'):
            page.fill('#setup-username', 'testuser')
            page.fill('#setup-password', 'testpass123')
            page.fill('#setup-confirm', 'testpass123')
            page.click('#setup-form button')
        elif page.is_visible('#unlock-form'):
            page.fill('#unlock-password', 'testpass123')
            page.click('#unlock-form button')
            
        page.wait_for_timeout(1000)
        
        # If still auth overlay visible, we can't test further
        if page.is_visible('#auth-overlay'):
            print('Could not unlock vault. Check errors:')
            print(errors)
            browser.close()
            return
            
        # 2. Open Add Item
        page.click('#btn-add-item')
        page.wait_for_timeout(500)
        
        # 3. Change to Secure Note
        page.select_option('#item-type', 'note')
        page.wait_for_timeout(500)
        
        # 4. Fill Note and verify resize
        initial_box = page.locator('#item-notes').bounding_box()
        page.fill('#item-notes', 'Line 1\n' * 20)
        page.wait_for_timeout(500)
        new_box = page.locator('#item-notes').bounding_box()
        
        print('Textarea Initial Height:', initial_box['height'], 'New Height:', new_box['height'])
        
        # 5. Check Manage Labels
        page.click('.close-modal')
        page.wait_for_timeout(500)
        page.click('#btn-manage-labels')
        page.wait_for_timeout(500)
        if not page.is_visible('#modal-manage-labels.active'):
            print('Manage Labels modal failed to open')
            
        print('JS Console Errors:', errors)
        
        browser.close()

if __name__ == "__main__":
    test_full_app()
