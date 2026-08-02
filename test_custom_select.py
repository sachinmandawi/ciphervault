import time
from playwright.sync_api import sync_playwright

def inspect_custom_select():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={'width': 375, 'height': 812})
        page = context.new_page()
        page.goto('file:///d:/appmd/index.html')
        
        # Bypass auth overlay
        page.evaluate('''() => {
            document.getElementById('auth-overlay').classList.remove('active');
        }''')
        page.wait_for_timeout(500)
        
        # Click the custom select trigger for sort-select
        page.evaluate('''() => {
            const selectWrapper = document.querySelector('#sort-select').parentNode;
            selectWrapper.querySelector('.custom-select-trigger').click();
        }''')
        
        page.wait_for_timeout(500)
        
        page.screenshot(path='C:/Users/smand/.gemini/antigravity/brain/02ee7fdc-a3c0-4305-8d9a-2997cc8c9e0d/scratch/test_custom_select.png')
        browser.close()

if __name__ == "__main__":
    inspect_custom_select()
