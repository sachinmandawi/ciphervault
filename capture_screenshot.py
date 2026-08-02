import time
from playwright.sync_api import sync_playwright

def capture_screenshot():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={'width': 375, 'height': 812})
        page = context.new_page()
        page.goto('file:///d:/appmd/index.html')
        
        # Inject items to make stats visible
        page.evaluate('''() => {
            document.getElementById('auth-overlay').classList.remove('active');
            
            // Add a test item to make sure stats are populated
            const card = document.createElement('div');
            card.className = 'item-card glass-panel';
            card.innerHTML = `<div class="item-body">test</div>`;
            document.getElementById('vault-items-container').appendChild(card);
            
            // Update stats
            document.getElementById('stat-total-items').textContent = '11';
            document.getElementById('stat-health').textContent = '85%';
            document.getElementById('stat-reused').textContent = '1';
            document.getElementById('stat-weak').textContent = '0';
        }''')
        
        page.wait_for_timeout(1000)
        
        page.screenshot(path='C:/Users/smand/.gemini/antigravity/brain/02ee7fdc-a3c0-4305-8d9a-2997cc8c9e0d/scratch/dashboard_screenshot.png')
            
        browser.close()

if __name__ == "__main__":
    capture_screenshot()
