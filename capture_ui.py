from playwright.sync_api import sync_playwright

def take_screenshot():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={'width': 375, 'height': 812},
            is_mobile=True,
            has_touch=True
        )
        page = context.new_page()
        page.goto("file:///d:/appmd/index.html")
        page.wait_for_timeout(1000)
        
        # Hide auth overlay
        page.evaluate("""
            document.getElementById('auth-overlay').classList.remove('active');
            document.getElementById('app').classList.remove('blur-content');
            
            // Render a dummy item manually by adding HTML
            const viewVault = document.getElementById('view-vault');
            viewVault.innerHTML = `
                <div class="stats-grid">
                  <div class="stat-card glass-panel">
                    <div class="stat-details">
                      <span class="stat-value">5</span>
                      <span class="stat-label">Total Vault Items</span>
                    </div>
                  </div>
                  <div class="stat-card glass-panel">
                    <div class="stat-details">
                      <span class="stat-value">100%</span>
                      <span class="stat-label">Vault Health Score</span>
                    </div>
                  </div>
                </div>
                
                <div class="item-card">
                  <div class="item-header">
                    <div class="item-favicon"></div>
                    <div class="item-title-block">
                      <div class="item-title">Instagram</div>
                      <div class="item-sub">doc.sachinmandavi • avinashmandavi85@gmail.com</div>
                    </div>
                  </div>
                </div>
            `;
        """)
        
        page.wait_for_timeout(1000)
        page.screenshot(path="d:/appmd/mobile_preview.png", full_page=False)
        browser.close()

if __name__ == "__main__":
    take_screenshot()
