import time
from playwright.sync_api import sync_playwright

def check_responsive():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        
        widths = [320, 375, 414]
        for w in widths:
            context = browser.new_context(viewport={'width': w, 'height': 800})
            page = context.new_page()
            page.goto('file:///d:/appmd/index.html')
            
            # Inject some content to simulate real usage
            page.evaluate('''() => {
                document.getElementById('auth-overlay').classList.remove('active');
                
                const card = document.createElement('div');
                card.className = 'item-card glass-panel';
                card.innerHTML = `<div class="item-body"><div style="font-family:var(--font-mono); font-size:0.85rem; color:#f8fafc; line-height:1.5; white-space:pre-wrap; word-break:break-all; overflow-wrap:anywhere; max-height:85px; overflow:hidden; width:100%; flex: 1; min-width: 0;">Username= sachinmandawi Master Password= sachinmandawi?810396833sachinmandawi</div></div>`;
                document.getElementById('vault-items-container').appendChild(card);
            }''')
            
            page.wait_for_timeout(500)
            
            vw = page.evaluate('window.innerWidth')
            sw = page.evaluate('document.body.scrollWidth')
            
            if sw > vw:
                print(f'FAIL on {w}px: scrollWidth is {sw}px (overflows by {sw-vw}px)')
            else:
                print(f'PASS on {w}px: No horizontal overflow (scrollWidth {sw}px == {vw}px)')
            
            context.close()
        
        browser.close()

if __name__ == "__main__":
    check_responsive()
