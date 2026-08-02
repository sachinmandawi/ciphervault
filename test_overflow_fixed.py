import time
from playwright.sync_api import sync_playwright

def inspect_overflow():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={'width': 375, 'height': 812})
        page = context.new_page()
        page.goto('file:///d:/appmd/index.html')
        
        # Inject styles to fix
        page.evaluate('''() => {
            const style = document.createElement('style');
            style.textContent = `
              .item-pass-hidden {
                word-break: break-all !important;
                overflow-wrap: anywhere !important;
                white-space: pre-wrap !important;
                flex: 1;
                min-width: 0;
                line-height: 1.4;
                padding-right: 10px;
              }
            `;
            document.head.appendChild(style);
        
            document.getElementById('auth-overlay').classList.remove('active');
            
            const card = document.createElement('div');
            card.className = 'item-card glass-panel';
            card.innerHTML = `
              <div class="item-body" title="Click to View Details">
                <span class="item-pass-hidden" style="">dE&q;pt:u=>k;z?tPNUjT6ux3!j11czJDG}7.cn$RQ(mLP;_+E.4:v)Zfq1K6*C</span>
                <div class="item-card-btns">
                  <button type="button" class="btn-icon btn-toggle-vis"><i class="fa-regular fa-eye"></i></button>
                </div>
              </div>
            `;
            document.getElementById('vault-items-container').appendChild(card);
        }''')
        
        page.wait_for_timeout(1000)
        
        layout = page.evaluate('''() => {
            function getRect(el) {
                if(!el) return null;
                const r = el.getBoundingClientRect();
                return {width: r.width, height: r.height};
            }
            return {
                body: getRect(document.querySelector('.item-body')),
                span: getRect(document.querySelector('.item-pass-hidden'))
            }
        }''')
        
        print("Layout Analysis Fixed:")
        for k, v in layout.items():
            print(f"{k}: {v}")
            
        page.screenshot(path='C:/Users/smand/.gemini/antigravity/brain/02ee7fdc-a3c0-4305-8d9a-2997cc8c9e0d/scratch/test_overflow_fixed.png')
        browser.close()

if __name__ == "__main__":
    inspect_overflow()
