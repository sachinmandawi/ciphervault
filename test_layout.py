import time
from playwright.sync_api import sync_playwright

def inspect_layout():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={'width': 375, 'height': 812})
        page = context.new_page()
        page.goto('file:///d:/appmd/index.html')
        
        # Inject items to make stats visible
        page.evaluate('''() => {
            document.getElementById('auth-overlay').classList.remove('active');
        }''')
        page.wait_for_timeout(1000)
        
        layout = page.evaluate('''() => {
            function getRect(el) {
                if(!el) return null;
                const r = el.getBoundingClientRect();
                return {x: r.x, y: r.y, width: r.width, height: r.height};
            }
            return {
                viewport: window.innerWidth,
                body: getRect(document.body),
                app: getRect(document.getElementById('app')),
                main: getRect(document.querySelector('.main-content')),
                scroll: getRect(document.querySelector('.content-scroll')),
                statsGrid: getRect(document.querySelector('.stats-grid')),
                statCard1: getRect(document.querySelectorAll('.stat-card')[0]),
                statCard2: getRect(document.querySelectorAll('.stat-card')[1])
            }
        }''')
        
        print("Layout Analysis on 375px viewport:")
        for k, v in layout.items():
            print(f"{k}: {v}")
            
        browser.close()

if __name__ == "__main__":
    inspect_layout()
