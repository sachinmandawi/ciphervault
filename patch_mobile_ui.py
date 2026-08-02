import re

def update_html():
    with open('index.html', 'r', encoding='utf-8') as f:
        html = f.read()

    # Hide desktop add button on mobile
    html = html.replace('id="btn-add-item" class="btn btn-primary glow-btn"', 'id="btn-add-item" class="btn btn-primary glow-btn desktop-only"')

    # Add bottom nav and FAB before </body>
    if 'class="bottom-nav' not in html:
        bottom_nav_html = """
  <!-- MOBILE BOTTOM NAV -->
  <nav class="bottom-nav mobile-only glass-header">
    <button class="bnav-item active" data-mobile-nav="vault">
      <i class="fa-solid fa-house"></i>
      <span>Home</span>
    </button>
    <button class="bnav-item" data-mobile-nav="generator">
      <i class="fa-solid fa-key"></i>
      <span>Gen</span>
    </button>
    <button class="bnav-item" data-mobile-nav="authenticator">
      <i class="fa-solid fa-shield-halved"></i>
      <span>2FA</span>
    </button>
    <button class="bnav-item" data-mobile-nav="settings">
      <i class="fa-solid fa-gear"></i>
      <span>Settings</span>
    </button>
  </nav>

  <!-- MOBILE FAB -->
  <button id="btn-fab-add" class="fab-add mobile-only glow-btn">
    <i class="fa-solid fa-plus"></i>
  </button>
"""
        html = html.replace('</body>', bottom_nav_html + '\n</body>')

    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(html)
    print("HTML updated.")

def update_css():
    with open('styles.css', 'r', encoding='utf-8') as f:
        css = f.read()

    # Add mobile-only / desktop-only if not present
    if '.mobile-only' not in css:
        print("Warning: .mobile-only not found, but it should be inside media query.")

    # We need to append CSS for the bottom nav and FAB inside max-width: 600px media query
    # Also override .modal-card for max-width: 600px
    # Let's just append a new media query block at the end of the file
    
    mobile_css = """
/* NATIVE ANDROID UI OVERHAUL */
@media (max-width: 600px) {
  /* Hide Sidebar completely on mobile in favor of bottom nav */
  .sidebar {
    display: none !important;
  }
  
  .mobile-only { display: flex !important; }
  .desktop-only { display: none !important; }

  /* Bottom Navigation */
  .bottom-nav {
    display: flex !important;
    position: fixed;
    bottom: 0;
    left: 0;
    width: 100%;
    height: 65px;
    background: rgba(10, 13, 22, 0.95);
    backdrop-filter: blur(12px);
    border-top: 1px solid rgba(255,255,255,0.05);
    z-index: 990;
    justify-content: space-around;
    align-items: center;
    padding-bottom: env(safe-area-inset-bottom, 0px);
  }

  .bnav-item {
    background: transparent;
    border: none;
    color: var(--text-muted);
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 4px;
    flex: 1;
    height: 100%;
    cursor: pointer;
    transition: all 0.2s;
  }

  .bnav-item i {
    font-size: 1.25rem;
    transition: transform 0.2s;
  }

  .bnav-item span {
    font-size: 0.65rem;
    font-weight: 500;
  }

  .bnav-item.active {
    color: var(--accent-cyan);
  }

  .bnav-item.active i {
    transform: translateY(-2px);
  }

  /* Floating Action Button (FAB) */
  .fab-add {
    display: flex !important;
    position: fixed;
    bottom: 80px; /* Above bottom nav */
    right: 20px;
    width: 56px;
    height: 56px;
    border-radius: 50%;
    background: var(--accent-cyan);
    color: #fff;
    border: none;
    align-items: center;
    justify-content: center;
    font-size: 1.5rem;
    box-shadow: 0 4px 15px rgba(6, 182, 212, 0.4);
    z-index: 995;
    cursor: pointer;
    transition: transform 0.2s;
  }

  .fab-add:active {
    transform: scale(0.92);
  }

  /* Make main content clear the bottom nav */
  .content-scroll {
    padding-bottom: 90px !important; 
  }

  /* Full Screen Modals */
  .modal-card {
    max-width: 100vw !important;
    height: 100vh !important;
    max-height: 100vh !important;
    border-radius: 0 !important;
    border: none !important;
    box-sizing: border-box;
  }
  
  .modal-overlay {
    padding: 0 !important;
  }

  .modal-body {
    flex: 1;
    overflow-y: auto;
    -webkit-overflow-scrolling: touch;
    box-sizing: border-box;
  }

  /* Ensure inputs don't overflow */
  input, textarea, select {
    box-sizing: border-box;
    max-width: 100%;
  }
  
  .top-header {
    border-radius: 0;
  }
}
"""
    if 'NATIVE ANDROID UI OVERHAUL' not in css:
        with open('styles.css', 'a', encoding='utf-8') as f:
            f.write(mobile_css)
        print("CSS updated.")
    else:
        print("CSS already updated.")

update_html()
update_css()
