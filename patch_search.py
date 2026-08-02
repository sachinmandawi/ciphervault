import re

def update_html():
    with open('index.html', 'r', encoding='utf-8') as f:
        html = f.read()

    # Move icon to the right, add 'search-icon' class for CSS targeting, change placeholder
    old_search = """<div class="search-box">
          <i class="fa-solid fa-magnifying-glass"></i>
          <input type="text" id="search-input" placeholder="Search logins, bank accounts, notes... (Ctrl+/)" autocomplete="off">
          <button id="clear-search" class="btn-icon hidden"><i class="fa-solid fa-xmark"></i></button>
        </div>"""
    
    new_search = """<div class="search-box pill-search">
          <input type="text" id="search-input" placeholder="Search..." autocomplete="off">
          <button id="clear-search" class="btn-icon hidden"><i class="fa-solid fa-xmark"></i></button>
          <i class="fa-solid fa-magnifying-glass search-icon"></i>
        </div>"""

    if old_search in html:
        html = html.replace(old_search, new_search)
        with open('index.html', 'w', encoding='utf-8') as f:
            f.write(html)
        print("HTML updated.")
    else:
        print("HTML already updated or old pattern not found.")

def update_css():
    with open('styles.css', 'r', encoding='utf-8') as f:
        css = f.read()

    new_css = """
/* COMPACT PILL SEARCH BAR OVERRIDE */
.search-box.pill-search {
  border-radius: 50px;
  background: rgba(255, 255, 255, 0.04);
  border: 1px solid rgba(255, 255, 255, 0.08);
  padding: 0.35rem 1rem;
  max-width: 320px;
}

.search-box.pill-search input {
  font-size: 0.85rem;
  padding: 0.1rem 0;
}

.search-box.pill-search:focus-within {
  background: rgba(255, 255, 255, 0.08);
  border-color: rgba(139, 92, 246, 0.4);
  box-shadow: 0 0 12px rgba(139, 92, 246, 0.2);
}

.search-box.pill-search .search-icon {
  color: var(--text-muted);
  font-size: 0.9rem;
  margin-left: 0.25rem;
}

@media (max-width: 600px) {
  .search-box.pill-search {
    max-width: 100%;
    padding: 0.25rem 0.85rem;
  }
  .search-box.pill-search input {
    font-size: 0.8rem;
  }
}
"""
    if 'PILL SEARCH BAR' not in css:
        with open('styles.css', 'a', encoding='utf-8') as f:
            f.write("\n" + new_css)
        print("CSS updated.")
    else:
        print("CSS already updated.")

update_html()
update_css()
