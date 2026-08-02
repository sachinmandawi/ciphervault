import re

def update_html():
    with open('index.html', 'r', encoding='utf-8') as f:
        html = f.read()

    # We need to replace the current search-box
    # Regex to find the <div class="search-box"...> ... </div> block
    
    # We will just do a string replacement since we know what it looks like from the previous patch
    
    old_search = """<div class="search-box pill-search">
          <input type="text" id="search-input" placeholder="Search..." autocomplete="off">
          <button id="clear-search" class="btn-icon hidden"><i class="fa-solid fa-xmark"></i></button>
          <i class="fa-solid fa-magnifying-glass search-icon"></i>
        </div>"""
        
    new_search = """<div class="InputContainer search-box">
          <input type="text" id="search-input" class="input" placeholder="Search..." autocomplete="off">
          <button id="clear-search" class="btn-icon hidden" style="margin-right:5px; height:24px; width:24px; font-size:12px;"><i class="fa-solid fa-xmark"></i></button>
          <div class="border"></div>
          <label for="search-input" class="labelforsearch">
            <i class="fa-solid fa-magnifying-glass searchIcon"></i>
          </label>
        </div>"""

    if old_search in html:
        html = html.replace(old_search, new_search)
        with open('index.html', 'w', encoding='utf-8') as f:
            f.write(html)
        print("HTML updated.")
    else:
        print("Could not find exact old search HTML. Attempting regex...")
        # fallback regex
        html = re.sub(r'<div class="search-box[^>]*>.*?</div>', new_search, html, flags=re.DOTALL)
        with open('index.html', 'w', encoding='utf-8') as f:
            f.write(html)
        print("HTML regex updated.")

def update_css():
    with open('styles.css', 'r', encoding='utf-8') as f:
        css = f.read()

    # Remove the old pill search CSS if it exists
    css = re.sub(r'/\* COMPACT PILL SEARCH BAR OVERRIDE \*/.*?@media \(max-width: 600px\) \{.*?\n\}\n', '', css, flags=re.DOTALL)

    new_css = """
/* Uiverse.io by Shaidend - Adapted for Dark Theme */ 
.InputContainer {
  height: 40px;
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: rgba(255, 255, 255, 0.04);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 10px;
  overflow: hidden;
  cursor: text;
  padding-left: 15px;
  box-shadow: 2px 2px 10px rgba(0, 0, 0, 0.2);
  transition: all 0.3s ease;
  flex: 1;
  max-width: 380px;
}

.InputContainer:focus-within {
  background-color: rgba(255, 255, 255, 0.08);
  border-color: rgba(139, 92, 246, 0.4);
  box-shadow: 0 0 12px rgba(139, 92, 246, 0.2);
}

.InputContainer .input {
  width: 100%;
  height: 100%;
  border: none;
  outline: none;
  font-size: 0.9em;
  background: transparent;
  color: var(--text-main);
  caret-color: var(--accent-primary);
}

.labelforsearch {
  cursor: text;
  padding: 0px 12px;
  display: flex;
  align-items: center;
}

.searchIcon {
  font-size: 13px;
  color: var(--text-muted);
  transition: color 0.3s ease;
}

.InputContainer:focus-within .searchIcon {
  color: var(--accent-purple);
}

.InputContainer .border {
  height: 40%;
  width: 1.5px;
  background-color: rgba(255, 255, 255, 0.15);
}

@media (max-width: 600px) {
  .InputContainer {
    max-width: 100%;
    height: 36px;
    padding-left: 10px;
  }
  .labelforsearch {
    padding: 0px 10px;
  }
}
"""
    with open('styles.css', 'w', encoding='utf-8') as f:
        f.write(css + "\n" + new_css)
    print("CSS updated.")

update_html()
update_css()
