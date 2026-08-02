import re

with open('app.js', 'r', encoding='utf-8') as f:
    js = f.read()

# Add DOM elements to DOM object
# First, let's find the DOM object definition
if 'bnavItems: document.querySelectorAll(' not in js:
    js = js.replace(
        "    navItems: document.querySelectorAll('.sidebar-nav .nav-item[data-category]'),",
        "    navItems: document.querySelectorAll('.sidebar-nav .nav-item[data-category]'),\n    bnavItems: document.querySelectorAll('.bnav-item'),\n    btnFabAdd: document.getElementById('btn-fab-add'),"
    )

# Add event listeners inside setupEventListeners()
# Search for `if (DOM.btnAddItem)` and add FAB listener
if 'if (DOM.btnFabAdd)' not in js:
    js = js.replace(
        "if (DOM.btnAddItem) DOM.btnAddItem.addEventListener('click', openAddModal);",
        "if (DOM.btnAddItem) DOM.btnAddItem.addEventListener('click', openAddModal);\n    if (DOM.btnFabAdd) DOM.btnFabAdd.addEventListener('click', openAddModal);"
    )

# Search for the place where allSidebarButtons are handled and add bnavItems handling
# Wait, let's just append the bnav logic to setupEventListeners. 
# Better to find where we bind `navGen.addEventListener` and add bnav listeners below it.

bnav_listeners = """
    // Mobile Bottom Nav logic
    if (DOM.bnavItems) {
      DOM.bnavItems.forEach(btn => {
        btn.addEventListener('click', () => {
          // Remove active from all bnav items
          DOM.bnavItems.forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          
          const target = btn.getAttribute('data-mobile-nav');
          if (target === 'vault') {
            state.selectedCategory = 'all';
            state.selectedTag = null;
            DOM.searchInput.value = '';
            state.searchQuery = '';
            switchView('vault');
            renderVault();
          } else if (target === 'generator') {
            switchView('generator');
            updateGeneratorView();
          } else if (target === 'authenticator') {
            switchView('authenticator');
          } else if (target === 'settings') {
            switchView('settings');
          }
        });
      });
    }
"""

if '// Mobile Bottom Nav logic' not in js:
    # Let's insert it before `if (DOM.navAuth) {`
    js = js.replace("if (DOM.navAuth) {", bnav_listeners + "\n    if (DOM.navAuth) {")

with open('app.js', 'w', encoding='utf-8') as f:
    f.write(js)
    print("JS patched for mobile UI.")
