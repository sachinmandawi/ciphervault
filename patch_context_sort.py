import re

def patch_app_js():
    with open('app.js', 'r', encoding='utf-8') as f:
        js = f.read()

    # 1. State init
    js = js.replace('vaultItems: [],\n    searchQuery', 'vaultItems: [],\n    customOrders: {},\n    searchQuery')

    # 2. Main boot decryption
    old_boot = """        let items = await CryptoEngine.decryptData(payload.vault, key);
        if (Array.isArray(items)) {
          items.forEach(i => {
            if (typeof i.tags === 'string') {
              i.tags = i.tags.split(/[,#\\s]+/).map(t => t.trim()).filter(Boolean);
            }
            if (!Array.isArray(i.tags)) {
              i.tags = [];
            }
          });
          state.vaultItems = items;"""
    
    new_boot = """        let decrypted = await CryptoEngine.decryptData(payload.vault, key);
        let items = [];
        if (Array.isArray(decrypted)) {
          items = decrypted;
          state.customOrders = {};
        } else if (decrypted && Array.isArray(decrypted.items)) {
          items = decrypted.items;
          state.customOrders = decrypted.customOrders || {};
        }

        items.forEach(i => {
          if (typeof i.tags === 'string') {
            i.tags = i.tags.split(/[,#\\s]+/).map(t => t.trim()).filter(Boolean);
          }
          if (!Array.isArray(i.tags)) {
            i.tags = [];
          }
        });
        state.vaultItems = items;"""
    js = js.replace(old_boot, new_boot)

    # 3. Save logic
    js = js.replace(
        'const encryptedVault = await CryptoEngine.encryptData(state.vaultItems, state.masterKey);',
        'const vaultData = { items: state.vaultItems, customOrders: state.customOrders };\n      const encryptedVault = await CryptoEngine.encryptData(vaultData, state.masterKey);'
    )

    # 4. Import logic
    old_import = """            const decItems = await CryptoEngine.decryptData(imported.vault, state.masterKey);
            state.vaultItems = [...state.vaultItems, ...decItems];"""
    new_import = """            let decItems = await CryptoEngine.decryptData(imported.vault, state.masterKey);
            if (decItems && !Array.isArray(decItems) && decItems.items) decItems = decItems.items;
            state.vaultItems = [...state.vaultItems, ...decItems];"""
    js = js.replace(old_import, new_import)

    # 5. renderVault sorting
    old_sort = """    if (state.sortBy === 'custom') {
      filtered.sort((a, b) => (a.orderIndex || 0) - (b.orderIndex || 0));
    }"""
    new_sort = """    let viewKey = 'all';
    if (state.selectedTag) {
      viewKey = 'label:' + state.selectedTag;
    } else if (state.currentCategory !== 'all') {
      viewKey = 'category:' + state.currentCategory;
    }

    if (state.sortBy === 'custom') {
      const orderList = state.customOrders[viewKey] || [];
      filtered.sort((a, b) => {
        let idxA = orderList.indexOf(String(a.id));
        let idxB = orderList.indexOf(String(b.id));
        if (idxA === -1) idxA = 999999;
        if (idxB === -1) idxB = 999999;
        return idxA - idxB;
      });
    }"""
    js = js.replace(old_sort, new_sort)

    # 6. handleDropReorder
    old_reorder_regex = r"async function handleDropReorder\(draggedId, targetId\).*?async function saveCustomOrder\(\).*?saveVaultToGitHub\(\);\s*\}"
    new_reorder = """  async function handleDropReorder(draggedId, targetId) {
    const container = DOM.itemsContainer;
    const cards = Array.from(container.querySelectorAll('.item-card'));
    
    let draggedCard = null;
    let targetCard = null;
    let draggedIdx = -1;
    let targetIdx = -1;
    
    cards.forEach((c, idx) => {
      if (c.dataset.id === draggedId) { draggedCard = c; draggedIdx = idx; }
      if (c.dataset.id === targetId) { targetCard = c; targetIdx = idx; }
    });
    
    if (!draggedCard || !targetCard) return;
    
    // Move in DOM visually
    if (draggedIdx < targetIdx) {
      targetCard.parentNode.insertBefore(draggedCard, targetCard.nextSibling);
    } else {
      targetCard.parentNode.insertBefore(draggedCard, targetCard);
    }
    
    // Save new DOM order for this specific view
    let viewKey = 'all';
    if (state.selectedTag) {
      viewKey = 'label:' + state.selectedTag;
    } else if (state.currentCategory !== 'all') {
      viewKey = 'category:' + state.currentCategory;
    }
    
    const newCards = Array.from(container.querySelectorAll('.item-card'));
    if (!state.customOrders) state.customOrders = {};
    state.customOrders[viewKey] = newCards.map(c => String(c.dataset.id));
    
    state.sortBy = 'custom';
    const sortSelect = document.getElementById('sort-select');
    if (sortSelect) sortSelect.value = 'custom';
    
    await saveVaultToGitHub();
  }"""
    js = re.sub(old_reorder_regex, new_reorder.strip(), js, flags=re.DOTALL)

    with open('app.js', 'w', encoding='utf-8') as f:
        f.write(js)

patch_app_js()
print("Applied View-Specific Custom Ordering.")
