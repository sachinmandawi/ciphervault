import re

with open('app.js', 'r', encoding='utf8') as f:
    code = f.read()

# 1. Update saveItem to include orderIndex
save_item_repl = """      favorite: id ? (state.vaultItems.find(i => i.id === id)?.favorite || false) : false,
      archived: id ? (state.vaultItems.find(i => i.id === id)?.archived || false) : false,
      deleted: id ? (state.vaultItems.find(i => i.id === id)?.deleted || false) : false,
      orderIndex: id ? (state.vaultItems.find(i => i.id === id)?.orderIndex || 0) : -Date.now(),"""
code = re.sub(
    r"      favorite: id \? \(state\.vaultItems\.find\(i => i\.id === id\)\?\.favorite \|\| false\) : false,\n      archived: id \? \(state\.vaultItems\.find\(i => i\.id === id\)\?\.archived \|\| false\) : false,\n      deleted: id \? \(state\.vaultItems\.find\(i => i\.id === id\)\?\.deleted \|\| false\) : false,",
    save_item_repl,
    code
)

# 2. Add id and drag events to createItemCard
drag_logic = """    card.className = 'item-card glass-panel';
    card.dataset.id = item.id;
    
    if (state.currentCategory === 'all' && !state.searchQuery && !state.selectedTag) {
      card.setAttribute('draggable', 'true');
      
      card.addEventListener('dragstart', (e) => {
        card.classList.add('dragging');
        e.dataTransfer.setData('text/plain', item.id);
        e.dataTransfer.effectAllowed = 'move';
      });
      
      card.addEventListener('dragend', (e) => {
        card.classList.remove('dragging');
        document.querySelectorAll('.item-card').forEach(c => c.classList.remove('drag-over'));
      });
      
      card.addEventListener('dragover', (e) => {
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        card.classList.add('drag-over');
      });
      
      card.addEventListener('dragleave', () => {
        card.classList.remove('drag-over');
      });
      
      card.addEventListener('drop', (e) => {
        e.preventDefault();
        card.classList.remove('drag-over');
        const draggedId = e.dataTransfer.getData('text/plain');
        if (draggedId && draggedId !== String(item.id)) {
          handleDropReorder(draggedId, String(item.id));
        }
      });
    }"""
code = re.sub(r"    card\.className = 'item-card glass-panel';", drag_logic, code)

# 3. Add handleDropReorder and saveCustomOrder functions
new_functions = """
  async function handleDropReorder(draggedId, targetId) {
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
    
    if (draggedIdx < targetIdx) {
      targetCard.parentNode.insertBefore(draggedCard, targetCard.nextSibling);
    } else {
      targetCard.parentNode.insertBefore(draggedCard, targetCard);
    }
    
    await saveCustomOrder();
  }
  
  async function saveCustomOrder() {
    const cards = Array.from(DOM.itemsContainer.querySelectorAll('.item-card'));
    cards.forEach((c, index) => {
      const id = c.dataset.id;
      const vItem = state.vaultItems.find(i => String(i.id) === id);
      if (vItem) vItem.orderIndex = index;
    });
    
    state.sortBy = 'custom';
    const sortSelect = document.getElementById('sort-select');
    if (sortSelect) sortSelect.value = 'custom';
    
    await saveVaultToGitHub();
  }

  // --- RENDER VAULT ITEMS ---"""
code = re.sub(r"  // --- RENDER VAULT ITEMS ---", new_functions, code)

# 4. Add custom sort logic
custom_sort = """    items.sort((a, b) => {
      if (state.sortBy === 'custom') return (a.orderIndex || 0) - (b.orderIndex || 0);"""
code = re.sub(r"    items\.sort\(\(a, b\) => {", custom_sort, code)

with open('app.js', 'w', encoding='utf8') as f:
    f.write(code)
print("app.js updated for drag & drop")
