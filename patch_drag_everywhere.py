import re

def fix_drag_everywhere():
    with open('app.js', 'r', encoding='utf-8') as f:
        js = f.read()

    # 1. Remove the condition that restricts draggable to 'all' category
    # Original: if (state.currentCategory === 'all' && !state.searchQuery && !state.selectedTag) {
    # We want to replace it with: if (!state.searchQuery) {
    # Because searching filters things in a way that moving them might be confusing, but the user said "sabhi category me... labels me bhi".
    # Let's just allow it everywhere except maybe search? The user said "sabhi jagah... labels me bhi".
    # I will just remove the condition entirely or change it to if(true) for simplicity, or just remove the if block wrapper if possible.
    # It's easier to just replace the if condition with if(true)
    js = re.sub(
        r"if\s*\(\s*state\.currentCategory\s*===\s*'all'\s*&&\s*!state\.searchQuery\s*&&\s*!state\.selectedTag\s*\)\s*\{",
        "if (true) {",
        js
    )

    # 2. Update handleDropReorder and saveCustomOrder to safely reorder the global array
    new_reorder_logic = """
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
    
    // Move in DOM
    if (draggedIdx < targetIdx) {
      targetCard.parentNode.insertBefore(draggedCard, targetCard.nextSibling);
    } else {
      targetCard.parentNode.insertBefore(draggedCard, targetCard);
    }
    
    // Ensure the global array is sorted by current orderIndex first
    state.vaultItems.sort((a, b) => (a.orderIndex || 0) - (b.orderIndex || 0));
    
    // Find the actual items
    const dItemIndex = state.vaultItems.findIndex(i => String(i.id) === draggedId);
    if (dItemIndex === -1) return;
    const [draggedItem] = state.vaultItems.splice(dItemIndex, 1);
    
    let tItemIndex = state.vaultItems.findIndex(i => String(i.id) === targetId);
    
    // Determine if we should insert before or after target in the global array
    // We can just check the new DOM order of dragged vs target
    const newCards = Array.from(container.querySelectorAll('.item-card'));
    const newDraggedIdx = newCards.indexOf(draggedCard);
    const newTargetIdx = newCards.indexOf(targetCard);
    
    if (newDraggedIdx > newTargetIdx) {
       // Insert AFTER target
       state.vaultItems.splice(tItemIndex + 1, 0, draggedItem);
    } else {
       // Insert BEFORE target
       state.vaultItems.splice(tItemIndex, 0, draggedItem);
    }
    
    await saveCustomOrder();
  }
  
  async function saveCustomOrder() {
    // Re-assign orderIndex globally based on the new array order
    state.vaultItems.forEach((item, index) => {
      item.orderIndex = index;
    });
    
    state.sortBy = 'custom';
    const sortSelect = document.getElementById('sort-select');
    if (sortSelect) sortSelect.value = 'custom';
    
    await saveVaultToGitHub();
  }
"""

    # Replace the old handleDropReorder and saveCustomOrder
    # Find the block from handleDropReorder to the end of saveCustomOrder
    pattern = r"async function handleDropReorder\(draggedId, targetId\).*?async function saveCustomOrder\(\).*?saveVaultToGitHub\(\);\s*\}"
    js = re.sub(pattern, new_reorder_logic.strip(), js, flags=re.DOTALL)

    with open('app.js', 'w', encoding='utf-8') as f:
        f.write(js)

fix_drag_everywhere()
print("Drag and drop enabled everywhere.")
