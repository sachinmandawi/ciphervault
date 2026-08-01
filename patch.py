import re

with open('app.js', 'r', encoding='utf8') as f:
    code = f.read()

# 1. Update getFilteredAndSortedItems
new_get_filtered = """  function getFilteredAndSortedItems() {
    let items = [...state.vaultItems];

    const cat = state.currentCategory;
    const isTrash = (cat === 'trash');
    const isArchive = (cat === 'archive');

    items = items.filter(item => {
      // Trash view logic
      if (isTrash) return item.deleted === true;
      if (item.deleted === true) return false;

      // Archive view logic
      if (isArchive) return item.archived === true;
      if (item.archived === true && cat !== 'favorite' && !state.selectedTag) return false;

      // Other category logic
      if (cat === 'favorite') return item.favorite === true;
      if (cat !== 'all' && cat !== 'trash' && cat !== 'archive') return item.type === cat;
      
      return true;
    });

    if (state.selectedTag) {
      items = items.filter(i => i.tags && i.tags.includes(state.selectedTag));
    }

    if (state.searchQuery) {
      const q = state.searchQuery.toLowerCase();
      items = items.filter(i => 
        (i.title && i.title.toLowerCase().includes(q)) ||
        (i.username && i.username.toLowerCase().includes(q)) ||
        (i.bankname && i.bankname.toLowerCase().includes(q)) ||
        (i.accountno && i.accountno.toLowerCase().includes(q)) ||
        (i.url && i.url.toLowerCase().includes(q)) ||
        (i.notes && i.notes.toLowerCase().includes(q)) ||
        (i.tags && i.tags.some(t => t.toLowerCase().includes(q)))
      );
    }

    items.sort((a, b) => {
      if (state.sortBy === 'title') return a.title.localeCompare(b.title);
      if (state.sortBy === 'created') return (b.createdAt || 0) - (a.createdAt || 0);
      if (state.sortBy === 'strength') {
        const strA = a.password ? Generator.calculateStrength(a.password).entropy : 0;
        const strB = b.password ? Generator.calculateStrength(b.password).entropy : 0;
        return strB - strA;
      }
      return (b.updatedAt || 0) - (a.updatedAt || 0);
    });

    return items;
  }"""
code = re.sub(r'  function getFilteredAndSortedItems\(\) \{[\s\S]*?    return items;\n  \}', new_get_filtered, code)

# 2. Update updateCountsAndStats
new_counts = """  function updateCountsAndStats() {
    const notDeleted = state.vaultItems.filter(i => !i.deleted);
    const countAll = notDeleted.filter(i => !i.archived).length;
    const countLogin = notDeleted.filter(i => !i.archived && i.type === 'login').length;
    const countCard = notDeleted.filter(i => !i.archived && i.type === 'card').length;
    const countBank = notDeleted.filter(i => !i.archived && i.type === 'bank').length;
    const countNote = notDeleted.filter(i => !i.archived && i.type === 'note').length;
    const countFav = notDeleted.filter(i => i.favorite).length;
    const countArchive = notDeleted.filter(i => i.archived).length;
    const countTrash = state.vaultItems.filter(i => i.deleted).length;

    if (DOM.countAll) DOM.countAll.textContent = countAll;
    if (DOM.countLogin) DOM.countLogin.textContent = countLogin;
    if (DOM.countCard) DOM.countCard.textContent = countCard;
    if (DOM.countBank) DOM.countBank.textContent = countBank;
    if (DOM.countNote) DOM.countNote.textContent = countNote;
    if (DOM.countFav) DOM.countFav.textContent = countFav;
    if (DOM.countArchive) DOM.countArchive.textContent = countArchive;
    if (DOM.countTrash) DOM.countTrash.textContent = countTrash;
"""
code = re.sub(r'  function updateCountsAndStats\(\) \{[\s\S]*?if \(DOM\.countFav\) DOM\.countFav\.textContent = countFav;', new_counts, code)

# 3. Add Star badge to createItemCard and remove color class
code = re.sub(r'card\.className = `item-card glass-panel color-\$\{item\.color \|\| \'default\'\}`;\n', "card.className = 'item-card glass-panel';\n", code)

badge_html = r"""<div class="item-title" style="display:flex; align-items:center; gap:0.35rem;">
            <span>${escapeHtml(item.title)}</span>
            ${item.favorite ? '<i class="fa-solid fa-star" style="color:var(--accent-yellow); font-size:0.85rem;" title="Pinned"></i>' : ''}
          </div>"""
code = re.sub(r'<div class="item-title" style="display:flex; align-items:center; gap:0.35rem;">[\s\S]*?</div>', badge_html, code)

# 4. In saveItem, fix archived and deleted properties
# First let's check what properties we have. It doesn't have archived and deleted.
# We replace the favorite line with archived and deleted.
code = re.sub(
    r"favorite: id \? \(state\.vaultItems\.find\(i => i\.id === id\)\?\.favorite \|\| false\) : false,",
    "favorite: id ? (state.vaultItems.find(i => i.id === id)?.favorite || false) : false,\n      archived: id ? (state.vaultItems.find(i => i.id === id)?.archived || false) : false,\n      deleted: id ? (state.vaultItems.find(i => i.id === id)?.deleted || false) : false,",
    code
)

with open('app.js', 'w', encoding='utf8') as f:
    f.write(code)

print('app.js patched')
