const fs = require('fs');
let code = fs.readFileSync('app.js', 'utf8');

// 1. Save Item: Add color, archived, deleted
code = code.replace(
  /favorite: existingItem \? existingItem\.favorite : false,\r?\n/,
  "favorite: existingItem ? existingItem.favorite : false,\n      color: state.currentColor,\n      archived: existingItem ? existingItem.archived : false,\n      deleted: existingItem ? existingItem.deleted : false,\n"
);

// 2. Add color swatch listeners to setupEventListeners
code = code.replace(
  /if \(DOM\.btnLockNow\) DOM\.btnLockNow\.addEventListener\('click', lockVault\);\r?\n/,
  `if (DOM.btnLockNow) DOM.btnLockNow.addEventListener('click', lockVault);
    if (DOM.colorSwatches) {
      DOM.colorSwatches.forEach(swatch => {
        swatch.addEventListener('click', (e) => {
          DOM.colorSwatches.forEach(s => s.classList.remove('active'));
          e.target.classList.add('active');
          state.currentColor = e.target.dataset.color || 'default';
        });
      });
    }\n`
);

// 3. Reset color in openAddItemModal
code = code.replace(
  /if \(DOM\.modalItemTitle\) DOM\.modalItemTitle\.textContent = 'Add New Vault Item';\r?\n/,
  `if (DOM.modalItemTitle) DOM.modalItemTitle.textContent = 'Add New Vault Item';
    state.currentColor = 'default';
    if (DOM.colorSwatches) {
      DOM.colorSwatches.forEach(s => s.classList.remove('active'));
      const def = Array.from(DOM.colorSwatches).find(s => s.dataset.color === 'default');
      if (def) def.classList.add('active');
    }\n`
);

// 4. Load color in openEditModal
code = code.replace(
  /if \(DOM\.modalItemTitle\) DOM\.modalItemTitle\.textContent = 'Edit Vault Item';\r?\n/,
  `if (DOM.modalItemTitle) DOM.modalItemTitle.textContent = 'Edit Vault Item';
    state.currentColor = item.color || 'default';
    if (DOM.colorSwatches) {
      DOM.colorSwatches.forEach(s => s.classList.remove('active'));
      const activeSwatch = Array.from(DOM.colorSwatches).find(s => s.dataset.color === state.currentColor);
      if (activeSwatch) activeSwatch.classList.add('active');
    }\n`
);

// 5. Update renderVault for filtering & sections
// We need to replace the logic of renderVault entirely
const renderVaultRegex = /async function renderVault\(\) \{[\s\S]*?    updateSidebarTags\(\);\r?\n  \}/m;

const newRenderVault = `async function renderVault() {
    if (!state.masterKey) return;

    if (DOM.itemsContainer) DOM.itemsContainer.innerHTML = '';
    
    // Sort
    let items = [...state.vaultItems];
    const sortVal = DOM.sortSelect ? DOM.sortSelect.value : 'alpha';
    if (sortVal === 'alpha') items.sort((a, b) => a.title.localeCompare(b.title));
    else if (sortVal === 'newest') items.sort((a, b) => b.updatedAt - a.updatedAt);
    else if (sortVal === 'oldest') items.sort((a, b) => a.updatedAt - b.updatedAt);

    // Categories
    const cat = state.currentCategory;
    const isTrash = (cat === 'trash');
    const isArchive = (cat === 'archive');
    
    // Apply Base Filters
    items = items.filter(item => {
      // If we are in Trash view, only show deleted
      if (isTrash) return item.deleted === true;
      
      // For all other views, exclude deleted
      if (item.deleted === true) return false;

      // If we are in Archive view, only show archived
      if (isArchive) return item.archived === true;
      
      // For all other views EXCEPT Favorites and Labels, exclude archived
      if (item.archived === true && cat !== 'favorite' && !state.selectedTag) return false;

      // Category match
      if (cat === 'favorite') return item.favorite === true;
      if (cat !== 'all' && cat !== 'trash' && cat !== 'archive') return item.type === cat;
      
      return true;
    });

    // Tag filter
    if (state.selectedTag) {
      items = items.filter(item => item.tags && item.tags.includes(state.selectedTag));
    }

    // Search
    const q = (state.searchQuery || '').toLowerCase();
    if (q) {
      items = items.filter(i => 
        (i.title || '').toLowerCase().includes(q) ||
        (i.username || '').toLowerCase().includes(q) ||
        (i.tags && i.tags.some(t => t.toLowerCase().includes(q)))
      );
    }

    // Update Counts
    const notDeleted = state.vaultItems.filter(i => !i.deleted);
    if (DOM.countAll) DOM.countAll.textContent = notDeleted.filter(i => !i.archived).length;
    if (DOM.countLogin) DOM.countLogin.textContent = notDeleted.filter(i => !i.archived && i.type === 'login').length;
    if (DOM.countCard) DOM.countCard.textContent = notDeleted.filter(i => !i.archived && i.type === 'card').length;
    if (DOM.countBank) DOM.countBank.textContent = notDeleted.filter(i => !i.archived && i.type === 'bank').length;
    if (DOM.countNote) DOM.countNote.textContent = notDeleted.filter(i => !i.archived && i.type === 'note').length;
    if (DOM.countFav) DOM.countFav.textContent = notDeleted.filter(i => i.favorite).length;
    if (DOM.countArchive) DOM.countArchive.textContent = notDeleted.filter(i => i.archived).length;
    if (DOM.countTrash) DOM.countTrash.textContent = state.vaultItems.filter(i => i.deleted).length;

    let titleText = 'All Items';
    if (cat === 'login') titleText = 'Logins';
    else if (cat === 'card') titleText = 'Debit Cards';
    else if (cat === 'bank') titleText = 'Bank Accounts';
    else if (cat === 'note') titleText = 'Secure Notes';
    else if (cat === 'favorite') titleText = 'Favorites (Pinned)';
    else if (cat === 'archive') titleText = 'Archive';
    else if (cat === 'trash') titleText = 'Trash';
    
    if (state.selectedTag) titleText = \`Tag: \${state.selectedTag}\`;
    if (q) titleText = \`Search: "\${q}"\`;
    if (DOM.currentCatTitle) DOM.currentCatTitle.textContent = titleText;
    if (DOM.itemsCounter) DOM.itemsCounter.textContent = \`\${items.length} items\`;

    if (items.length === 0) {
      if (DOM.emptyState) DOM.emptyState.classList.remove('hidden');
      if (DOM.itemsContainer) DOM.itemsContainer.classList.add('hidden');
      if (DOM.btnEmptyAdd) DOM.btnEmptyAdd.style.display = (isTrash || isArchive) ? 'none' : 'inline-flex';
    } else {
      if (DOM.emptyState) DOM.emptyState.classList.add('hidden');
      if (DOM.itemsContainer) {
        DOM.itemsContainer.classList.remove('hidden');
        DOM.itemsContainer.innerHTML = ''; // Ensure clear

        // Separation Logic: Pinned vs Others (Only if not in Trash/Archive/Favorites and no Search)
        if (!isTrash && !isArchive && cat !== 'favorite' && !q && !state.selectedTag) {
          const pinned = items.filter(i => i.favorite);
          const others = items.filter(i => !i.favorite);

          if (pinned.length > 0) {
            const pinHeader = document.createElement('h4');
            pinHeader.textContent = 'Pinned';
            pinHeader.style.width = '100%';
            pinHeader.style.margin = '0 0 1rem 0';
            pinHeader.style.color = 'var(--text-muted)';
            pinHeader.style.textTransform = 'uppercase';
            pinHeader.style.fontSize = '0.75rem';
            pinHeader.style.letterSpacing = '1px';
            DOM.itemsContainer.appendChild(pinHeader);
            
            const pinGrid = document.createElement('div');
            pinGrid.className = 'items-grid';
            if (state.viewMode === 'list') pinGrid.classList.add('list-view');
            pinned.forEach(item => { pinGrid.appendChild(createItemCard(item)); });
            DOM.itemsContainer.appendChild(pinGrid);
          }

          if (others.length > 0) {
            const otherHeader = document.createElement('h4');
            otherHeader.textContent = pinned.length > 0 ? 'Others' : 'Items';
            otherHeader.style.width = '100%';
            otherHeader.style.margin = '1.5rem 0 1rem 0';
            otherHeader.style.color = 'var(--text-muted)';
            otherHeader.style.textTransform = 'uppercase';
            otherHeader.style.fontSize = '0.75rem';
            otherHeader.style.letterSpacing = '1px';
            DOM.itemsContainer.appendChild(otherHeader);

            const otherGrid = document.createElement('div');
            otherGrid.className = 'items-grid';
            if (state.viewMode === 'list') otherGrid.classList.add('list-view');
            others.forEach(item => { otherGrid.appendChild(createItemCard(item)); });
            DOM.itemsContainer.appendChild(otherGrid);
          }
        } else {
           // Normal rendering
           const grid = document.createElement('div');
           grid.className = 'items-grid';
           if (state.viewMode === 'list') grid.classList.add('list-view');
           items.forEach(item => { grid.appendChild(createItemCard(item)); });
           DOM.itemsContainer.appendChild(grid);
        }
      }
    }

    updateSidebarTags();
  }`;

code = code.replace(renderVaultRegex, newRenderVault);

// 6. Update createItemCard to add color classes and new menu items
// Re-write createItemCard dropdown items
const createCardMenuRegex = /<button class="btn-card-action edit-item" title="Edit">[\s\S]*?<\/div>/;
const newCardMenu = `<button class="btn-card-action edit-item" title="\${item.deleted ? 'Cannot Edit' : 'Edit'}" \${item.deleted ? 'disabled' : ''}>
              <i class="fa-solid fa-pen"></i>
            </button>
            <div class="card-dropdown-wrapper">
              <button class="btn-card-action btn-dropdown" title="More options">
                <i class="fa-solid fa-ellipsis-vertical"></i>
              </button>
              <div class="card-dropdown-menu hidden">
                \${item.deleted ? \`
                  <button class="menu-action restore-item"><i class="fa-solid fa-rotate-left"></i> Restore</button>
                  <button class="menu-action text-danger wipe-item"><i class="fa-solid fa-fire"></i> Delete Forever</button>
                \` : \`
                  <button class="menu-action fav-item"><i class="\${item.favorite ? 'fa-solid' : 'fa-regular'} fa-star"></i> \${item.favorite ? 'Unpin' : 'Pin to Top'}</button>
                  <button class="menu-action toggle-archive"><i class="fa-solid fa-box-archive"></i> \${item.archived ? 'Unarchive' : 'Archive'}</button>
                  <button class="menu-action text-danger del-item"><i class="fa-solid fa-trash"></i> Move to Trash</button>
                \`}
              </div>
            </div>`;

code = code.replace(createCardMenuRegex, newCardMenu);

// Also add color class to card
code = code.replace(/const card = document\.createElement\('div'\);\r?\n\s+card\.className = 'item-card';/, "const card = document.createElement('div');\n    card.className = `item-card color-${item.color || 'default'}`;");

// Add event listeners for new actions in createItemCard
code = code.replace(/const delBtn = card\.querySelector\('\.del-item'\);\r?\n\s+if \(delBtn\) \{\r?\n\s+delBtn\.addEventListener\('click', \(e\) => \{\r?\n\s+e\.stopPropagation\(\);\r?\n\s+deleteItem\(item\.id\);\r?\n\s+\}\);\r?\n\s+\}/,
`const delBtn = card.querySelector('.del-item');
    if (delBtn) delBtn.addEventListener('click', (e) => { e.stopPropagation(); moveToTrash(item.id); });

    const archiveBtn = card.querySelector('.toggle-archive');
    if (archiveBtn) archiveBtn.addEventListener('click', (e) => { e.stopPropagation(); toggleArchive(item.id); });

    const restoreBtn = card.querySelector('.restore-item');
    if (restoreBtn) restoreBtn.addEventListener('click', (e) => { e.stopPropagation(); restoreFromTrash(item.id); });

    const wipeBtn = card.querySelector('.wipe-item');
    if (wipeBtn) wipeBtn.addEventListener('click', (e) => { e.stopPropagation(); deleteItem(item.id); });`);


// 7. Implement new action functions globally
const actionFuncs = `
  async function moveToTrash(id) {
    const idx = state.vaultItems.findIndex(i => i.id === id);
    if (idx === -1) return;
    state.vaultItems[idx].deleted = true;
    await saveVaultToGitHub();
    renderVault();
    showToast('Item moved to Trash', 'info');
  }

  async function restoreFromTrash(id) {
    const idx = state.vaultItems.findIndex(i => i.id === id);
    if (idx === -1) return;
    state.vaultItems[idx].deleted = false;
    await saveVaultToGitHub();
    renderVault();
    showToast('Item restored', 'success');
  }

  async function toggleArchive(id) {
    const idx = state.vaultItems.findIndex(i => i.id === id);
    if (idx === -1) return;
    state.vaultItems[idx].archived = !state.vaultItems[idx].archived;
    await saveVaultToGitHub();
    renderVault();
    showToast(state.vaultItems[idx].archived ? 'Item archived' : 'Item unarchived', 'info');
  }
`;

code = code.replace(/async function deleteItem\(id\) \{/, actionFuncs + "\n  async function deleteItem(id) {");


// 8. Update Sidebar Tags Logic
const sidebarTagsRegex = /function updateSidebarTags\(\) \{[\s\S]*?    \}\r?\n  \}/;
const newSidebarTags = `function updateSidebarTags() {
    if (!DOM.sidebarTagsNav) return;
    
    // Extract unique tags from non-deleted items
    const allTags = new Set();
    state.vaultItems.forEach(item => {
      if (item.deleted) return;
      if (item.tags && Array.isArray(item.tags)) {
        item.tags.forEach(t => allTags.add(t));
      }
    });

    DOM.sidebarTagsNav.innerHTML = '';
    
    if (allTags.size === 0) {
      DOM.sidebarTagsNav.innerHTML = '<div style="padding: 0.35rem 0.75rem; font-size:0.75rem; color:var(--text-dim);">No labels created yet</div>';
      return;
    }

    const sortedTags = Array.from(allTags).sort();
    sortedTags.forEach(tag => {
      const btn = document.createElement('button');
      btn.className = 'nav-item';
      if (state.selectedTag === tag) btn.classList.add('active');
      btn.innerHTML = \`<i class="fa-solid fa-tag"></i> <span>\${escapeHtml(tag)}</span>\`;
      
      btn.addEventListener('click', () => {
        // Clear category selection
        document.querySelectorAll('.sidebar-nav .nav-item').forEach(n => n.classList.remove('active'));
        btn.classList.add('active');
        state.currentCategory = 'all';
        state.selectedTag = tag;
        switchView(DOM.viewVault);
        renderVault();
        closeMobileMenu();
      });
      DOM.sidebarTagsNav.appendChild(btn);
    });
  }`;

code = code.replace(sidebarTagsRegex, newSidebarTags);

fs.writeFileSync('app.js', code);
console.log('App.js patched successfully!');
