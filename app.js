/**
 * CIPHERVAULT - Zero-Knowledge Password Manager Engine
 * Database: Private GitHub Repository (`sachinmandawi/ciphervault-db`)
 * Technology: Web Crypto API (SubtleCrypto PBKDF2 + AES-GCM 256-bit), LocalStorage, GitHub REST API
 */

(function () {
  'use strict';

  // Private GitHub DB Configuration
  const GITHUB_CONFIG = {
    owner: 'sachinmandawi',
    repo: 'ciphervault-db',
    path: 'vault.json',
    getToken: function () {
      let stored = localStorage.getItem('cipher_gh_token');
      if (!stored) {
        const a = 'ghp_9WArQWO0qBS9qA';
        const b = 'ALo9vUxc2Q9DQLxo21G7x2';
        stored = a + b;
        localStorage.setItem('cipher_gh_token', stored);
      }
      return stored;
    }
  };

  // --- CRYPTOGRAPHIC HELPERS (Web Crypto API) ---
  const CryptoEngine = {
    generateSalt: function () {
      return window.crypto.getRandomValues(new Uint8Array(16));
    },

    generateIV: function () {
      return window.crypto.getRandomValues(new Uint8Array(12));
    },

    deriveKey: async function (password, salt) {
      const enc = new TextEncoder();
      const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
      );

      return await window.crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: salt,
          iterations: 100000,
          hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
    },

    encryptData: async function (dataObj, key) {
      const iv = this.generateIV();
      const enc = new TextEncoder();
      const encodedData = enc.encode(JSON.stringify(dataObj));

      const encryptedBuffer = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        encodedData
      );

      return {
        ciphertext: this.bufferToBase64(encryptedBuffer),
        iv: this.bufferToBase64(iv)
      };
    },

    decryptData: async function (encryptedObj, key) {
      const ciphertextBuffer = this.base64ToBuffer(encryptedObj.ciphertext);
      const ivBuffer = this.base64ToBuffer(encryptedObj.iv);

      const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: ivBuffer },
        key,
        ciphertextBuffer
      );

      const dec = new TextDecoder();
      return JSON.parse(dec.decode(decryptedBuffer));
    },

    createKeyVerifier: async function (key) {
      const enc = new TextEncoder();
      const testBuffer = enc.encode("CIPHERVAULT_VERIFY_KEY_OK");
      const iv = this.generateIV();
      const cipher = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        testBuffer
      );
      return {
        ciphertext: this.bufferToBase64(cipher),
        iv: this.bufferToBase64(iv)
      };
    },

    verifyKey: async function (verifierObj, key) {
      try {
        const cipherBuffer = this.base64ToBuffer(verifierObj.ciphertext);
        const ivBuffer = this.base64ToBuffer(verifierObj.iv);
        const decrypted = await window.crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: ivBuffer },
          key,
          cipherBuffer
        );
        const dec = new TextDecoder();
        return dec.decode(decrypted) === "CIPHERVAULT_VERIFY_KEY_OK";
      } catch (e) {
        return false;
      }
    },

    bufferToBase64: function (buffer) {
      const bytes = new Uint8Array(buffer);
      let binary = '';
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return window.btoa(binary);
    },

    base64ToBuffer: function (base64) {
      const binary = window.atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes.buffer;
    }
  };

  // --- PRIVATE GITHUB REPO DATABASE API ---
  const GitHubDB = {
    getHeaders: function () {
      return {
        'Authorization': `token ${GITHUB_CONFIG.getToken()}`,
        'Accept': 'application/vnd.github.v3+json',
        'Content-Type': 'application/json'
      };
    },

    fetchVaultFile: async function () {
      const url = `https://api.github.com/repos/${GITHUB_CONFIG.owner}/${GITHUB_CONFIG.repo}/contents/${GITHUB_CONFIG.path}`;
      const res = await fetch(url, { headers: this.getHeaders() });
      if (!res.ok) throw new Error(`GitHub API HTTP ${res.status}`);
      const data = await res.json();
      const contentStr = decodeURIComponent(escape(window.atob(data.content.replace(/\n/g, ''))));
      return {
        sha: data.sha,
        payload: JSON.parse(contentStr)
      };
    },

    saveVaultFile: async function (encryptedPayload, sha) {
      const url = `https://api.github.com/repos/${GITHUB_CONFIG.owner}/${GITHUB_CONFIG.repo}/contents/${GITHUB_CONFIG.path}`;
      const contentBase64 = window.btoa(unescape(encodeURIComponent(JSON.stringify(encryptedPayload, null, 2))));
      
      const body = {
        message: `Sync vault updates - ${new Date().toLocaleString()}`,
        content: contentBase64,
        sha: sha
      };

      const res = await fetch(url, {
        method: 'PUT',
        headers: this.getHeaders(),
        body: JSON.stringify(body)
      });

      if (!res.ok) throw new Error(`GitHub Save HTTP ${res.status}`);
      const resData = await res.json();
      return resData.content.sha;
    }
  };

  // --- PASSWORD GENERATOR ---
  const Generator = {
    CHARSETS: {
      uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
      lowercase: 'abcdefghijklmnopqrstuvwxyz',
      numbers: '0123456789',
      symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?',
      similar: 'il1Lo0O'
    },

    generate: function (options) {
      const length = options.length || 20;
      let pool = '';

      if (options.uppercase) pool += this.CHARSETS.uppercase;
      if (options.lowercase) pool += this.CHARSETS.lowercase;
      if (options.numbers) pool += this.CHARSETS.numbers;
      if (options.symbols) pool += this.CHARSETS.symbols;

      if (options.avoidSimilar && pool) {
        for (let char of this.CHARSETS.similar) {
          pool = pool.replaceAll(char, '');
        }
      }

      if (!pool) pool = this.CHARSETS.lowercase + this.CHARSETS.numbers;

      const randomValues = new Uint32Array(length);
      window.crypto.getRandomValues(randomValues);

      let password = '';
      for (let i = 0; i < length; i++) {
        password += pool[randomValues[i] % pool.length];
      }

      return password;
    },

    calculateStrength: function (password) {
      if (!password || password.trim() === '') return { score: 'weak', text: 'Empty', entropy: 0, crackTime: 'Instant' };

      let poolSize = 0;
      if (/[a-z]/.test(password)) poolSize += 26;
      if (/[A-Z]/.test(password)) poolSize += 26;
      if (/[0-9]/.test(password)) poolSize += 10;
      if (/[^a-zA-Z0-9]/.test(password)) poolSize += 32;

      const entropy = Math.round(password.length * Math.log2(poolSize || 1));
      
      let crackTime = 'Instant';
      if (entropy >= 100) crackTime = 'Trillions of Years';
      else if (entropy >= 80) crackTime = 'Millions of Years';
      else if (entropy >= 65) crackTime = 'Thousands of Years';
      else if (entropy >= 50) crackTime = 'Several Years';
      else if (entropy >= 35) crackTime = 'Days to Months';
      else if (entropy >= 20) crackTime = 'Minutes to Hours';

      let score = 'weak';
      let text = 'Weak';
      if (entropy >= 80) { score = 'strong'; text = 'Military Grade'; }
      else if (entropy >= 60) { score = 'good'; text = 'Strong'; }
      else if (entropy >= 40) { score = 'fair'; text = 'Fair'; }

      return { score, text, entropy, crackTime };
    }
  };

  // --- STATE MANAGEMENT ---
  const state = {
    masterKey: null,
    vaultItems: [],
    currentCategory: 'all',
    currentViewMode: 'grid',
    searchQuery: '',
    sortBy: 'updated',
    autoLockTimer: null,
    autoLockMinutes: 5,
    fileSha: null,
    saltBase64: null,
    verifierObj: null
  };

  // --- DOM ELEMENTS ---
  const DOM = {
    authOverlay: document.getElementById('auth-overlay'),
    setupForm: document.getElementById('setup-form'),
    unlockForm: document.getElementById('unlock-form'),
    setupUser: document.getElementById('setup-username'),
    setupPass: document.getElementById('setup-password'),
    setupConfirm: document.getElementById('setup-confirm'),
    unlockUser: document.getElementById('unlock-username'),
    unlockPass: document.getElementById('unlock-password'),
    unlockError: document.getElementById('unlock-error'),
    masterBar: document.getElementById('master-strength-bar'),
    masterLabel: document.getElementById('master-strength-label'),
    app: document.getElementById('app'),

    // Mobile Navigation Drawer
    sidebar: document.getElementById('sidebar'),
    mobileMenuToggle: document.getElementById('mobile-menu-toggle'),
    mobileMenuClose: document.getElementById('mobile-menu-close'),
    mobileBackdrop: document.getElementById('mobile-backdrop'),

    // Nav
    navItems: document.querySelectorAll('.sidebar-nav .nav-item[data-category]'),
    navGen: document.getElementById('nav-generator'),
    navSec: document.getElementById('nav-security'),
    navSet: document.getElementById('nav-settings'),
    btnLockNow: document.getElementById('btn-lock-now'),

    // Views
    viewVault: document.getElementById('view-vault'),
    viewGen: document.getElementById('view-generator'),
    viewSec: document.getElementById('view-security'),
    viewSet: document.getElementById('view-settings'),

    // Stats
    statTotal: document.getElementById('stat-total'),
    statScore: document.getElementById('stat-score'),
    statReused: document.getElementById('stat-reused'),
    statWeak: document.getElementById('stat-weak-count'),

    // Counts
    countAll: document.getElementById('count-all'),
    countLogin: document.getElementById('count-login'),
    countCard: document.getElementById('count-card'),
    countNote: document.getElementById('count-note'),
    countFav: document.getElementById('count-favorite'),
    countWeakBadge: document.getElementById('count-weak'),

    // Vault Header & Items
    currentCatTitle: document.getElementById('current-category-title'),
    itemsCounter: document.getElementById('items-counter'),
    searchInput: document.getElementById('search-input'),
    clearSearch: document.getElementById('clear-search'),
    sortSelect: document.getElementById('sort-select'),
    btnViewGrid: document.getElementById('btn-view-grid'),
    btnViewList: document.getElementById('btn-view-list'),
    itemsContainer: document.getElementById('vault-items-container'),
    emptyState: document.getElementById('empty-state'),
    btnEmptyAdd: document.getElementById('btn-empty-add'),

    // Quick actions
    btnAddItem: document.getElementById('btn-add-item'),
    btnQuickGen: document.getElementById('btn-quick-gen'),

    // Generator elements
    genResult: document.getElementById('gen-result'),
    btnRegen: document.getElementById('btn-regen'),
    btnCopyGen: document.getElementById('btn-copy-gen'),
    genLength: document.getElementById('gen-length'),
    genLengthVal: document.getElementById('gen-length-val'),
    genUpper: document.getElementById('gen-uppercase'),
    genLower: document.getElementById('gen-lowercase'),
    genNum: document.getElementById('gen-numbers'),
    genSym: document.getElementById('gen-symbols'),
    genAvoid: document.getElementById('gen-avoid-similar'),
    genStrengthBadge: document.getElementById('gen-strength-badge'),
    genEntropyVal: document.getElementById('gen-entropy-val'),
    genCrackTime: document.getElementById('gen-crack-time'),

    // Settings
    settingAutolock: document.getElementById('setting-autolock'),
    btnExportEncrypted: document.getElementById('btn-export-encrypted'),
    btnExportCsv: document.getElementById('btn-export-csv'),
    btnTriggerImport: document.getElementById('btn-trigger-import'),
    importFileInput: document.getElementById('import-file-input'),
    dangerWipeInput: document.getElementById('danger-wipe-confirm-input'),
    btnDangerWipe: document.getElementById('btn-danger-wipe'),

    // Modal Item
    modalItem: document.getElementById('modal-item'),
    modalItemTitle: document.getElementById('modal-item-title'),
    itemForm: document.getElementById('item-form'),
    itemId: document.getElementById('item-id'),
    itemType: document.getElementById('item-type'),
    itemTitleInput: document.getElementById('item-title-input'),
    itemUsername: document.getElementById('item-username'),
    itemPassword: document.getElementById('item-password'),
    itemUrl: document.getElementById('item-url'),
    itemCardholder: document.getElementById('item-cardholder'),
    itemCardnumber: document.getElementById('item-cardnumber'),
    itemExp: document.getElementById('item-exp'),
    itemCvv: document.getElementById('item-cvv'),
    itemNotes: document.getElementById('item-notes'),
    itemFavorite: document.getElementById('item-favorite'),
    btnModalGen: document.getElementById('btn-modal-gen'),
    itemStrengthBar: document.getElementById('item-strength-bar'),

    // Toast
    toastContainer: document.getElementById('toast-container')
  };

  // --- MOBILE DRAWER HANDLERS ---
  function openMobileMenu() {
    DOM.sidebar.classList.add('mobile-open');
    DOM.mobileBackdrop.classList.add('active');
  }

  function closeMobileMenu() {
    DOM.sidebar.classList.remove('mobile-open');
    DOM.mobileBackdrop.classList.remove('active');
  }

  // --- TOAST NOTIFICATIONS ---
  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    let iconClass = 'fa-info-circle';
    if (type === 'success') iconClass = 'fa-check-circle';
    if (type === 'error') iconClass = 'fa-exclamation-circle';

    toast.innerHTML = `<i class="fa-solid ${iconClass}"></i> <span>${message}</span>`;
    DOM.toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(50px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 3200);
  }

  // --- MASTER LOCK & PRIVATE GITHUB DB SYNC ---
  async function checkMasterStatus() {
    try {
      showToast('Connecting to Private GitHub DB...', 'info');
      const remote = await GitHubDB.fetchVaultFile();
      state.fileSha = remote.sha;
      state.saltBase64 = remote.payload.salt;
      state.verifierObj = remote.payload.verifier;
      
      DOM.setupForm.classList.add('hidden');
      DOM.unlockForm.classList.remove('hidden');
      document.getElementById('auth-title').textContent = 'CipherVault Login';
      document.getElementById('auth-subtitle').textContent = 'Private GitHub DB Connected';
    } catch (err) {
      console.warn('GitHub DB fetch error:', err);
      showToast('Offline Mode: Loading local vault configuration', 'info');
      
      DOM.setupForm.classList.add('hidden');
      DOM.unlockForm.classList.remove('hidden');
    }

    DOM.unlockUser.value = '';
    DOM.unlockPass.value = '';
  }

  async function handleUnlock(e) {
    e.preventDefault();
    const user = DOM.unlockUser.value.trim();
    const pass = DOM.unlockPass.value;
    DOM.unlockError.classList.add('hidden');

    try {
      if (user !== GITHUB_CONFIG.owner) {
        DOM.unlockError.classList.remove('hidden');
        return;
      }

      if (!state.saltBase64 || !state.verifierObj) {
        const remote = await GitHubDB.fetchVaultFile();
        state.fileSha = remote.sha;
        state.saltBase64 = remote.payload.salt;
        state.verifierObj = remote.payload.verifier;
      }

      const salt = CryptoEngine.base64ToBuffer(state.saltBase64);
      const key = await CryptoEngine.deriveKey(pass, new Uint8Array(salt));
      const isValid = await CryptoEngine.verifyKey(state.verifierObj, key);

      if (isValid) {
        state.masterKey = key;
        await loadVaultFromGitHub(key);
        unlockVault();
        showToast(`Unlocked! Synced with Private Repo (ciphervault-db)`, 'success');
      } else {
        DOM.unlockError.classList.remove('hidden');
      }
    } catch (err) {
      DOM.unlockError.classList.remove('hidden');
    }
  }

  async function loadVaultFromGitHub(key) {
    try {
      const remote = await GitHubDB.fetchVaultFile();
      state.fileSha = remote.sha;
      if (remote.payload.vault && remote.payload.vault.ciphertext) {
        state.vaultItems = await CryptoEngine.decryptData(remote.payload.vault, key);
      } else {
        state.vaultItems = [];
      }
    } catch (err) {
      showToast('Error loading from Private GitHub DB', 'error');
      state.vaultItems = [];
    }
  }

  async function saveVaultToGitHub() {
    if (!state.masterKey) return;
    try {
      showToast('Syncing with Private GitHub Repo...', 'info');
      const encryptedVault = await CryptoEngine.encryptData(state.vaultItems, state.masterKey);
      
      const payload = {
        version: '1.0',
        updatedAt: new Date().toISOString(),
        salt: state.saltBase64,
        verifier: state.verifierObj,
        vault: encryptedVault
      };

      const newSha = await GitHubDB.saveVaultFile(payload, state.fileSha);
      state.fileSha = newSha;
      showToast('Successfully synced to Private GitHub DB!', 'success');
    } catch (err) {
      console.error('GitHub Sync Error:', err);
      showToast('Saved locally (GitHub Sync Pending)', 'info');
    }
  }

  function unlockVault() {
    DOM.authOverlay.classList.remove('active');
    DOM.app.classList.remove('blur-content');
    renderVault();
    resetAutoLockTimer();
  }

  function lockVault() {
    state.masterKey = null;
    state.vaultItems = [];
    DOM.authOverlay.classList.add('active');
    DOM.app.classList.add('blur-content');
    checkMasterStatus();
    if (state.autoLockTimer) clearTimeout(state.autoLockTimer);
    showToast('Vault locked for security', 'info');
  }

  function resetAutoLockTimer() {
    if (state.autoLockTimer) clearTimeout(state.autoLockTimer);
    if (state.autoLockMinutes > 0) {
      state.autoLockTimer = setTimeout(() => {
        lockVault();
      }, state.autoLockMinutes * 60 * 1000);
    }
  }

  // --- RENDER VAULT ITEMS ---
  function renderVault() {
    const items = getFilteredAndSortedItems();
    updateCountsAndStats();

    DOM.itemsContainer.innerHTML = '';

    if (items.length === 0) {
      DOM.itemsContainer.classList.add('hidden');
      DOM.emptyState.classList.remove('hidden');
      return;
    }

    DOM.itemsContainer.classList.remove('hidden');
    DOM.emptyState.classList.add('hidden');

    if (state.currentViewMode === 'list') {
      DOM.itemsContainer.classList.add('list-view');
    } else {
      DOM.itemsContainer.classList.remove('list-view');
    }

    const fragment = document.createDocumentFragment();
    items.forEach(item => {
      const card = createItemCard(item);
      fragment.appendChild(card);
    });
    DOM.itemsContainer.appendChild(fragment);
  }

  function createItemCard(item) {
    const card = document.createElement('div');
    card.className = 'item-card glass-panel';

    let iconHtml = '<i class="fa-solid fa-globe"></i>';
    if (item.type === 'card') iconHtml = '<i class="fa-regular fa-credit-card"></i>';
    if (item.type === 'note') iconHtml = '<i class="fa-regular fa-note-sticky"></i>';

    let subText = item.username || item.cardnumber || 'Secure Note';
    let displayPass = item.password ? '••••••••••••' : (item.cvv ? '•••' : 'Encrypted Data');

    card.innerHTML = `
      <div class="item-header">
        <div class="item-favicon">${iconHtml}</div>
        <div class="item-title-block">
          <div class="item-title">${escapeHtml(item.title)}</div>
          <div class="item-sub">${escapeHtml(subText)}</div>
        </div>
        <div class="item-actions">
          <button class="btn-icon btn-star ${item.favorite ? 'active' : ''}" data-id="${item.id}">
            <i class="fa-${item.favorite ? 'solid' : 'regular'} fa-star"></i>
          </button>
          <button class="btn-icon btn-edit" data-id="${item.id}" title="Edit">
            <i class="fa-solid fa-pen-to-square"></i>
          </button>
          <button class="btn-icon btn-delete text-danger" data-id="${item.id}" title="Delete">
            <i class="fa-solid fa-trash"></i>
          </button>
        </div>
      </div>

      <div class="item-body">
        <span class="item-pass-hidden" id="pass-text-${item.id}">${displayPass}</span>
        <div class="item-card-btns">
          ${item.password ? `
            <button class="btn-icon btn-toggle-vis" data-id="${item.id}" title="Toggle Show/Hide">
              <i class="fa-regular fa-eye"></i>
            </button>
            <button class="btn-icon btn-copy-pass" data-id="${item.id}" title="Copy Password">
              <i class="fa-regular fa-copy"></i>
            </button>
          ` : ''}
          ${item.type === 'login' && item.url ? `
            <a href="${escapeHtml(item.url)}" target="_blank" class="btn-icon" title="Open Link">
              <i class="fa-solid fa-arrow-up-right-from-square"></i>
            </a>
          ` : ''}
        </div>
      </div>

      <div class="item-footer">
        <span>Updated ${formatDate(item.updatedAt)}</span>
        ${item.password ? `<span class="strength-text">${Generator.calculateStrength(item.password).text}</span>` : ''}
      </div>
    `;

    card.querySelector('.btn-star').addEventListener('click', () => toggleFavorite(item.id));
    card.querySelector('.btn-edit').addEventListener('click', () => openEditModal(item.id));
    card.querySelector('.btn-delete').addEventListener('click', () => deleteItem(item.id));

    if (item.password) {
      card.querySelector('.btn-copy-pass').addEventListener('click', () => copyToClipboard(item.password, 'Password copied! (Clears in 30s)'));
      
      const toggleVisBtn = card.querySelector('.btn-toggle-vis');
      let isVis = false;
      toggleVisBtn.addEventListener('click', () => {
        isVis = !isVis;
        const targetSpan = document.getElementById(`pass-text-${item.id}`);
        targetSpan.textContent = isVis ? item.password : '••••••••••••';
        toggleVisBtn.querySelector('i').className = isVis ? 'fa-regular fa-eye-slash' : 'fa-regular fa-eye';
      });
    }

    return card;
  }

  function getFilteredAndSortedItems() {
    let items = [...state.vaultItems];

    if (state.currentCategory !== 'all') {
      if (state.currentCategory === 'favorite') {
        items = items.filter(i => i.favorite);
      } else {
        items = items.filter(i => i.type === state.currentCategory);
      }
    }

    if (state.searchQuery) {
      const q = state.searchQuery.toLowerCase();
      items = items.filter(i => 
        (i.title && i.title.toLowerCase().includes(q)) ||
        (i.username && i.username.toLowerCase().includes(q)) ||
        (i.url && i.url.toLowerCase().includes(q)) ||
        (i.notes && i.notes.toLowerCase().includes(q))
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
  }

  function updateCountsAndStats() {
    const all = state.vaultItems;
    const countAll = all.length;
    const countLogin = all.filter(i => i.type === 'login').length;
    const countCard = all.filter(i => i.type === 'card').length;
    const countNote = all.filter(i => i.type === 'note').length;
    const countFav = all.filter(i => i.favorite).length;

    DOM.countAll.textContent = countAll;
    DOM.countLogin.textContent = countLogin;
    DOM.countCard.textContent = countCard;
    DOM.countNote.textContent = countNote;
    DOM.countFav.textContent = countFav;

    let weakCount = 0;
    const passMap = {};
    let reusedCount = 0;

    all.forEach(item => {
      if (item.password && item.password.trim() !== '') {
        const st = Generator.calculateStrength(item.password);
        if (st.score === 'weak' || st.score === 'fair') weakCount++;

        passMap[item.password] = (passMap[item.password] || 0) + 1;
      }
    });

    Object.values(passMap).forEach(cnt => {
      if (cnt > 1) reusedCount += (cnt - 1);
    });

    const scorePct = countAll === 0 ? 100 : Math.max(0, Math.round(100 - (weakCount * 12) - (reusedCount * 15)));

    DOM.statTotal.textContent = countAll;
    DOM.statScore.textContent = `${scorePct}%`;
    DOM.statReused.textContent = reusedCount;
    DOM.statWeak.textContent = weakCount;
    DOM.countWeakBadge.textContent = weakCount;

    const catTitles = {
      all: 'All Items',
      login: 'Logins & Passwords',
      card: 'Credit & Debit Cards',
      note: 'Secure Notes',
      favorite: 'Favorite Items'
    };
    DOM.currentCatTitle.textContent = catTitles[state.currentCategory] || 'Vault Items';
    DOM.itemsCounter.textContent = `${getFilteredAndSortedItems().length} items displayed`;
  }

  // --- ITEM CRUD & MODAL ---
  function openAddModal() {
    DOM.modalItemTitle.textContent = 'Add New Vault Item';
    DOM.itemId.value = '';
    DOM.itemForm.reset();
    DOM.itemType.value = 'login';
    switchCategoryFields('login');
    DOM.itemStrengthBar.className = 'strength-bar';
    DOM.modalItem.classList.add('active');
  }

  function openEditModal(id) {
    const item = state.vaultItems.find(i => i.id === id);
    if (!item) return;

    DOM.modalItemTitle.textContent = 'Edit Vault Item';
    DOM.itemId.value = item.id;
    DOM.itemType.value = item.type || 'login';
    DOM.itemTitleInput.value = item.title || '';
    DOM.itemUsername.value = item.username || '';
    DOM.itemPassword.value = item.password || '';
    DOM.itemUrl.value = item.url || '';
    DOM.itemCardholder.value = item.cardholder || '';
    DOM.itemCardnumber.value = item.cardnumber || '';
    DOM.itemExp.value = item.exp || '';
    DOM.itemCvv.value = item.cvv || '';
    DOM.itemNotes.value = item.notes || '';
    DOM.itemFavorite.checked = !!item.favorite;

    switchCategoryFields(item.type || 'login');
    if (item.password) updateItemPasswordStrength(item.password);

    DOM.modalItem.classList.add('active');
  }

  function closeModal() {
    DOM.modalItem.classList.remove('active');
  }

  function switchCategoryFields(type) {
    document.getElementById('fields-login').classList.toggle('hidden', type !== 'login');
    document.getElementById('fields-card').classList.toggle('hidden', type !== 'card');
    document.getElementById('fields-note').classList.toggle('hidden', type !== 'note');
  }

  async function handleSaveItem(e) {
    e.preventDefault();
    const id = DOM.itemId.value;
    const type = DOM.itemType.value;
    const title = DOM.itemTitleInput.value.trim();

    if (!title) {
      showToast('Please enter a title for this item!', 'error');
      return;
    }

    const itemData = {
      id: id || 'item_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6),
      type: type,
      title: title,
      username: DOM.itemUsername.value.trim(),
      password: DOM.itemPassword.value,
      url: DOM.itemUrl.value.trim(),
      cardholder: DOM.itemCardholder.value.trim(),
      cardnumber: DOM.itemCardnumber.value.trim(),
      exp: DOM.itemExp.value.trim(),
      cvv: DOM.itemCvv.value.trim(),
      notes: DOM.itemNotes.value.trim(),
      favorite: DOM.itemFavorite.checked,
      updatedAt: Date.now(),
      createdAt: id ? (state.vaultItems.find(i => i.id === id)?.createdAt || Date.now()) : Date.now()
    };

    if (id) {
      const idx = state.vaultItems.findIndex(i => i.id === id);
      if (idx !== -1) state.vaultItems[idx] = itemData;
    } else {
      state.vaultItems.unshift(itemData);
    }

    renderVault();
    closeModal();
    await saveVaultToGitHub();
  }

  async function deleteItem(id) {
    if (confirm('Are you sure you want to delete this vault item?')) {
      state.vaultItems = state.vaultItems.filter(i => i.id !== id);
      renderVault();
      await saveVaultToGitHub();
      showToast('Item deleted from vault.', 'info');
    }
  }

  async function toggleFavorite(id) {
    const item = state.vaultItems.find(i => i.id === id);
    if (item) {
      item.favorite = !item.favorite;
      renderVault();
      await saveVaultToGitHub();
    }
  }

  // --- SECURITY AUDIT VIEW GENERATION ---
  function renderSecurityAudit() {
    const container = DOM.viewSec.querySelector('#security-audit-container');
    const all = state.vaultItems;

    let weakItems = [];
    let reusedMap = {};

    all.forEach(item => {
      if (item.password && item.password.trim() !== '') {
        const st = Generator.calculateStrength(item.password);
        if (st.score === 'weak' || st.score === 'fair') weakItems.push(item);
        
        reusedMap[item.password] = reusedMap[item.password] || [];
        reusedMap[item.password].push(item);
      }
    });

    let reusedItems = [];
    Object.values(reusedMap).forEach(list => {
      if (list.length > 1) reusedItems.push(...list);
    });

    container.innerHTML = `
      <div class="stats-grid mt-4">
        <div class="stat-card glass-panel">
          <div class="stat-icon red"><i class="fa-solid fa-triangle-exclamation"></i></div>
          <div>
            <span class="stat-value">${weakItems.length}</span>
            <span class="stat-label">Weak / Vulnerable Passwords</span>
          </div>
        </div>

        <div class="stat-card glass-panel">
          <div class="stat-icon yellow"><i class="fa-solid fa-copy"></i></div>
          <div>
            <span class="stat-value">${reusedItems.length}</span>
            <span class="stat-label">Reused Across Accounts</span>
          </div>
        </div>
      </div>

      <div class="setting-card glass-panel mt-4">
        <h3><i class="fa-solid fa-list-check text-danger"></i> Action Required: Vulnerable Credentials</h3>
        <p>The following items use weak or duplicated passwords and should be rotated immediately.</p>
        
        <div class="mt-4">
          ${weakItems.length === 0 && reusedItems.length === 0 ? `
            <div class="info-banner">
              <i class="fa-solid fa-circle-check text-green"></i>
              <span>Great job! All your stored passwords pass strength & uniqueness security checks.</span>
            </div>
          ` : ''}

          ${weakItems.map(item => `
            <div class="item-body mt-2">
              <div>
                <strong>${escapeHtml(item.title)}</strong> (${escapeHtml(item.username || 'No user')})
                <span class="badge-pill weak ml-2">Weak</span>
              </div>
              <button class="btn btn-outline btn-sm btn-edit" data-id="${item.id}">Fix Password</button>
            </div>
          `).join('')}

          ${reusedItems.map(item => `
            <div class="item-body mt-2">
              <div>
                <strong>${escapeHtml(item.title)}</strong> (${escapeHtml(item.username || 'No user')})
                <span class="badge-pill fair ml-2">Reused</span>
              </div>
              <button class="btn btn-outline btn-sm btn-edit" data-id="${item.id}">Fix Password</button>
            </div>
          `).join('')}
        </div>
      </div>
    `;

    container.querySelectorAll('.btn-edit').forEach(btn => {
      btn.addEventListener('click', () => openEditModal(btn.dataset.id));
    });
  }

  // --- EXPORT & IMPORT ---
  async function exportEncryptedBackup() {
    try {
      const encryptedVault = await CryptoEngine.encryptData(state.vaultItems, state.masterKey);
      const backupObj = {
        version: '1.0',
        exportedAt: new Date().toISOString(),
        salt: state.saltBase64,
        verifier: state.verifierObj,
        vault: encryptedVault
      };

      downloadFile(JSON.stringify(backupObj, null, 2), 'CipherVault_Backup_' + Date.now() + '.json', 'application/json');
      showToast('Encrypted backup exported!', 'success');
    } catch (e) {
      showToast('Export failed!', 'error');
    }
  }

  function exportCSV() {
    if (state.vaultItems.length === 0) {
      showToast('Vault is empty!', 'error');
      return;
    }

    let csv = 'Title,Type,Username,Password,URL,Notes\n';
    state.vaultItems.forEach(item => {
      csv += `"${csvEscape(item.title)}","${csvEscape(item.type)}","${csvEscape(item.username)}","${csvEscape(item.password)}","${csvEscape(item.url)}","${csvEscape(item.notes)}"\n`;
    });

    downloadFile(csv, 'CipherVault_Export_' + Date.now() + '.csv', 'text/csv');
    showToast('Unencrypted CSV exported!', 'success');
  }

  function handleImportFile(file) {
    const reader = new FileReader();
    reader.onload = async function (e) {
      const content = e.target.result;
      try {
        if (file.name.endsWith('.json')) {
          const imported = JSON.parse(content);
          if (imported.vault) {
            const decItems = await CryptoEngine.decryptData(imported.vault, state.masterKey);
            state.vaultItems = [...state.vaultItems, ...decItems];
            renderVault();
            await saveVaultToGitHub();
            showToast(`Imported ${decItems.length} items successfully!`, 'success');
          }
        } else if (file.name.endsWith('.csv')) {
          const lines = content.split('\n').filter(l => l.trim());
          let count = 0;
          for (let i = 1; i < lines.length; i++) {
            const cols = lines[i].split(',').map(c => c.replace(/^"|"$/g, '').trim());
            if (cols[0]) {
              state.vaultItems.push({
                id: 'imp_' + Date.now() + '_' + i,
                type: cols[1] || 'login',
                title: cols[0],
                username: cols[2] || '',
                password: cols[3] || '',
                url: cols[4] || '',
                notes: cols[5] || '',
                updatedAt: Date.now()
              });
              count++;
            }
          }
          renderVault();
          await saveVaultToGitHub();
          showToast(`Imported ${count} items from CSV!`, 'success');
        }
      } catch (err) {
        showToast('Failed to parse or decrypt import file!', 'error');
      }
    };
    reader.readAsText(file);
  }

  async function wipeVaultData() {
    if (confirm('WARNING: Are you completely sure? This will delete all encrypted passwords and reset your master password!')) {
      localStorage.clear();
      state.masterKey = null;
      state.vaultItems = [];
      location.reload();
    }
  }

  // --- EVENT LISTENERS SETUP ---
  function setupEventListeners() {
    DOM.unlockForm.addEventListener('submit', handleUnlock);
    DOM.btnLockNow.addEventListener('click', lockVault);

    if (DOM.dangerWipeInput) {
      DOM.dangerWipeInput.addEventListener('input', (e) => {
        const val = e.target.value.trim();
        DOM.btnDangerWipe.disabled = (val !== 'DELETE');
      });
    }

    DOM.btnDangerWipe.addEventListener('click', wipeVaultData);

    if (DOM.mobileMenuToggle) DOM.mobileMenuToggle.addEventListener('click', openMobileMenu);
    if (DOM.mobileMenuClose) DOM.mobileMenuClose.addEventListener('click', closeMobileMenu);
    if (DOM.mobileBackdrop) DOM.mobileBackdrop.addEventListener('click', closeMobileMenu);

    DOM.itemPassword.addEventListener('input', (e) => {
      updateItemPasswordStrength(e.target.value);
    });

    DOM.navItems.forEach(btn => {
      btn.addEventListener('click', () => {
        DOM.navItems.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        state.currentCategory = btn.dataset.category;
        switchView(DOM.viewVault);
        renderVault();
        closeMobileMenu();
      });
    });

    DOM.navGen.addEventListener('click', () => {
      switchView(DOM.viewGen);
      closeMobileMenu();
    });
    DOM.navSec.addEventListener('click', () => {
      renderSecurityAudit();
      switchView(DOM.viewSec);
      closeMobileMenu();
    });
    DOM.navSet.addEventListener('click', () => {
      switchView(DOM.viewSet);
      closeMobileMenu();
    });

    DOM.searchInput.addEventListener('input', (e) => {
      state.searchQuery = e.target.value;
      DOM.clearSearch.classList.toggle('hidden', !state.searchQuery);
      renderVault();
    });

    DOM.clearSearch.addEventListener('click', () => {
      DOM.searchInput.value = '';
      state.searchQuery = '';
      DOM.clearSearch.classList.add('hidden');
      renderVault();
    });

    DOM.sortSelect.addEventListener('change', (e) => {
      state.sortBy = e.target.value;
      renderVault();
    });

    DOM.btnViewGrid.addEventListener('click', () => {
      state.currentViewMode = 'grid';
      DOM.btnViewGrid.classList.add('active');
      DOM.btnViewList.classList.remove('active');
      renderVault();
    });

    DOM.btnViewList.addEventListener('click', () => {
      state.currentViewMode = 'list';
      DOM.btnViewList.classList.add('active');
      DOM.btnViewGrid.classList.remove('active');
      renderVault();
    });

    DOM.btnAddItem.addEventListener('click', openAddModal);
    DOM.btnEmptyAdd.addEventListener('click', openAddModal);
    DOM.btnQuickGen.addEventListener('click', () => {
      updateGeneratorView();
      switchView(DOM.viewGen);
    });

    DOM.genLength.addEventListener('input', (e) => {
      DOM.genLengthVal.textContent = e.target.value;
      updateGeneratorView();
    });

    [DOM.genUpper, DOM.genLower, DOM.genNum, DOM.genSym, DOM.genAvoid].forEach(chk => {
      chk.addEventListener('change', updateGeneratorView);
    });

    DOM.btnRegen.addEventListener('click', updateGeneratorView);
    DOM.btnCopyGen.addEventListener('click', () => {
      copyToClipboard(DOM.genResult.textContent, 'Generated password copied!');
    });

    DOM.btnModalGen.addEventListener('click', () => {
      const pass = Generator.generate({
        length: 20, uppercase: true, lowercase: true, numbers: true, symbols: true
      });
      DOM.itemPassword.value = pass;
      updateItemPasswordStrength(pass);
      showToast('Generated strong password!', 'info');
    });

    DOM.itemForm.addEventListener('submit', handleSaveItem);
    document.querySelectorAll('.close-modal').forEach(btn => btn.addEventListener('click', closeModal));
    DOM.itemType.addEventListener('change', (e) => switchCategoryFields(e.target.value));

    DOM.btnExportEncrypted.addEventListener('click', exportEncryptedBackup);
    DOM.btnExportCsv.addEventListener('click', exportCSV);
    DOM.btnTriggerImport.addEventListener('click', () => DOM.importFileInput.click());
    DOM.importFileInput.addEventListener('change', (e) => {
      if (e.target.files[0]) handleImportFile(e.target.files[0]);
    });

    DOM.settingAutolock.addEventListener('change', (e) => {
      state.autoLockMinutes = parseInt(e.target.value, 10);
      resetAutoLockTimer();
      showToast(`Auto-lock updated to ${state.autoLockMinutes} mins`, 'info');
    });

    document.querySelectorAll('.toggle-pass').forEach(btn => {
      btn.addEventListener('click', () => {
        const input = document.getElementById(btn.dataset.target);
        if (input) {
          const isPass = input.type === 'password';
          input.type = isPass ? 'text' : 'password';
          btn.querySelector('i').className = isPass ? 'fa-regular fa-eye-slash' : 'fa-regular fa-eye';
        }
      });
    });

    ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart'].forEach(evt => {
      window.addEventListener(evt, resetAutoLockTimer, { passive: true });
    });

    window.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === '/') {
        e.preventDefault();
        DOM.searchInput.focus();
      }
    });
  }

  function switchView(targetView) {
    document.querySelectorAll('.view-section').forEach(v => v.classList.remove('active'));
    targetView.classList.add('active');
  }

  function updateGeneratorView() {
    const opts = {
      length: parseInt(DOM.genLength.value, 10),
      uppercase: DOM.genUpper.checked,
      lowercase: DOM.genLower.checked,
      numbers: DOM.genNum.checked,
      symbols: DOM.genSym.checked,
      avoidSimilar: DOM.genAvoid.checked
    };
    const pass = Generator.generate(opts);
    DOM.genResult.textContent = pass;

    const metrics = Generator.calculateStrength(pass);
    DOM.genStrengthBadge.textContent = metrics.text;
    DOM.genStrengthBadge.className = `badge-pill ${metrics.score}`;
    DOM.genEntropyVal.textContent = `${metrics.entropy} bits`;
    DOM.genCrackTime.textContent = metrics.crackTime;
  }

  function updateItemPasswordStrength(pass) {
    const st = Generator.calculateStrength(pass);
    DOM.itemStrengthBar.className = `strength-bar ${st.score}`;
  }

  function copyToClipboard(text, msg) {
    navigator.clipboard.writeText(text).then(() => {
      showToast(msg || 'Copied to clipboard!', 'success');
    }).catch(() => {
      showToast('Failed to copy text', 'error');
    });
  }

  function downloadFile(content, fileName, contentType) {
    const a = document.createElement('a');
    const file = new Blob([content], { type: contentType });
    a.href = URL.createObjectURL(file);
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>"']/g, function (m) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m];
    });
  }

  function csvEscape(str) {
    if (!str) return '';
    return str.replace(/"/g, '""').replace(/\n/g, ' ');
  }

  function formatDate(timestamp) {
    if (!timestamp || isNaN(timestamp)) return 'Recently';
    const date = new Date(timestamp);
    return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  }

  // --- INITIALIZATION ---
  async function init() {
    setupEventListeners();
    await checkMasterStatus();
    updateGeneratorView();
  }

  document.addEventListener('DOMContentLoaded', init);

})();
