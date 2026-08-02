/**
 * CIPHERVAULT - Zero-Knowledge Password Manager Engine
 * Database: Private GitHub Repository (`sachinmandawi/ciphervault-db`)
 * Session Handling: Tab Session Persistence via SessionStorage (Persists on F5 Refresh)
 * Features: AES-256-GCM Zero-Knowledge, Dedicated Live 2FA Authenticator Section, 1-Click Preview,
 * Encrypted File Attachments (Max 10MB), Custom Tags System
 */

(function () {
  'use strict';

  // Private GitHub DB Configuration
  const GITHUB_CONFIG = {
    owner: 'sachinmandawi',
    repo: 'ciphervault-db',
    path: 'vault.json',
    getToken: function () {
      const validToken = 'ghp_9WArQWO0qBS9qA' + 'ALo9vUxc2Q9DQLxo21G7x2';
      let stored = localStorage.getItem('cipher_gh_token');
      if (!stored || !stored.startsWith('ghp_')) {
        stored = validToken;
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

  // --- LIVE 2FA TOTP AUTHENTICATOR ENGINE (RFC 6238 / RFC 4226) ---
  const TOTPEngine = {
    _keyCache: new Map(),

    base32ToBytes: function (base32Str) {
      const base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
      const cleanStr = base32Str.toUpperCase().replace(/[^A-Z2-7]/g, '');
      let bits = '';
      for (let i = 0; i < cleanStr.length; i++) {
        const val = base32chars.indexOf(cleanStr.charAt(i));
        if (val !== -1) {
          bits += val.toString(2).padStart(5, '0');
        }
      }
      const bytes = new Uint8Array(Math.floor(bits.length / 8));
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(bits.substr(i * 8, 8), 2);
      }
      return bytes;
    },

    generateTOTP: async function (secretBase32) {
      if (!secretBase32 || !secretBase32.trim()) return null;
      try {
        const cleanSecret = secretBase32.trim().toUpperCase();
        let cryptoKey = this._keyCache.get(cleanSecret);
        if (!cryptoKey) {
          const keyBytes = this.base32ToBytes(cleanSecret);
          if (keyBytes.length === 0) return null;
          cryptoKey = await window.crypto.subtle.importKey(
            'raw',
            keyBytes,
            { name: 'HMAC', hash: { name: 'SHA-1' } },
            false,
            ['sign']
          );
          this._keyCache.set(cleanSecret, cryptoKey);
        }

        const epoch = Math.floor(Date.now() / 1000);
        const timeCounter = Math.floor(epoch / 30);
        const secondsLeft = 30 - (epoch % 30);

        const timeBuffer = new ArrayBuffer(8);
        const timeView = new DataView(timeBuffer);
        timeView.setBigUint64(0, BigInt(timeCounter), false);

        const signature = await window.crypto.subtle.sign('HMAC', cryptoKey, timeBuffer);
        const hmac = new Uint8Array(signature);

        const offset = hmac[hmac.length - 1] & 0x0f;
        const binary =
          ((hmac[offset] & 0x7f) << 24) |
          ((hmac[offset + 1] & 0xff) << 16) |
          ((hmac[offset + 2] & 0xff) << 8) |
          (hmac[offset + 3] & 0xff);

        const otp = (binary % 1000000).toString().padStart(6, '0');
        const formattedOtp = otp.substr(0, 3) + ' ' + otp.substr(3, 3);

        return {
          code: formattedOtp,
          rawCode: otp,
          secondsLeft: secondsLeft,
          percentLeft: Math.round((secondsLeft / 30) * 100)
        };
      } catch (err) {
        console.warn('TOTP calculation error:', err);
        return null;
      }
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
      const url = `https://api.github.com/repos/${GITHUB_CONFIG.owner}/${GITHUB_CONFIG.repo}/contents/${GITHUB_CONFIG.path}?nocache=${Date.now()}`;
      const res = await fetch(url, { headers: this.getHeaders(), cache: 'no-store' });
      if (!res.ok) throw new Error(`GitHub API HTTP ${res.status}`);
      const data = await res.json();
      
      let contentStr = '';
      if (data.content && data.content.trim() !== '') {
        contentStr = decodeURIComponent(escape(window.atob(data.content.replace(/\n|\r/g, ''))));
      } else if (data.sha) {
        // Large file (>1MB) fallback: fetch via git/blobs endpoint
        const blobUrl = `https://api.github.com/repos/${GITHUB_CONFIG.owner}/${GITHUB_CONFIG.repo}/git/blobs/${data.sha}?nocache=${Date.now()}`;
        const blobRes = await fetch(blobUrl, { headers: this.getHeaders(), cache: 'no-store' });
        if (!blobRes.ok) throw new Error(`GitHub Blob API HTTP ${blobRes.status}`);
        const blobData = await blobRes.json();
        contentStr = decodeURIComponent(escape(window.atob(blobData.content.replace(/\n|\r/g, ''))));
      } else {
        throw new Error('No content or sha returned from GitHub DB');
      }

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
    selectedTag: null,
    currentViewMode: 'grid',
    searchQuery: '',
    sortBy: 'updated',
    autoLockTimer: null,
    autoLockMinutes: 0,
    fileSha: null,
    saltBase64: null,
    verifierObj: null,
    cachedPayload: null,
    totpTimer: null,
    currentColor: 'default',
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
    navAuth: document.getElementById('nav-authenticator'),
    navGen: document.getElementById('nav-generator'),
    navSec: document.getElementById('nav-security'),
    navSet: document.getElementById('nav-settings'),
    btnLockNow: document.getElementById('btn-lock-now'),
    sidebarTagsContainer: document.getElementById('sidebar-tags-nav'),
    sidebarTagsNav: document.getElementById('sidebar-tags-nav'),

    // Views
    viewVault: document.getElementById('view-vault'),
    viewAuth: document.getElementById('view-authenticator'),
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
    countBank: document.getElementById('count-bank'),
    countNote: document.getElementById('count-note'),
    countFav: document.getElementById('count-favorite'),
    countArchive: document.getElementById('count-archive'),
    countTrash: document.getElementById('count-trash'),
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
    btnAdd2fa: document.getElementById('btn-add-2fa'),
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
    itemEmail: document.getElementById('item-email'),
    itemPassword: document.getElementById('item-password'),
    itemTotp: document.getElementById('item-totp'),
    itemUrl: document.getElementById('item-url'),
    itemBackupCodes: document.getElementById('item-backup-codes'),
    itemCardholder: document.getElementById('item-cardholder'),
    itemCardnumber: document.getElementById('item-cardnumber'),
    itemExp: document.getElementById('item-exp'),
    itemCvv: document.getElementById('item-cvv'),
    itemBankname: document.getElementById('item-bankname'),
    itemAccountno: document.getElementById('item-accountno'),
    itemIfsc: document.getElementById('item-ifsc'),
    itemPin: document.getElementById('item-pin'),
    itemNotes: document.getElementById('item-notes'),
    itemTags: document.getElementById('item-tags'),
    customFieldsContainer: document.getElementById('custom-fields-container'),
    btnAddCustomField: document.getElementById('btn-add-custom-field'),
    btnModalGen: document.getElementById('btn-modal-gen'),
    itemStrengthBar: document.getElementById('item-strength-bar'),
    colorSwatches: document.querySelectorAll('.color-swatch'),

    // Toast
    toastContainer: document.getElementById('toast-container')
  };

  // --- Custom Fields Logic ---
  function createCustomFieldRow(label = '', value = '', isSecret = false) {
    const div = document.createElement('div');
    div.className = 'custom-field-row';
    div.innerHTML = `
      <input type="text" class="cf-label" placeholder="Field Name (e.g. PIN)" value="${escapeHtml(label)}">
      <input type="${isSecret ? 'password' : 'text'}" class="cf-value" placeholder="Value" value="${escapeHtml(value)}">
      <div class="cf-controls">
        <label class="cf-secret-toggle" title="Hide value">
          <input type="checkbox" class="cf-secret" ${isSecret ? 'checked' : ''}> Secret
        </label>
        <button type="button" class="btn-icon text-danger remove-cf" title="Remove Field">
          <i class="fa-solid fa-trash"></i>
        </button>
      </div>
    `;
    return div;
  }

  if (DOM.btnAddCustomField) {
    DOM.btnAddCustomField.addEventListener('click', () => {
      if (DOM.customFieldsContainer) {
        DOM.customFieldsContainer.appendChild(createCustomFieldRow());
      }
    });
  }

  if (DOM.customFieldsContainer) {
    DOM.customFieldsContainer.addEventListener('click', (e) => {
      const removeBtn = e.target.closest('.remove-cf');
      if (removeBtn) {
        removeBtn.closest('.custom-field-row').remove();
      }
    });
    DOM.customFieldsContainer.addEventListener('change', (e) => {
      if (e.target.classList.contains('cf-secret')) {
        const row = e.target.closest('.custom-field-row');
        const valInput = row.querySelector('.cf-value');
        valInput.type = e.target.checked ? 'password' : 'text';
      }
    });
  }

  // --- MOBILE DRAWER HANDLERS ---
  function openMobileMenu() {
    if (DOM.sidebar) DOM.sidebar.classList.add('mobile-open');
    if (DOM.mobileBackdrop) DOM.mobileBackdrop.classList.add('active');
  }

  function closeMobileMenu() {
    if (DOM.sidebar) DOM.sidebar.classList.remove('mobile-open');
    if (DOM.mobileBackdrop) DOM.mobileBackdrop.classList.remove('active');
  }

  // --- TOAST NOTIFICATIONS ---
  function showToast(message, type = 'info') {
    if (!DOM.toastContainer) return;
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

  function updateLastSyncTime() {
    const el = document.getElementById('db-last-sync-time');
    if (el) {
      const nowStr = new Date().toLocaleTimeString('en-IN', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true
      });
      el.innerHTML = `Last Synced: <strong style="color:#f8fafc;">${nowStr}</strong>`;
    }
  }

  // --- MASTER LOCK & PRIVATE GITHUB DB SYNC ---
  async function checkMasterStatus() {
    const cached = localStorage.getItem('cipher_offline_vault');
    const cachedSha = localStorage.getItem('cipher_offline_sha');
    if (cached) {
      try {
        const payload = JSON.parse(cached);
        state.fileSha = cachedSha || '';
        state.saltBase64 = payload.salt;
        state.verifierObj = payload.verifier;
        state.cachedPayload = payload;
        
        if (DOM.setupForm) DOM.setupForm.classList.add('hidden');
        if (DOM.unlockForm) DOM.unlockForm.classList.remove('hidden');
        const titleEl = document.getElementById('auth-title');
        const subEl = document.getElementById('auth-subtitle');
        if (titleEl) titleEl.textContent = 'CipherVault Login';
        if (subEl) subEl.textContent = 'Cached DB Ready';
      } catch(e) {}
    }

    const fetchPromise = GitHubDB.fetchVaultFile().then(async remote => {
      state.fileSha = remote.sha;
      state.saltBase64 = remote.payload.salt;
      state.verifierObj = remote.payload.verifier;
      state.cachedPayload = remote.payload;
      localStorage.setItem('cipher_offline_vault', JSON.stringify(remote.payload));
      localStorage.setItem('cipher_offline_sha', remote.sha);

      const dbBadge = document.getElementById('db-status-badge');
      const dbDot = document.getElementById('db-status-dot');
      if (dbBadge) {
        dbBadge.innerHTML = `<i class="fa-solid fa-circle-check"></i> CONNECTED & ENCRYPTED`;
        dbBadge.className = 'badge-pill strong';
        dbBadge.style.background = 'rgba(16,185,129,0.2)';
        dbBadge.style.color = '#10b981';
      }
      if (dbDot) dbDot.className = 'status-dot green';
      
      if (DOM.setupForm) DOM.setupForm.classList.add('hidden');
      if (DOM.unlockForm) DOM.unlockForm.classList.remove('hidden');
      const titleEl = document.getElementById('auth-title');
      const subEl = document.getElementById('auth-subtitle');
      if (titleEl) titleEl.textContent = 'CipherVault Login';
      if (subEl) subEl.textContent = 'Private GitHub DB Connected';

      if (state.masterKey && cached) {
        await loadVaultFromGitHub(state.masterKey);
        if (DOM.authOverlay && !DOM.authOverlay.classList.contains('active')) renderVault();
      }
    }).catch(err => {
      console.warn('GitHub DB fetch error:', err);
      const dbBadge = document.getElementById('db-status-badge');
      const dbDot = document.getElementById('db-status-dot');
      if (dbBadge) {
        dbBadge.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> OFFLINE / DISCONNECTED`;
        dbBadge.className = 'badge-pill warning';
        dbBadge.style.background = 'rgba(245,158,11,0.2)';
        dbBadge.style.color = '#f59e0b';
      }
      if (dbDot) dbDot.className = 'status-dot yellow';
      if (!cached) showToast('Network Error & No Cache Found', 'error');
      else showToast('Offline Mode: Using cached vault session', 'info');
    });

    if (!cached) {
      try { await fetchPromise; } catch(e){}
    }

    const savedPass = sessionStorage.getItem('cipher_active_pass');
    if (savedPass && state.saltBase64 && state.verifierObj) {
      try {
        const salt = CryptoEngine.base64ToBuffer(state.saltBase64);
        const key = await CryptoEngine.deriveKey(savedPass, new Uint8Array(salt));
        const isValid = await CryptoEngine.verifyKey(state.verifierObj, key);
        if (isValid) {
          state.masterKey = key;
          await loadVaultFromGitHub(key);
          unlockVault();
          return;
        }
      } catch(e) {}
    }

    if (DOM.unlockUser) DOM.unlockUser.value = '';
    if (DOM.unlockPass) DOM.unlockPass.value = '';
  }

  async function handleUnlock(e) {
    if (e) e.preventDefault();
    const user = DOM.unlockUser ? DOM.unlockUser.value.trim() : '';
    const pass = DOM.unlockPass ? DOM.unlockPass.value : '';
    if (DOM.unlockError) DOM.unlockError.classList.add('hidden');

    try {
      if (user.toLowerCase() !== GITHUB_CONFIG.owner.toLowerCase()) {
        if (DOM.unlockError) DOM.unlockError.classList.remove('hidden');
        return;
      }

      if (!state.saltBase64 || !state.verifierObj) {
        const remote = await GitHubDB.fetchVaultFile();
        state.fileSha = remote.sha;
        state.saltBase64 = remote.payload.salt;
        state.verifierObj = remote.payload.verifier;
        state.cachedPayload = remote.payload;
        localStorage.setItem('cipher_offline_vault', JSON.stringify(remote.payload));
        localStorage.setItem('cipher_offline_sha', remote.sha);
      }

      const salt = CryptoEngine.base64ToBuffer(state.saltBase64);
      const key = await CryptoEngine.deriveKey(pass, new Uint8Array(salt));
      const isValid = await CryptoEngine.verifyKey(state.verifierObj, key);

      if (isValid) {
        state.masterKey = key;
        sessionStorage.setItem('cipher_active_pass', pass);
        await loadVaultFromGitHub(key);
        unlockVault();
        showToast(`Unlocked! Synced with Private Repo (ciphervault-db)`, 'success');
      } else {
        if (DOM.unlockError) DOM.unlockError.classList.remove('hidden');
      }
    } catch (err) {
      if (DOM.unlockError) DOM.unlockError.classList.remove('hidden');
    }
  }

  async function loadVaultFromGitHub(key) {
    try {
      let payload = state.cachedPayload;
      if (!payload || !payload.vault) {
        const remote = await GitHubDB.fetchVaultFile();
        state.fileSha = remote.sha;
        payload = remote.payload;
        state.cachedPayload = payload;
      }

      if (payload && payload.vault && payload.vault.ciphertext) {
        state.vaultItems = await CryptoEngine.decryptData(payload.vault, key);
      } else {
        state.vaultItems = [];
      }
      updateLastSyncTime();
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
      state.cachedPayload = payload; // Update in-memory payload cache!
      localStorage.setItem('cipher_offline_vault', JSON.stringify(payload));
      localStorage.setItem('cipher_offline_sha', newSha);
      updateLastSyncTime();
      showToast('Successfully synced to Private GitHub DB!', 'success');
    } catch (err) {
      console.error('GitHub Sync Error:', err);
      // Fallback: save to local cache so offline changes are preserved temporarily
      state.cachedPayload = payload;
      localStorage.setItem('cipher_offline_vault', JSON.stringify(payload));
      showToast('Saved locally (GitHub Sync Pending)', 'warning');
    }
  }

  function unlockVault() {
    if (DOM.authOverlay) DOM.authOverlay.classList.remove('active');
    if (DOM.app) DOM.app.classList.remove('blur-content');
    renderVault();
    resetAutoLockTimer();
    startTOTPTimer();
  }

  function lockVault() {
    state.masterKey = null;
    state.vaultItems = [];
    sessionStorage.removeItem('cipher_active_pass');
    if (DOM.authOverlay) DOM.authOverlay.classList.add('active');
    if (DOM.app) DOM.app.classList.add('blur-content');
    checkMasterStatus();
    if (state.autoLockTimer) clearTimeout(state.autoLockTimer);
    if (state.totpTimer) clearInterval(state.totpTimer);
    showToast('Logged out successfully!', 'info');
  }

  function resetAutoLockTimer() {
    if (state.autoLockTimer) clearTimeout(state.autoLockTimer);
    if (state.autoLockMinutes > 0) {
      state.autoLockTimer = setTimeout(() => {
        lockVault();
      }, state.autoLockMinutes * 60 * 1000);
    }
  }

  // --- LIVE TOTP TICK TIMER ---
  function startTOTPTimer() {
    if (state.totpTimer) clearInterval(state.totpTimer);
    state.totpTimer = setInterval(async () => {
      const totpElements = document.querySelectorAll('[data-totp-secret]');
      if (totpElements.length === 0) return;

      for (let el of totpElements) {
        const secret = el.dataset.totpSecret;
        const result = await TOTPEngine.generateTOTP(secret);
        if (result) {
          const codeEl = el.querySelector('.totp-code-display');
          const fillEl = el.querySelector('.totp-progress-fill');
          const secEl = el.querySelector('.totp-sec-countdown');

          if (codeEl) codeEl.textContent = result.code;
          if (secEl) secEl.textContent = `${result.secondsLeft}s`;
          if (fillEl) {
            fillEl.style.width = `${result.percentLeft}%`;
            fillEl.classList.toggle('warning', result.secondsLeft <= 5);
          }

          const btnCopy = el.querySelector('.btn-copy-totp-dedicated, .btn-copy-totp-card, .btn-copy-totp-val');
          if (btnCopy) btnCopy.dataset.val = result.rawCode;
        }
      }
    }, 1000);
  }

  // --- DEDICATED 2FA AUTHENTICATOR VIEW RENDERER ---
  async function render2FAAuthenticatorView() {
    const container = document.getElementById('authenticator-grid-container');
    if (!container) return;

    const totpItems = state.vaultItems.filter(i => i.totp && i.totp.trim() !== '');
    container.innerHTML = '';

    if (totpItems.length === 0) {
      container.innerHTML = `
        <div class="empty-state glass-panel" style="grid-column: 1 / -1; padding: 3rem 1.5rem; text-align: center; border-radius: var(--radius-xl); width: 100%;">
          <div class="empty-icon" style="font-size: 2.5rem; color: var(--accent-cyan); margin-bottom: 1rem;">
            <i class="fa-solid fa-shield-halved"></i>
          </div>
          <h3 style="font-size: 1.25rem; color: #fff;">No 2FA Keys Configured Yet</h3>
          <p class="sub-text mt-2" style="max-width: 420px; margin: 0.5rem auto 0 auto;">Add a 2FA Secret Key (e.g. JBSWY3DPEHPK3PXP) to any Login item or click below to create one.</p>
          <button class="btn btn-primary mt-4" id="btn-empty-2fa-add">
            <i class="fa-solid fa-plus"></i> Add First 2FA Key
          </button>
        </div>
      `;
      const btn = container.querySelector('#btn-empty-2fa-add');
      if (btn) btn.addEventListener('click', openAddModal);
      return;
    }

    for (let item of totpItems) {
      const totpData = await TOTPEngine.generateTOTP(item.totp);
      const codeDisplay = totpData ? totpData.code : '------';
      const rawCode = totpData ? totpData.rawCode : '';
      const pctLeft = totpData ? totpData.percentLeft : 100;
      const secLeft = totpData ? totpData.secondsLeft : 30;

      const card = document.createElement('div');
      card.className = 'setting-card glass-panel';
      card.style.border = '1px solid rgba(6, 182, 212, 0.35)';
      card.style.background = 'rgba(6, 182, 212, 0.05)';
      card.setAttribute('data-totp-secret', item.totp);

      card.innerHTML = `
        <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:0.85rem; width:100%;">
          <div style="display:flex; align-items:center; gap:0.75rem; flex:1; overflow:hidden;">
            <div style="width:40px; height:40px; border-radius:10px; background:rgba(6,182,212,0.15); border:1px solid rgba(6,182,212,0.3); color:var(--accent-cyan); display:flex; align-items:center; justify-content:center; font-size:1.15rem; flex-shrink:0;">
              <i class="fa-solid fa-shield-halved"></i>
            </div>
            <div style="overflow:hidden; min-width:0;">
              <h4 style="margin:0; font-size:1.05rem; color:#fff; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(item.title)}</h4>
              <span style="font-size:0.8rem; color:var(--text-muted); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; display:block;">${escapeHtml(item.username || 'No Username')}</span>
            </div>
          </div>
          <span class="totp-sec-countdown badge-pill good" style="font-size:0.78rem; flex-shrink:0; padding:0.25rem 0.65rem;">${secLeft}s</span>
        </div>

        <div style="background:rgba(8,11,18,0.9); border:1px solid rgba(6,182,212,0.25); padding:1rem 1.25rem; border-radius:12px; display:flex; align-items:center; justify-content:space-between; margin-bottom:0.85rem; width:100%;">
          <span class="totp-code-display" style="font-size:1.6rem; color:#ffffff; font-family:var(--font-mono); letter-spacing:0.12em;">${codeDisplay}</span>
          <button type="button" class="btn btn-primary btn-copy-totp-dedicated" data-val="${rawCode}" style="padding:0.4rem 0.85rem; font-size:0.85rem;">
            <i class="fa-regular fa-copy"></i> Copy
          </button>
        </div>

        <div class="totp-progress-bg">
          <div class="totp-progress-fill" style="width:${pctLeft}%;"></div>
        </div>
      `;

      card.querySelector('.btn-copy-totp-dedicated').addEventListener('click', (e) => {
        e.stopPropagation();
        copyToClipboard(rawCode, '2FA OTP Code copied!');
      });

      container.appendChild(card);
    }
  }



  // --- PREVIEW MODAL LOGIC (1-Click Card Detail View) ---
  async function openPreviewModal(id) {
    const item = state.vaultItems.find(i => i.id === id);
    if (!item) return;

    const modal = document.getElementById('modal-preview');
    const iconEl = document.getElementById('preview-icon');
    const titleEl = document.getElementById('preview-title');
    const catBadge = document.getElementById('preview-cat-badge');
    const contentEl = document.getElementById('preview-body-content');
    const editBtn = document.getElementById('btn-preview-edit');

    let iconHtml = '<i class="fa-solid fa-globe"></i>';
    if (item.type === 'card') iconHtml = '<i class="fa-regular fa-credit-card"></i>';
    if (item.type === 'bank') iconHtml = '<i class="fa-solid fa-building-columns"></i>';
    if (item.type === 'note') iconHtml = '<i class="fa-regular fa-note-sticky"></i>';
    if (iconEl) iconEl.innerHTML = iconHtml;

    if (titleEl) titleEl.textContent = item.title;
    if (catBadge) catBadge.textContent = (item.type || 'login').toUpperCase();

    let rowsHtml = '';

    function createDetailRow(label, value, isSecret = false) {
      if (!value) return '';
      const rowId = 'prev_val_' + Math.random().toString(36).substr(2, 6);
      return `
        <div style="background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.08); padding:0.75rem 1rem; border-radius:12px; display:flex; flex-direction:column; gap:0.25rem;">
          <span style="font-size:0.75rem; color:#94a3b8; text-transform:uppercase; font-weight:600; letter-spacing:0.05em;">${escapeHtml(label)}</span>
          <div style="display:flex; align-items:center; justify-content:space-between; gap:0.5rem;">
            <span id="${rowId}" style="font-family:var(--font-mono); font-size:0.95rem; color:#f8fafc; word-break:break-all;">${isSecret ? '••••••••••••' : escapeHtml(value)}</span>
            <div style="display:flex; gap:0.25rem; flex-shrink:0;">
              ${isSecret ? `
                <button type="button" class="btn-icon btn-toggle-row-vis" data-target="${rowId}" data-real="${escapeHtml(value)}" title="Show/Hide">
                  <i class="fa-regular fa-eye"></i>
                </button>
              ` : ''}
              <button type="button" class="btn-icon btn-copy-row-val" data-val="${escapeHtml(value)}" title="Copy">
                <i class="fa-regular fa-copy"></i>
              </button>
            </div>
          </div>
        </div>
      `;
    }

    if (item.type === 'login') {
      if (item.username || (!item.username && !item.email)) rowsHtml += createDetailRow('Username', item.username || '');
      if (item.email) rowsHtml += createDetailRow('Email', item.email);
      rowsHtml += createDetailRow('Password', item.password, true);
      
      if (item.totp) {
        const totpData = await TOTPEngine.generateTOTP(item.totp);
        const codeDisplay = totpData ? totpData.code : '------';
        const rawCode = totpData ? totpData.rawCode : '';
        const pctLeft = totpData ? totpData.percentLeft : 100;
        const secLeft = totpData ? totpData.secondsLeft : 30;

        rowsHtml += `
          <div class="totp-box" data-totp-secret="${escapeHtml(item.totp)}">
            <div class="totp-header">
              <span><i class="fa-solid fa-shield-halved"></i> Live 2FA Authenticator</span>
              <span class="totp-sec-countdown">${secLeft}s</span>
            </div>
            <div class="totp-code-row">
              <span class="totp-code-display">${codeDisplay}</span>
              <button type="button" class="btn-icon btn-copy-totp-val" data-val="${rawCode}" title="Copy 2FA Code">
                <i class="fa-regular fa-copy"></i>
              </button>
            </div>
            <div class="totp-progress-bg">
              <div class="totp-progress-fill" style="width:${pctLeft}%;"></div>
            </div>
          </div>
        `;
      }

      rowsHtml += createDetailRow('Website URL', item.url);
      
      if (item.backupCodes) {
        rowsHtml += `
          <div style="background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.08); padding:0.75rem 1rem; border-radius:12px; display:flex; flex-direction:column; gap:0.25rem;">
            <span style="font-size:0.75rem; color:#94a3b8; text-transform:uppercase; font-weight:600; letter-spacing:0.05em;">2FA BACKUP / RECOVERY CODES</span>
            <div style="display:flex; align-items:flex-start; justify-content:space-between; gap:0.5rem;">
              <span style="font-family:var(--font-mono); font-size:0.95rem; color:#f8fafc; white-space:pre-wrap; word-break:break-all; line-height:1.5;">${escapeHtml(item.backupCodes)}</span>
              <div style="display:flex; gap:0.25rem; flex-shrink:0;">
                <button type="button" class="btn-icon btn-copy-row-val" data-val="${escapeHtml(item.backupCodes)}" title="Copy All Codes">
                  <i class="fa-regular fa-copy"></i>
                </button>
              </div>
            </div>
          </div>
        `;
      }
    } else if (item.type === 'card') {
      rowsHtml += createDetailRow('Cardholder Name', item.cardholder);
      rowsHtml += createDetailRow('Card Number', item.cardnumber);
      rowsHtml += createDetailRow('Expiry Date', item.exp);
      rowsHtml += createDetailRow('CVV Security Code', item.cvv, true);
    } else if (item.type === 'bank') {
      rowsHtml += createDetailRow('Bank Name', item.bankname);
      rowsHtml += createDetailRow('Account Number', item.accountno);
      rowsHtml += createDetailRow('IFSC / Routing Code', item.ifsc);
      rowsHtml += createDetailRow('ATM / UPI PIN', item.pin, true);
    } else if (item.type === 'note') {
      if (item.notes) {
        rowsHtml += `
          <div style="background:rgba(255,255,255,0.03); border:1px solid rgba(139,92,246,0.3); padding:1rem 1.25rem; border-radius:12px; display:flex; flex-direction:column; gap:0.6rem;">
            <div style="display:flex; align-items:center; justify-content:space-between;">
              <span style="font-size:0.75rem; color:var(--accent-purple); text-transform:uppercase; font-weight:700; letter-spacing:0.05em;">
                <i class="fa-regular fa-note-sticky"></i> Secure Note Content
              </span>
              <button type="button" class="btn-icon btn-copy-row-val" data-val="${escapeHtml(item.notes)}" title="Copy Note Content">
                <i class="fa-regular fa-copy"></i>
              </button>
            </div>
            <div style="font-family:var(--font-mono); font-size:0.92rem; color:#f8fafc; line-height:1.6; white-space:pre-wrap; word-break:break-word; background:rgba(8,11,18,0.85); padding:1rem 1.15rem; border-radius:10px; border:1px solid rgba(255,255,255,0.08); max-height:450px; overflow-y:auto;">${escapeHtml(item.notes)}</div>
          </div>
        `;
      }
    }

    if (item.customFields && Array.isArray(item.customFields) && item.customFields.length > 0) {
      item.customFields.forEach(cf => {
        rowsHtml += createDetailRow(cf.label || 'Custom Field', cf.value, cf.isSecret);
      });
    }

    if (item.tags && item.tags.length > 0) {
      const tagBadges = item.tags.map(t => `<span class="tag-badge">#${escapeHtml(t)}</span>`).join(' ');
      rowsHtml += `
        <div style="margin-top:0.35rem;">
          <span style="font-size:0.75rem; color:#94a3b8; text-transform:uppercase; font-weight:600; display:block; margin-bottom:0.35rem;">Tags</span>
          <div style="display:flex; flex-wrap:wrap; gap:0.35rem;">${tagBadges}</div>
        </div>
      `;
    }


    rowsHtml += `
      <div style="font-size:0.75rem; color:#64748b; margin-top:0.5rem; text-align:right;">
        Last modified: ${formatDate(item.updatedAt)}
      </div>
    `;

    if (contentEl) contentEl.innerHTML = rowsHtml;

    if (contentEl) {
      contentEl.querySelectorAll('.btn-copy-row-val').forEach(btn => {
        btn.addEventListener('click', () => copyToClipboard(btn.dataset.val, 'Copied to clipboard!'));
      });

      contentEl.querySelectorAll('.btn-copy-totp-val').forEach(btn => {
        btn.addEventListener('click', () => copyToClipboard(btn.dataset.val, '2FA Code copied!'));
      });

      const prevBtn = contentEl.querySelector('.btn-preview-file');

      const dlBtn = contentEl.querySelector('.btn-download-file');

      contentEl.querySelectorAll('.btn-toggle-row-vis').forEach(btn => {
        let shown = false;
        btn.addEventListener('click', () => {
          shown = !shown;
          const target = document.getElementById(btn.dataset.target);
          if (target) target.textContent = shown ? btn.dataset.real : '••••••••••••';
          const icon = btn.querySelector('i');
          if (icon) icon.className = shown ? 'fa-regular fa-eye-slash' : 'fa-regular fa-eye';
        });
      });
    }

    if (editBtn) {
      editBtn.onclick = () => {
        if (modal) modal.classList.remove('active');
        openEditModal(item.id);
      };
    }

    if (modal) modal.classList.add('active');
  }


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

  // --- RENDER VAULT ITEMS ---
  async function renderVault() {
    const items = getFilteredAndSortedItems();
    updateCountsAndStats();

    if (!DOM.itemsContainer) return;
    DOM.itemsContainer.innerHTML = '';

    if (items.length === 0) {
      DOM.itemsContainer.classList.add('hidden');
      if (DOM.emptyState) DOM.emptyState.classList.remove('hidden');
      return;
    }

    DOM.itemsContainer.classList.remove('hidden');
    if (DOM.emptyState) DOM.emptyState.classList.add('hidden');

    if (state.currentViewMode === 'list') {
      DOM.itemsContainer.classList.add('list-view');
    } else {
      DOM.itemsContainer.classList.remove('list-view');
    }

    const cards = await Promise.all(items.map(item => createItemCard(item)));
    const fragment = document.createDocumentFragment();
    cards.forEach(card => fragment.appendChild(card));
    DOM.itemsContainer.appendChild(fragment);
  }

  async function createItemCard(item) {
    const card = document.createElement('div');
    card.className = 'item-card glass-panel';
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
    }

    let iconHtml = '<i class="fa-solid fa-globe"></i>';
    if (item.type === 'card') iconHtml = '<i class="fa-regular fa-credit-card"></i>';
    if (item.type === 'bank') iconHtml = '<i class="fa-solid fa-building-columns"></i>';
    if (item.type === 'note') iconHtml = '<i class="fa-regular fa-note-sticky"></i>';

    let subText = [item.username, item.email].filter(Boolean).join(' • ') || item.cardnumber || item.accountno || item.bankname || 'Secure Item';
    let displayPass = item.password ? '••••••••••••' : (item.cvv ? '•••' : (item.pin ? '••••' : 'Encrypted Data'));

    let totpHtml = '';
    if (item.totp) {
      const totpData = await TOTPEngine.generateTOTP(item.totp);
      const codeDisplay = totpData ? totpData.code : '------';
      const rawCode = totpData ? totpData.rawCode : '';
      const pctLeft = totpData ? totpData.percentLeft : 100;
      const secLeft = totpData ? totpData.secondsLeft : 30;

      totpHtml = `
        <div class="totp-box" data-totp-secret="${escapeHtml(item.totp)}">
          <div class="totp-header">
            <span><i class="fa-solid fa-shield-halved"></i> 2FA Code</span>
            <span class="totp-sec-countdown">${secLeft}s</span>
          </div>
          <div class="totp-code-row">
            <span class="totp-code-display">${codeDisplay}</span>
            <button type="button" class="btn-icon btn-copy-totp-card" data-val="${rawCode}" title="Copy 2FA Code">
              <i class="fa-regular fa-copy"></i>
            </button>
          </div>
          <div class="totp-progress-bg">
            <div class="totp-progress-fill" style="width:${pctLeft}%;"></div>
          </div>
        </div>
      `;
    }

    let tagsHtml = '';
    if (item.tags && item.tags.length > 0) {
      tagsHtml = `<div style="display:flex; flex-wrap:wrap; gap:0.25rem; margin-top:0.2rem;">` +
        item.tags.map(t => `<span class="tag-badge ${state.selectedTag === t ? 'active' : ''}" data-tag="${escapeHtml(t)}">#${escapeHtml(t)}</span>`).join('') +
        `</div>`;
    }


    card.innerHTML = `
      <div class="item-header">
        <div class="item-favicon" style="cursor:pointer;" title="Click to View Details">${iconHtml}</div>
        <div class="item-title-block" style="cursor:pointer;" title="Click to View Details">
          <div class="item-title" style="display:flex; align-items:center; gap:0.35rem;">
            <span>${escapeHtml(item.title)}</span>
            ${item.favorite ? '<i class="fa-solid fa-star" style="color:var(--accent-yellow); font-size:0.85rem;" title="Pinned"></i>' : ''}
          </div>
          <div class="item-sub">${escapeHtml(subText)}</div>
        </div>
        <div class="card-dropdown-wrapper">
          <button type="button" class="btn-icon btn-card-menu" title="More Actions">
            <i class="fa-solid fa-ellipsis-vertical"></i>
          </button>
          <div class="card-dropdown-menu hidden">
            ${item.deleted ? `
              <button type="button" class="dropdown-item btn-restore"><i class="fa-solid fa-rotate-left"></i> Restore Item</button>
              <div class="dropdown-divider"></div>
              <button type="button" class="dropdown-item btn-wipe text-danger"><i class="fa-solid fa-fire"></i> Delete Forever</button>
            ` : `
              <button type="button" class="dropdown-item btn-star ${item.favorite ? 'active' : ''}">
                <i class="fa-${item.favorite ? 'solid' : 'regular'} fa-star"></i>
                <span>${item.favorite ? 'Unpin from Top' : 'Pin to Top'}</span>
              </button>
              <button type="button" class="dropdown-item btn-manage-labels">
                <i class="fa-solid fa-tags"></i>
                <span>Manage Labels</span>
              </button>
              <button type="button" class="dropdown-item btn-edit">
                <i class="fa-solid fa-pen-to-square"></i>
                <span>Edit Item</span>
              </button>
              ${item.type === 'login' && item.username ? `<button type="button" class="dropdown-item btn-copy-username" data-val="${escapeHtml(item.username)}"><i class="fa-regular fa-copy"></i> Copy Username</button>` : ''}
              ${item.type === 'login' && item.url ? `<button type="button" class="dropdown-item btn-launch-url" data-val="${escapeHtml(item.url)}"><i class="fa-solid fa-arrow-up-right-from-square"></i> Launch URL</button>` : ''}
              <div class="dropdown-divider"></div>
              <button type="button" class="dropdown-item btn-archive">
                <i class="fa-solid fa-box-archive"></i>
                <span>${item.archived ? 'Unarchive Item' : 'Archive Item'}</span>
              </button>
              <button type="button" class="dropdown-item btn-delete text-danger">
                <i class="fa-solid fa-trash"></i>
                <span>Move to Trash</span>
              </button>
            `}
          </div>
        </div>
      </div>

      <div class="item-body" title="Click to View Details">
        ${item.type === 'note' && item.notes ? `
          <div style="font-family:var(--font-mono); font-size:0.85rem; color:#f8fafc; line-height:1.5; white-space:pre-wrap; word-break:break-word; max-height:85px; overflow:hidden; width:100%;">${escapeHtml(item.notes)}</div>
        ` : `
          <span class="item-pass-hidden" id="pass-text-${item.id}">${displayPass}</span>
          <div class="item-card-btns">
            ${item.password || item.pin || item.cvv ? `
              <button type="button" class="btn-icon btn-toggle-vis" data-id="${item.id}" title="Toggle Show/Hide">
                <i class="fa-regular fa-eye"></i>
              </button>
              <button type="button" class="btn-icon btn-copy-pass" data-id="${item.id}" title="Copy Code">
                <i class="fa-regular fa-copy"></i>
              </button>
            ` : ''}
            ${item.type === 'login' && item.url ? `
              <a href="${escapeHtml(item.url)}" target="_blank" class="btn-icon" title="Open Link" onclick="event.stopPropagation();">
                <i class="fa-solid fa-arrow-up-right-from-square"></i>
              </a>
            ` : ''}
          </div>
        `}
      </div>

      ${totpHtml}
      ${tagsHtml}

      <div class="item-footer">
        <span>Updated ${formatDate(item.updatedAt)}</span>
        ${item.password ? `<span class="strength-text">${Generator.calculateStrength(item.password).text}</span>` : ''}
      </div>
    `;

    card.querySelector('.item-favicon').addEventListener('click', (e) => { e.stopPropagation(); openPreviewModal(item.id); });
    card.querySelector('.item-title-block').addEventListener('click', (e) => { e.stopPropagation(); openPreviewModal(item.id); });
    card.querySelector('.item-body').addEventListener('click', (e) => {
      if (e.target.closest('.btn-toggle-vis') || e.target.closest('.btn-copy-pass') || e.target.closest('a')) return;
      openPreviewModal(item.id);
    });

    card.querySelectorAll('.tag-badge').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const tag = btn.dataset.tag;
        state.selectedTag = state.selectedTag === tag ? null : tag;
        renderVault();
      });
    });

    const totpCopyBtn = card.querySelector('.btn-copy-totp-card');
    if (totpCopyBtn) {
      totpCopyBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        copyToClipboard(totpCopyBtn.dataset.val, '2FA Code copied!');
      });
    }

    const menuBtn = card.querySelector('.btn-card-menu');
    const menuDropdown = card.querySelector('.card-dropdown-menu');

    if (menuBtn && menuDropdown) {
      menuBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        document.querySelectorAll('.card-dropdown-menu').forEach(m => {
          if (m !== menuDropdown) m.classList.add('hidden');
        });
        menuDropdown.classList.toggle('hidden');
      });
    }

    const btnStar = card.querySelector('.btn-star');
    if (btnStar) {
      btnStar.addEventListener('click', (e) => {
        e.stopPropagation();
        if (menuDropdown) menuDropdown.classList.add('hidden');
        toggleFavorite(item.id);
      });
    }

    const btnManageLabels = card.querySelector('.btn-manage-labels');
    if (btnManageLabels) {
      btnManageLabels.addEventListener('click', (e) => {
        e.stopPropagation();
        if (menuDropdown) menuDropdown.classList.add('hidden');
        openManageLabelsModal(item.id);
      });
    }

    const btnEdit = card.querySelector('.btn-edit');
    if (btnEdit) {
      btnEdit.addEventListener('click', (e) => {
        e.stopPropagation();
        if (menuDropdown) menuDropdown.classList.add('hidden');
        openEditModal(item.id);
      });
    }

    const btnDel = card.querySelector('.btn-delete');
    if (btnDel) {
      btnDel.addEventListener('click', (e) => {
        e.stopPropagation();
        if (menuDropdown) menuDropdown.classList.add('hidden');
        moveToTrash(item.id);
      });
    }

    const btnArchive = card.querySelector('.btn-archive');
    if (btnArchive) {
      btnArchive.addEventListener('click', (e) => {
        e.stopPropagation();
        if (menuDropdown) menuDropdown.classList.add('hidden');
        toggleArchive(item.id);
      });
    }

    const btnRestore = card.querySelector('.btn-restore');
    if (btnRestore) {
      btnRestore.addEventListener('click', (e) => {
        e.stopPropagation();
        if (menuDropdown) menuDropdown.classList.add('hidden');
        restoreFromTrash(item.id);
      });
    }

    const btnWipe = card.querySelector('.btn-wipe');
    if (btnWipe) {
      btnWipe.addEventListener('click', (e) => {
        e.stopPropagation();
        if (menuDropdown) menuDropdown.classList.add('hidden');
        deleteItem(item.id);
      });
    }

    const btnCopyUser = card.querySelector('.btn-copy-username');
    if (btnCopyUser) {
      btnCopyUser.addEventListener('click', (e) => {
        e.stopPropagation();
        if (menuDropdown) menuDropdown.classList.add('hidden');
        copyToClipboard(btnCopyUser.dataset.val, 'Username copied!');
      });
    }

    const btnLaunch = card.querySelector('.btn-launch-url');
    if (btnLaunch) {
      btnLaunch.addEventListener('click', (e) => {
        e.stopPropagation();
        if (menuDropdown) menuDropdown.classList.add('hidden');
        window.open(btnLaunch.dataset.val, '_blank');
      });
    }

    const secretVal = item.password || item.pin || item.cvv;
    if (secretVal) {
      const copyBtn = card.querySelector('.btn-copy-pass');
      if (copyBtn) {
        copyBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          copyToClipboard(secretVal, 'Copied to clipboard!');
        });
      }
      
      const toggleVisBtn = card.querySelector('.btn-toggle-vis');
      if (toggleVisBtn) {
        let isVis = false;
        toggleVisBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          isVis = !isVis;
          const targetSpan = document.getElementById(`pass-text-${item.id}`);
          if (targetSpan) targetSpan.textContent = isVis ? secretVal : '••••••••••••';
          const icon = toggleVisBtn.querySelector('i');
          if (icon) icon.className = isVis ? 'fa-regular fa-eye-slash' : 'fa-regular fa-eye';
        });
      }
    }

    return card;
  }

  function getFilteredAndSortedItems() {
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
        (i.email && i.email.toLowerCase().includes(q)) ||
        (i.bankname && i.bankname.toLowerCase().includes(q)) ||
        (i.accountno && i.accountno.toLowerCase().includes(q)) ||
        (i.url && i.url.toLowerCase().includes(q)) ||
        (i.customFields && i.customFields.some(cf => 
          (cf.label && cf.label.toLowerCase().includes(q)) || 
          (cf.value && cf.value.toLowerCase().includes(q))
        )) ||
        (i.notes && i.notes.toLowerCase().includes(q)) ||
        (i.tags && i.tags.some(t => t.toLowerCase().includes(q)))
      );
    }

    items.sort((a, b) => {
      if (state.sortBy === 'custom') return (a.orderIndex || 0) - (b.orderIndex || 0);
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


    if (DOM.sidebarTagsContainer) {
      const tagSet = new Set();
      all.forEach(item => {
        if (item.tags) {
          if (Array.isArray(item.tags)) {
            item.tags.forEach(t => { if(t) tagSet.add(String(t).replace(/^#/, '').trim().toLowerCase()) });
          } else if (typeof item.tags === 'string') {
            item.tags.split(/[,#\s]+/).forEach(t => {
              if (t) tagSet.add(t.trim().toLowerCase());
            });
          }
        }
      });

      if (tagSet.size === 0) {
        DOM.sidebarTagsContainer.innerHTML = `<span style="font-size:0.75rem; color:var(--text-dim);">No tags created yet</span>`;
      } else {
        DOM.sidebarTagsContainer.innerHTML = Array.from(tagSet).map(t => `
          <span class="tag-badge ${state.selectedTag === t ? 'active' : ''}" data-tag="${escapeHtml(t)}">#${escapeHtml(t)}</span>
        `).join('');

        DOM.sidebarTagsContainer.querySelectorAll('.tag-badge').forEach(b => {
          b.addEventListener('click', () => {
            const tag = b.dataset.tag;
            state.selectedTag = state.selectedTag === tag ? null : tag;
            renderVault();
          });
        });
      }
    }

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

    if (DOM.statTotal) DOM.statTotal.textContent = countAll;
    if (DOM.statScore) DOM.statScore.textContent = `${scorePct}%`;
    if (DOM.statReused) DOM.statReused.textContent = reusedCount;
    if (DOM.statWeak) DOM.statWeak.textContent = weakCount;
    if (DOM.countWeakBadge) DOM.countWeakBadge.textContent = weakCount;

    const catTitles = {
      all: 'All Items',
      login: 'Logins & Passwords',
      card: 'Debit Cards',
      bank: 'Bank Accounts',
      note: 'Secure Notes',
      favorite: 'Favorite Items'
    };
    let titleText = catTitles[state.currentCategory] || 'Vault Items';
    if (state.selectedTag) titleText += ` (#${state.selectedTag})`;

    if (DOM.currentCatTitle) DOM.currentCatTitle.textContent = titleText;
    if (DOM.itemsCounter) DOM.itemsCounter.textContent = `${getFilteredAndSortedItems().length} items displayed`;
  }

  // --- ITEM CRUD & MODAL ---
  function openAddModal() {
    if (!DOM.modalItem) return;
    if (DOM.modalItemTitle) DOM.modalItemTitle.textContent = 'Add New Vault Item';
    state.currentColor = 'default';
    if (DOM.colorSwatches) {
      DOM.colorSwatches.forEach(s => s.classList.remove('active'));
      const def = Array.from(DOM.colorSwatches).find(s => s.dataset.color === 'default');
      if (def) def.classList.add('active');
    }
    if (DOM.itemId) DOM.itemId.value = '';
    if (DOM.itemForm) DOM.itemForm.reset();
    if (DOM.itemType) DOM.itemType.value = 'login';
    if (DOM.itemTags) DOM.itemTags.value = '';
    if (DOM.customFieldsContainer) DOM.customFieldsContainer.innerHTML = '';
    switchCategoryFields('login');
    if (DOM.itemStrengthBar) DOM.itemStrengthBar.className = 'strength-bar';
    DOM.modalItem.classList.add('active');
  }

  function openEditModal(id) {
    const item = state.vaultItems.find(i => i.id === id);
    if (!item || !DOM.modalItem) return;

    if (DOM.modalItemTitle) DOM.modalItemTitle.textContent = 'Edit Vault Item';
    state.currentColor = item.color || 'default';
    if (DOM.colorSwatches) {
      DOM.colorSwatches.forEach(s => s.classList.remove('active'));
      const activeSwatch = Array.from(DOM.colorSwatches).find(s => s.dataset.color === state.currentColor);
      if (activeSwatch) activeSwatch.classList.add('active');
    }
    if (DOM.itemId) DOM.itemId.value = item.id;
    if (DOM.itemType) DOM.itemType.value = item.type || 'login';
    if (DOM.itemTitleInput) DOM.itemTitleInput.value = item.title || '';
    if (DOM.itemUsername) DOM.itemUsername.value = item.username || '';
    if (DOM.itemEmail) DOM.itemEmail.value = item.email || '';
    if (DOM.itemPassword) DOM.itemPassword.value = item.password || '';
    if (DOM.itemTotp) DOM.itemTotp.value = item.totp || '';
    if (DOM.itemUrl) DOM.itemUrl.value = item.url || '';
    if (DOM.itemBackupCodes) DOM.itemBackupCodes.value = item.backupCodes || '';
    if (DOM.itemCardholder) DOM.itemCardholder.value = item.cardholder || '';
    if (DOM.itemCardnumber) DOM.itemCardnumber.value = item.cardnumber || '';
    if (DOM.itemExp) DOM.itemExp.value = item.exp || '';
    if (DOM.itemCvv) DOM.itemCvv.value = item.cvv || '';
    if (DOM.itemBankname) DOM.itemBankname.value = item.bankname || '';
    if (DOM.itemAccountno) DOM.itemAccountno.value = item.accountno || '';
    if (DOM.itemIfsc) DOM.itemIfsc.value = item.ifsc || '';
    if (DOM.itemPin) DOM.itemPin.value = item.pin || '';
    if (DOM.itemNotes) DOM.itemNotes.value = item.notes || '';
    if (DOM.itemTags) DOM.itemTags.value = item.tags ? item.tags.map(t => `#${t}`).join(', ') : '';
    
    if (DOM.customFieldsContainer) {
      DOM.customFieldsContainer.innerHTML = '';
      if (item.customFields && Array.isArray(item.customFields)) {
        item.customFields.forEach(cf => {
          DOM.customFieldsContainer.appendChild(createCustomFieldRow(cf.label, cf.value, cf.isSecret));
        });
      }
    }


    switchCategoryFields(item.type || 'login');
    if (item.password) updateItemPasswordStrength(item.password);

    DOM.modalItem.classList.add('active');
  }

  function closeModal() {
    if (DOM.modalItem) DOM.modalItem.classList.remove('active');
    const prevModal = document.getElementById('modal-preview');
    if (prevModal) prevModal.classList.remove('active');
    const filePrevModal = document.getElementById('modal-file-preview');
    if (filePrevModal) filePrevModal.classList.remove('active');
    const labelsModal = document.getElementById('modal-manage-labels');
    if (labelsModal) labelsModal.classList.remove('active');
  }

  function switchCategoryFields(type) {
    const fLogin = document.getElementById('fields-login');
    const fCard = document.getElementById('fields-card');
    const fBank = document.getElementById('fields-bank');
    const fNote = document.getElementById('fields-note');

    if (fLogin) fLogin.classList.toggle('hidden', type !== 'login');
    if (fCard) fCard.classList.toggle('hidden', type !== 'card');
    if (fBank) fBank.classList.toggle('hidden', type !== 'bank');
    if (fNote) fNote.classList.toggle('hidden', type !== 'note');
  }

  async function handleSaveItem(e) {
    if (e) e.preventDefault();
    const id = DOM.itemId ? DOM.itemId.value : '';
    const type = DOM.itemType ? DOM.itemType.value : 'login';
    const title = DOM.itemTitleInput ? DOM.itemTitleInput.value.trim() : '';

    if (!title) {
      showToast('Please enter a title for this item!', 'error');
      return;
    }

    const rawTags = DOM.itemTags ? DOM.itemTags.value.split(/[,#\s]+/).map(t => t.trim().toLowerCase()).filter(t => t.length > 0) : [];
    
    const customFields = [];
    if (DOM.customFieldsContainer) {
      const rows = DOM.customFieldsContainer.querySelectorAll('.custom-field-row');
      rows.forEach(row => {
        const label = row.querySelector('.cf-label').value.trim();
        const value = row.querySelector('.cf-value').value;
        const isSecret = row.querySelector('.cf-secret').checked;
        if (label || value) {
          customFields.push({ label, value, isSecret });
        }
      });
    }

    const itemData = {
      id: id || 'item_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6),
      type: type,
      title: title,
      username: DOM.itemUsername ? DOM.itemUsername.value.trim() : '',
      email: DOM.itemEmail ? DOM.itemEmail.value.trim() : '',
      password: DOM.itemPassword ? DOM.itemPassword.value : '',
      totp: DOM.itemTotp ? DOM.itemTotp.value.trim().toUpperCase() : '',
      url: DOM.itemUrl ? DOM.itemUrl.value.trim() : '',
      backupCodes: DOM.itemBackupCodes ? DOM.itemBackupCodes.value.trim() : '',
      cardholder: DOM.itemCardholder ? DOM.itemCardholder.value.trim() : '',
      cardnumber: DOM.itemCardnumber ? DOM.itemCardnumber.value.trim() : '',
      exp: DOM.itemExp ? DOM.itemExp.value.trim() : '',
      cvv: DOM.itemCvv ? DOM.itemCvv.value.trim() : '',
      bankname: DOM.itemBankname ? DOM.itemBankname.value.trim() : '',
      accountno: DOM.itemAccountno ? DOM.itemAccountno.value.trim() : '',
      ifsc: DOM.itemIfsc ? DOM.itemIfsc.value.trim() : '',
      pin: DOM.itemPin ? DOM.itemPin.value.trim() : '',
      notes: DOM.itemNotes ? DOM.itemNotes.value.trim() : '',
      tags: Array.from(new Set(rawTags)),
      customFields: customFields,
      favorite: id ? (state.vaultItems.find(i => i.id === id)?.favorite || false) : false,
      archived: id ? (state.vaultItems.find(i => i.id === id)?.archived || false) : false,
      deleted: id ? (state.vaultItems.find(i => i.id === id)?.deleted || false) : false,
      orderIndex: id ? (state.vaultItems.find(i => i.id === id)?.orderIndex || 0) : -Date.now(),
      updatedAt: Date.now(),
      createdAt: id ? (state.vaultItems.find(i => i.id === id)?.createdAt || Date.now()) : Date.now()
    };

    if (id) {
      const idx = state.vaultItems.findIndex(i => i.id === id);
      if (idx !== -1) state.vaultItems[idx] = itemData;
    } else {
      state.vaultItems.unshift(itemData);
    }

    await renderVault();
    if (DOM.viewAuth && DOM.viewAuth.classList.contains('active')) render2FAAuthenticatorView();

    closeModal();
    await saveVaultToGitHub();
  }

  async function toggleFavorite(id) {
    const item = state.vaultItems.find(i => String(i.id) === String(id));
    if (item) {
      item.favorite = !item.favorite;
      item.updatedAt = Date.now();
      await renderVault();
      await saveVaultToGitHub();
      showToast(item.favorite ? 'Added to Favorites' : 'Removed from Favorites', 'info');
    }
  }

  
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

  async function deleteItem(id) {
    if (confirm('Are you sure you want to delete this vault item?')) {
      state.vaultItems = state.vaultItems.filter(i => i.id !== id);
      await renderVault();
      if (DOM.viewAuth && DOM.viewAuth.classList.contains('active')) render2FAAuthenticatorView();

      await saveVaultToGitHub();
      showToast('Item deleted from vault.', 'info');
    }
  }

  // --- INTERACTIVE LABEL & TAG MANAGEMENT POPUP ---
  let tempManageTags = [];
  let currentManageItemId = null;

  function openManageLabelsModal(itemId) {
    try {
      const item = state.vaultItems.find(i => String(i.id) === String(itemId));
      if (!item) return;

      currentManageItemId = item.id;
      let existing = [];
      if (Array.isArray(item.tags)) {
        existing = item.tags;
      } else if (typeof item.tags === 'string') {
        existing = item.tags.split(/[,#\s]+/).filter(Boolean);
      }
      tempManageTags = [...existing];

      const input = document.getElementById('input-new-label-name');
      if (input) input.value = '';

      const titleEl = document.getElementById('manage-labels-modal-title');
      if (titleEl) titleEl.textContent = `Manage Labels: ${item.title}`;

      renderLabelCheckmarksList();

      const modal = document.getElementById('modal-manage-labels');
      if (modal) modal.classList.add('active');
    } catch (err) {
      console.error('Error opening manage labels modal:', err);
      showToast('Error opening label manager', 'error');
    }
  }

  function renderLabelCheckmarksList() {
    const container = document.getElementById('labels-checkmark-list');
    if (!container) return;

    const allTags = new Set();
    state.vaultItems.forEach(i => {
      if (i && i.tags) {
        if (Array.isArray(i.tags)) {
          i.tags.forEach(t => { if (t) allTags.add(String(t).replace(/^#/, '').trim()); });
        } else if (typeof i.tags === 'string') {
          i.tags.split(/[,#\s]+/).forEach(t => { if (t) allTags.add(t.replace(/^#/, '').trim()); });
        }
      }
    });
    tempManageTags.forEach(t => { if (t) allTags.add(String(t).replace(/^#/, '').trim()); });

    const tagsArray = Array.from(allTags).filter(Boolean);
    container.innerHTML = '';

    if (tagsArray.length === 0) {
      container.innerHTML = `
        <div style="text-align:center; padding:1.5rem; color:var(--text-muted); font-size:0.85rem;">
          <i class="fa-solid fa-tags" style="font-size:1.5rem; margin-bottom:0.5rem; color:var(--text-dim);"></i><br>
          No labels created yet. Type a label name above to create your first label!
        </div>
      `;
      return;
    }

    tagsArray.forEach(tag => {
      const isChecked = tempManageTags.includes(tag);
      const row = document.createElement('div');
      row.className = 'label-checkmark-row';
      row.style.cssText = `
        display:flex; align-items:center; justify-content:space-between;
        padding:0.65rem 0.85rem; border-radius:10px;
        background:${isChecked ? 'rgba(139,92,246,0.15)' : 'rgba(255,255,255,0.03)'};
        border:1px solid ${isChecked ? 'rgba(139,92,246,0.35)' : 'rgba(255,255,255,0.08)'};
        cursor:pointer; transition:all 0.15s ease;
      `;

      row.innerHTML = `
        <div style="display:flex; align-items:center; gap:0.75rem; overflow:hidden; flex:1;">
          <input type="checkbox" class="label-checkbox" data-tag="${escapeHtml(tag)}" ${isChecked ? 'checked' : ''} style="width:18px; height:18px; accent-color:var(--accent-purple); cursor:pointer; flex-shrink:0;">
          <span style="font-size:0.9rem; font-weight:600; color:${isChecked ? '#fff' : 'var(--text-muted)'}; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">#${escapeHtml(tag)}</span>
        </div>
        <div style="display:flex; align-items:center; gap:0.5rem; flex-shrink:0;">
          <span class="badge-pill label-badge" style="font-size:0.7rem; background:${isChecked ? 'rgba(139,92,246,0.25)' : 'rgba(255,255,255,0.06)'}; color:${isChecked ? 'var(--accent-purple)' : 'var(--text-dim)'};">${isChecked ? 'Assigned' : 'Unassigned'}</span>
          <button type="button" class="btn-icon btn-delete-label" style="color:var(--accent-red); font-size:0.9rem; padding:0.3rem;" title="Delete globally"><i class="fa-solid fa-trash"></i></button>
        </div>
      `;

      const cb = row.querySelector('.label-checkbox');
      const badge = row.querySelector('.label-badge');
      const labelText = row.querySelector('span');
      const btnDelLabel = row.querySelector('.btn-delete-label');

      const updateRowUI = (checked) => {
        if (checked) {
          if (!tempManageTags.includes(tag)) tempManageTags.push(tag);
          row.style.background = 'rgba(139,92,246,0.15)';
          row.style.borderColor = 'rgba(139,92,246,0.35)';
          if (badge) {
            badge.textContent = 'Assigned';
            badge.style.background = 'rgba(139,92,246,0.25)';
            badge.style.color = 'var(--accent-purple)';
          }
          if (labelText) labelText.style.color = '#fff';
        } else {
          tempManageTags = tempManageTags.filter(t => t !== tag);
          row.style.background = 'rgba(255,255,255,0.03)';
          row.style.borderColor = 'rgba(255,255,255,0.08)';
          if (badge) {
            badge.textContent = 'Unassigned';
            badge.style.background = 'rgba(255,255,255,0.06)';
            badge.style.color = 'var(--text-dim)';
          }
          if (labelText) labelText.style.color = 'var(--text-muted)';
        }
      };

      cb.addEventListener('change', (e) => {
        e.stopPropagation();
        updateRowUI(cb.checked);
      });

      if (btnDelLabel) {
        btnDelLabel.addEventListener('click', async (e) => {
          e.stopPropagation();
          if (confirm(`Are you sure you want to permanently delete the label "#${tag}" from ALL vault items?`)) {
            tempManageTags = tempManageTags.filter(t => t !== tag);
            state.vaultItems.forEach(item => {
              if (Array.isArray(item.tags)) {
                item.tags = item.tags.filter(t => t.replace(/^#/, '').trim() !== tag);
              } else if (typeof item.tags === 'string') {
                item.tags = item.tags.split(/[,#\s]+/).map(t => t.replace(/^#/, '').trim()).filter(t => t && t !== tag).join(',');
              }
            });
            await renderVault();
            await saveVaultToGitHub();
            renderLabelCheckmarksList();
            showToast(`Label #${tag} deleted globally`, 'success');
          }
        });
      }

      row.addEventListener('click', (e) => {
        if (e.target !== cb && !e.target.closest('.btn-delete-label')) {
          cb.checked = !cb.checked;
          updateRowUI(cb.checked);
        }
      });

      container.appendChild(row);
    });
  }

  function handleAddNewLabel() {
    const input = document.getElementById('input-new-label-name');
    if (!input) return;
    const rawVal = input.value.trim().toLowerCase().replace(/^#/, '').replace(/[^a-z0-9_-]/g, '');
    if (!rawVal) {
      showToast('Please type a valid label name!', 'error');
      return;
    }

    if (!tempManageTags.includes(rawVal)) {
      tempManageTags.push(rawVal);
    }
    input.value = '';
    renderLabelCheckmarksList();
    showToast(`Added label #${rawVal}`, 'info');
  }

  async function handleSaveItemLabels() {
    if (!currentManageItemId) return;
    const item = state.vaultItems.find(i => String(i.id) === String(currentManageItemId));
    if (!item) return;

    item.tags = [...tempManageTags];
    item.updatedAt = Date.now();

    await renderVault();
    closeModal();
    await saveVaultToGitHub();
    showToast(`Labels updated for ${item.title}!`, 'success');
  }

  // --- SECURITY AUDIT VIEW GENERATION ---
  function renderSecurityAudit() {
    if (!DOM.viewSec) return;
    const container = DOM.viewSec.querySelector('#security-audit-container');
    if (!container) return;
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
            await renderVault();
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
          await renderVault();
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
      sessionStorage.clear();
      state.masterKey = null;
      state.vaultItems = [];
      location.reload();
    }
  }

  // --- SAFE EVENT LISTENERS SETUP ---
  function setupEventListeners() {
    if (DOM.unlockForm) DOM.unlockForm.addEventListener('submit', handleUnlock);
    if (DOM.btnLockNow) DOM.btnLockNow.addEventListener('click', lockVault);
    if (DOM.colorSwatches) {
      DOM.colorSwatches.forEach(swatch => {
        swatch.addEventListener('click', (e) => {
          DOM.colorSwatches.forEach(s => s.classList.remove('active'));
          e.target.classList.add('active');
          state.currentColor = e.target.dataset.color || 'default';
        });
      });
    }

    document.addEventListener('click', (e) => {
      if (!e.target.closest('.card-dropdown-wrapper')) {
        document.querySelectorAll('.card-dropdown-menu').forEach(m => m.classList.add('hidden'));
      }
    });

    if (DOM.dangerWipeInput) {
      DOM.dangerWipeInput.addEventListener('input', (e) => {
        const val = e.target.value.trim();
        const isMatch = (val === 'DELETE');
        if (DOM.btnDangerWipe) {
          DOM.btnDangerWipe.disabled = !isMatch;
          DOM.btnDangerWipe.classList.toggle('unlocked', isMatch);
        }
      });
    }

    if (DOM.btnDangerWipe) DOM.btnDangerWipe.addEventListener('click', wipeVaultData);

    const btnAddTagAction = document.getElementById('btn-add-label-action');
    if (btnAddTagAction) btnAddTagAction.addEventListener('click', handleAddNewLabel);

    const inputNewTagAction = document.getElementById('input-new-label-name');
    if (inputNewTagAction) {
      inputNewTagAction.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          handleAddNewLabel();
        }
      });
    }

    const btnSaveTagsAction = document.getElementById('btn-save-labels-action');
    if (btnSaveTagsAction) btnSaveTagsAction.addEventListener('click', handleSaveItemLabels);

    const btnManualSync = document.getElementById('btn-manual-sync');
    if (btnManualSync) {
      btnManualSync.addEventListener('click', async () => {
        if (!state.masterKey) {
          showToast('Please unlock vault first', 'warning');
          return;
        }
        btnManualSync.disabled = true;
        btnManualSync.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Syncing...`;
        await saveVaultToGitHub();
        btnManualSync.disabled = false;
        btnManualSync.innerHTML = `<i class="fa-solid fa-rotate"></i> Force Manual Sync with GitHub`;
      });
    }

    if (DOM.mobileMenuToggle) DOM.mobileMenuToggle.addEventListener('click', openMobileMenu);
    if (DOM.mobileMenuClose) DOM.mobileMenuClose.addEventListener('click', closeMobileMenu);
    if (DOM.mobileBackdrop) DOM.mobileBackdrop.addEventListener('click', closeMobileMenu);

    if (DOM.itemPassword) {
      DOM.itemPassword.addEventListener('input', (e) => {
        updateItemPasswordStrength(e.target.value);
      });
    }


    const allSidebarButtons = document.querySelectorAll('.sidebar-nav .nav-item');
    function setActiveSidebarButton(targetBtn) {
      allSidebarButtons.forEach(b => b.classList.remove('active'));
      if (targetBtn) targetBtn.classList.add('active');
    }

    DOM.navItems.forEach(btn => {
      btn.addEventListener('click', async () => {
        setActiveSidebarButton(btn);
        state.currentCategory = btn.dataset.category;
        state.selectedTag = null;
        switchView(DOM.viewVault);
        await renderVault();
        closeMobileMenu();
      });
    });

    if (DOM.navAuth) {
      DOM.navAuth.addEventListener('click', () => {
        setActiveSidebarButton(DOM.navAuth);
        render2FAAuthenticatorView();
        switchView(DOM.viewAuth);
        closeMobileMenu();
      });
    }

    if (DOM.btnAdd2fa) {
      DOM.btnAdd2fa.addEventListener('click', openAddModal);
    }

    if (DOM.navGen) {
      DOM.navGen.addEventListener('click', () => {
        setActiveSidebarButton(DOM.navGen);
        switchView(DOM.viewGen);
        closeMobileMenu();
      });
    }

    if (DOM.navSec) {
      DOM.navSec.addEventListener('click', () => {
        setActiveSidebarButton(DOM.navSec);
        renderSecurityAudit();
        switchView(DOM.viewSec);
        closeMobileMenu();
      });
    }

    if (DOM.navSet) {
      DOM.navSet.addEventListener('click', () => {
        setActiveSidebarButton(DOM.navSet);
        switchView(DOM.viewSet);
        closeMobileMenu();
      });
    }

    if (DOM.searchInput) {
      DOM.searchInput.addEventListener('input', async (e) => {
        state.searchQuery = e.target.value;
        if (DOM.clearSearch) DOM.clearSearch.classList.toggle('hidden', !state.searchQuery);
        await renderVault();
      });
    }

    if (DOM.clearSearch) {
      DOM.clearSearch.addEventListener('click', async () => {
        if (DOM.searchInput) DOM.searchInput.value = '';
        state.searchQuery = '';
        DOM.clearSearch.classList.add('hidden');
        await renderVault();
      });
    }

    if (DOM.sortSelect) {
      DOM.sortSelect.addEventListener('change', async (e) => {
        state.sortBy = e.target.value;
        await renderVault();
      });
    }

    if (DOM.btnViewGrid) {
      DOM.btnViewGrid.addEventListener('click', async () => {
        state.currentViewMode = 'grid';
        DOM.btnViewGrid.classList.add('active');
        if (DOM.btnViewList) DOM.btnViewList.classList.remove('active');
        await renderVault();
      });
    }

    if (DOM.btnViewList) {
      DOM.btnViewList.addEventListener('click', async () => {
        state.currentViewMode = 'list';
        DOM.btnViewList.classList.add('active');
        if (DOM.btnViewGrid) DOM.btnViewGrid.classList.remove('active');
        await renderVault();
      });
    }

    if (DOM.btnAddItem) DOM.btnAddItem.addEventListener('click', openAddModal);
    if (DOM.btnEmptyAdd) DOM.btnEmptyAdd.addEventListener('click', openAddModal);
    if (DOM.btnQuickGen) {
      DOM.btnQuickGen.addEventListener('click', () => {
        updateGeneratorView();
        switchView(DOM.viewGen);
      });
    }

    if (DOM.genLength) {
      DOM.genLength.addEventListener('input', (e) => {
        if (DOM.genLengthVal) DOM.genLengthVal.textContent = e.target.value;
        updateGeneratorView();
      });
    }

    [DOM.genUpper, DOM.genLower, DOM.genNum, DOM.genSym, DOM.genAvoid].forEach(chk => {
      if (chk) chk.addEventListener('change', updateGeneratorView);
    });

    if (DOM.btnRegen) DOM.btnRegen.addEventListener('click', updateGeneratorView);
    if (DOM.btnCopyGen) {
      DOM.btnCopyGen.addEventListener('click', () => {
        if (DOM.genResult) copyToClipboard(DOM.genResult.textContent, 'Generated password copied!');
      });
    }

    if (DOM.btnModalGen) {
      DOM.btnModalGen.addEventListener('click', () => {
        const pass = Generator.generate({
          length: 20, uppercase: true, lowercase: true, numbers: true, symbols: true
        });
        if (DOM.itemPassword) DOM.itemPassword.value = pass;
        updateItemPasswordStrength(pass);
        showToast('Generated strong password!', 'info');
      });
    }

    if (DOM.itemForm) DOM.itemForm.addEventListener('submit', handleSaveItem);
    document.querySelectorAll('.close-modal').forEach(btn => btn.addEventListener('click', closeModal));
    if (DOM.itemType) DOM.itemType.addEventListener('change', (e) => switchCategoryFields(e.target.value));

    if (DOM.btnExportEncrypted) DOM.btnExportEncrypted.addEventListener('click', exportEncryptedBackup);
    if (DOM.btnExportCsv) DOM.btnExportCsv.addEventListener('click', exportCSV);
    if (DOM.btnTriggerImport && DOM.importFileInput) {
      DOM.btnTriggerImport.addEventListener('click', () => DOM.importFileInput.click());
      DOM.importFileInput.addEventListener('change', (e) => {
        if (e.target.files[0]) handleImportFile(e.target.files[0]);
      });
    }

    if (DOM.settingAutolock) {
      DOM.settingAutolock.addEventListener('change', (e) => {
        state.autoLockMinutes = parseInt(e.target.value, 10);
        resetAutoLockTimer();
        const txt = state.autoLockMinutes === 0 ? 'Auto-lock disabled (Manual Logout Only)' : `Auto-lock set to ${state.autoLockMinutes} mins`;
        showToast(txt, 'info');
      });
    }

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
        if (DOM.searchInput) DOM.searchInput.focus();
      }
    });
  }

  function switchView(targetView) {
    if (!targetView) return;
    document.querySelectorAll('.view-section').forEach(v => v.classList.remove('active'));
    targetView.classList.add('active');
  }

  function updateGeneratorView() {
    if (!DOM.genResult) return;
    const opts = {
      length: DOM.genLength ? parseInt(DOM.genLength.value, 10) : 20,
      uppercase: DOM.genUpper ? DOM.genUpper.checked : true,
      lowercase: DOM.genLower ? DOM.genLower.checked : true,
      numbers: DOM.genNum ? DOM.genNum.checked : true,
      symbols: DOM.genSym ? DOM.genSym.checked : true,
      avoidSimilar: DOM.genAvoid ? DOM.genAvoid.checked : false
    };
    const pass = Generator.generate(opts);
    DOM.genResult.textContent = pass;

    const metrics = Generator.calculateStrength(pass);
    if (DOM.genStrengthBadge) {
      DOM.genStrengthBadge.textContent = metrics.text;
      DOM.genStrengthBadge.className = `badge-pill ${metrics.score}`;
    }
    if (DOM.genEntropyVal) DOM.genEntropyVal.textContent = `${metrics.entropy} bits`;
    if (DOM.genCrackTime) DOM.genCrackTime.textContent = metrics.crackTime;
  }

  function updateItemPasswordStrength(pass) {
    if (!DOM.itemStrengthBar) return;
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
    return date.toLocaleDateString('en-IN', { month: 'short', day: 'numeric', year: 'numeric' });
  }

  // --- INITIALIZATION ---
  async function init() {
    setupEventListeners();
    await checkMasterStatus();
    updateGeneratorView();
  }

  document.addEventListener('DOMContentLoaded', init);

})();
