/**
 * CIPHERVAULT - Zero-Knowledge Password Manager Engine
 * Database: Private GitHub Repository (`sachinmandawi/ciphervault-db`)
 * Session Handling: Tab Session Persistence via SessionStorage (Persists on F5 Refresh)
 * Features: AES-256-GCM Zero-Knowledge, Dedicated Live 2FA Authenticator Section, 1-Click Preview,
 * Encrypted File Attachments (Max 10MB), Custom Tags System
 */

(function () {
  'use strict';

  // --- SECURE CONTEXT GUARD ---
  if (window.isSecureContext === false || !window.crypto || !window.crypto.subtle) {
    document.addEventListener('DOMContentLoaded', () => {
      document.body.innerHTML = `
        <div style="display:flex; height:100vh; background:#0f172a; color:#f8fafc; font-family:sans-serif; align-items:center; justify-content:center; text-align:center; padding:2rem;">
          <div style="max-width:500px; background:rgba(239, 68, 68, 0.1); border:1px solid rgba(239, 68, 68, 0.3); padding:2rem; border-radius:12px;">
            <h1 style="color:#ef4444; margin-bottom:1rem; font-size:1.5rem;"><i class="fa-solid fa-triangle-exclamation"></i> Insecure Connection Detected</h1>
            <p style="color:#94a3b8; line-height:1.6; font-size:1rem;">CipherVault is a Zero-Knowledge Password Manager that relies on the Web Crypto API to encrypt your data locally. Modern browsers strictly disable this API on insecure connections to protect you.</p>
            <p style="color:#f8fafc; margin-top:1.5rem; font-weight:600;">Please access this site over <span style="color:#10b981;">HTTPS</span> or localhost to continue.</p>
          </div>
        </div>
      `;
    });
    return;
  }

  // Private GitHub DB Configuration
  const GITHUB_CONFIG = {
    owner: '', // dynamically resolved
    repo: 'ciphervault-db',
    path: 'vault.json',
    getToken: function () {
      return localStorage.getItem('cipher_gh_token');
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
        'Authorization': `Bearer ${GITHUB_CONFIG.getToken()}`,
        'Accept': 'application/vnd.github.v3+json',
        'Content-Type': 'application/json'
      };
    },

    initUser: async function () {
      if (GITHUB_CONFIG.owner) return GITHUB_CONFIG.owner;
      const res = await fetch('https://api.github.com/user', { headers: this.getHeaders(), cache: 'no-store' });
      if (res.status === 401) {
        localStorage.removeItem('cipher_gh_token');
        window.location.reload();
        return;
      }
      if (!res.ok) throw new Error(`GitHub User API HTTP ${res.status}`);
      const data = await res.json();
      GITHUB_CONFIG.owner = data.login;

      // Update DB status card with real user details
      const repoNameEl = document.getElementById('db-repo-name');
      const repoLinkEl = document.getElementById('db-repo-link');
      const repoUrl = `https://github.com/${data.login}/ciphervault-db`;
      if (repoNameEl) repoNameEl.textContent = `${data.login}/ciphervault-db`;
      if (repoLinkEl) repoLinkEl.href = repoUrl;

      return data.login;
    },

    createRepoIfNotExists: async function () {
      if (!GITHUB_CONFIG.owner) await this.initUser();
      const checkRes = await fetch(`https://api.github.com/repos/${GITHUB_CONFIG.owner}/${GITHUB_CONFIG.repo}`, { headers: this.getHeaders(), cache: 'no-store' });
      if (checkRes.ok) return;
      if (checkRes.status !== 404) throw new Error(`GitHub Repo Check HTTP ${checkRes.status}`);

      const res = await fetch('https://api.github.com/user/repos', {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ name: GITHUB_CONFIG.repo, private: true, description: "CipherVault Encrypted Database" })
      });
      if (!res.ok) throw new Error(`GitHub Create Repo HTTP ${res.status}`);
    },

    fetchVaultFile: async function () {
      if (!GITHUB_CONFIG.owner) await this.initUser();
      const url = `https://api.github.com/repos/${GITHUB_CONFIG.owner}/${GITHUB_CONFIG.repo}/contents/${GITHUB_CONFIG.path}?nocache=${Date.now()}`;
      const res = await fetch(url, { headers: this.getHeaders(), cache: 'no-store' });
      // 404 = new user, no vault yet — return null gracefully instead of throwing
      if (res.status === 404) return null;
      if (!res.ok) throw new Error(`GitHub API HTTP ${res.status}`);
      const data = await res.json();
      
      let contentStr = '';
      if (data.content && data.content.trim() !== '') {
        contentStr = new TextDecoder().decode(Uint8Array.from(atob(data.content.replace(/\n|\r/g, '')), c => c.charCodeAt(0)));
      } else if (data.sha) {
        // Large file (>1MB) fallback: fetch via git/blobs endpoint
        const blobUrl = `https://api.github.com/repos/${GITHUB_CONFIG.owner}/${GITHUB_CONFIG.repo}/git/blobs/${data.sha}?nocache=${Date.now()}`;
        const blobRes = await fetch(blobUrl, { headers: this.getHeaders(), cache: 'no-store' });
        if (!blobRes.ok) throw new Error(`GitHub Blob API HTTP ${blobRes.status}`);
        const blobData = await blobRes.json();
        contentStr = new TextDecoder().decode(Uint8Array.from(atob(blobData.content.replace(/\n|\r/g, '')), c => c.charCodeAt(0)));
      } else {
        throw new Error('No content or sha returned from GitHub DB');
      }

      return {
        sha: data.sha,
        payload: JSON.parse(contentStr)
      };
    },

    saveVaultFile: async function (encryptedPayload, sha) {
      await this.createRepoIfNotExists();
      const url = `https://api.github.com/repos/${GITHUB_CONFIG.owner}/${GITHUB_CONFIG.repo}/contents/${GITHUB_CONFIG.path}`;
      const jsonStr = JSON.stringify(encryptedPayload, null, 2);
      const contentBase64 = window.btoa(Array.from(new TextEncoder().encode(jsonStr)).map(b => String.fromCharCode(b)).join(''));
      
      const body = {
        message: `Sync vault updates - ${new Date().toLocaleString()}`,
        content: contentBase64,
        ...(sha ? { sha } : {})
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
    sortBy: 'custom',
    autoLockTimer: null,
    autoLockMinutes: 0,
    fileSha: null,
    saltBase64: null,
    verifierObj: null,
    cachedPayload: null,
    totpTimer: null,
    isSyncBroken: false,
  };

  // Auto-resize textareas
  document.querySelectorAll('textarea.auto-expand').forEach(textarea => {
    textarea.addEventListener('input', function() {
      this.style.height = 'auto';
      this.style.height = this.scrollHeight + 'px';
    });
  });

  // --- DOM ELEMENTS ---
  const DOM = {
    authOverlay: document.getElementById('auth-overlay'),
    setupForm: document.getElementById('setup-form'),
    unlockForm: document.getElementById('unlock-form'),
    githubAuthStep: document.getElementById('github-auth-step'),
    btnGithubLogin: document.getElementById('btn-github-login'),
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
    viewPreview: document.getElementById('view-preview'),
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
    viewPreview: document.getElementById('view-preview'),
    viewItemEdit: document.getElementById('view-item-edit'),
    modalItemTitle: document.getElementById('modal-item-title'),
    itemForm: document.getElementById('item-form'),
    itemId: document.getElementById('item-id'),
    itemType: document.getElementById('item-type'),
    itemTitleInput: document.getElementById('item-title-input'),
    itemUsername: document.getElementById('item-username'),
    itemEmail: document.getElementById('item-email'),
    itemMobile: document.getElementById('item-mobile'),
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

    // Toast
    toastContainer: document.getElementById('toast-container'),
    vaultStatsGrid: document.querySelector('#view-vault .stats-grid')
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
  function showToast(message, type = 'info', subtitle = '') {
    if (!DOM.toastContainer) return;
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    let iconClass = 'fa-info-circle';
    if (type === 'success') iconClass = 'fa-circle-check';
    if (type === 'error') iconClass = 'fa-triangle-exclamation';
    if (type === 'warning') iconClass = 'fa-triangle-exclamation';

    toast.innerHTML = `
      <div class="toast-icon"><i class="fa-solid ${iconClass}"></i></div>
      <div class="toast-body">
        <div class="toast-title">${message}</div>
        ${subtitle ? `<div class="toast-subtitle">${subtitle}</div>` : ''}
      </div>
      <button class="toast-close" onclick="this.closest('.toast').remove()"><i class="fa-solid fa-xmark"></i></button>
    `;
    DOM.toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(110%)';
      toast.style.transition = 'all 0.4s ease';
      setTimeout(() => toast.remove(), 400);
    }, 4000);
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
    const hasToken = !!GITHUB_CONFIG.getToken();

    // Hide all forms first
    if (DOM.githubAuthStep) DOM.githubAuthStep.classList.add('hidden');
    if (DOM.setupForm) DOM.setupForm.classList.add('hidden');
    if (DOM.unlockForm) DOM.unlockForm.classList.add('hidden');

    // No token & no cache → show GitHub login step
    if (!hasToken && !cached) {
      if (DOM.githubAuthStep) DOM.githubAuthStep.classList.remove('hidden');
      return;
    }

    // Has cache → instantly show unlock form (returning user)
    if (cached) {
      try {
        const payload = JSON.parse(cached);
        state.fileSha = cachedSha || null;
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
    } else {
      // Has token but no cache → show loading spinner while fetching from GitHub
      const titleEl = document.getElementById('auth-title');
      const subEl = document.getElementById('auth-subtitle');
      if (titleEl) titleEl.textContent = 'Connecting...';
      if (subEl) subEl.innerHTML = '<i class="fa-solid fa-spinner fa-spin" style="margin-right:0.4rem;"></i>Checking your GitHub vault...';
    }

    // Fetch from GitHub (background for cached users, awaited for uncached users)
    const fetchPromise = GitHubDB.fetchVaultFile().then(async remote => {
      // null = 404 → no vault file exists → new user
      if (!remote || !remote.payload) {
        if (!cached) {
          // Confirmed new user — show setup form now
          if (DOM.setupForm) DOM.setupForm.classList.remove('hidden');
          const titleEl = document.getElementById('auth-title');
          const subEl = document.getElementById('auth-subtitle');
          if (titleEl) titleEl.textContent = 'Create Your Vault';
          if (subEl) subEl.textContent = 'Set your master password to get started';
        }
        return;
      }

      // Got remote vault → returning user (even on new device with no cache)
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

      // Always show unlock form once we have remote data
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
      if (cached) {
        // Returning user gone offline — show unlock form with cache
        if (DOM.unlockForm) DOM.unlockForm.classList.remove('hidden');
        showToast('Offline Mode Active', 'warning', 'Using your last cached vault session.');
      } else {
        // No cache, no network → show GitHub login to reconnect
        if (DOM.githubAuthStep) DOM.githubAuthStep.classList.remove('hidden');
        const titleEl = document.getElementById('auth-title');
        if (titleEl) titleEl.textContent = 'Connection Failed';
      }
    });

    // For uncached users: MUST await fetch before continuing (prevents flash)
    if (!cached) {
      try { await fetchPromise; } catch(e) {}
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

  async function handleSetup(e) {
      if (e) e.preventDefault();
      const user = DOM.setupUser ? DOM.setupUser.value.trim() : '';
      const pass = DOM.setupPass ? DOM.setupPass.value : '';
      const confirm = DOM.setupConfirm ? DOM.setupConfirm.value : '';

      if (pass.length < 8) {
        showToast('Master password must be at least 8 characters!', 'error');
        return;
      }
      if (pass !== confirm) {
        showToast('Passwords do not match!', 'error');
        return;
      }

      try {
        const salt = CryptoEngine.generateSalt();
        state.saltBase64 = CryptoEngine.bufferToBase64(salt);
        const key = await CryptoEngine.deriveKey(pass, salt);
        state.verifierObj = await CryptoEngine.createKeyVerifier(key);
        state.masterKey = key;
        state.vaultItems = [];
        state.fileSha = null;

        sessionStorage.setItem('cipher_active_pass', pass);
        
        const payload = {
          salt: state.saltBase64,
          verifier: state.verifierObj,
          vault: []
        };
        localStorage.setItem('cipher_offline_vault', JSON.stringify(payload));

        if (GITHUB_CONFIG.getToken()) {
          try {
            await saveVaultToGitHub();
          } catch(e) {
            console.warn('GitHub sync skipped during setup:', e);
          }
        }

        if (DOM.setupForm) DOM.setupForm.classList.add('hidden');
        unlockVault();
        showToast('Vault initialized successfully!', 'success');
      } catch (err) {
        showToast('Failed to initialize vault: ' + err.message, 'error');
        console.error('Setup Error:', err);
      }
    }

    async function handleUnlock(e) {
      if (e) e.preventDefault();
      const user = DOM.unlockUser ? DOM.unlockUser.value.trim() : '';
      const pass = DOM.unlockPass ? DOM.unlockPass.value.trim() : '';
      if (DOM.unlockError) DOM.unlockError.classList.add('hidden');

      try {
        if (user.toLowerCase() !== GITHUB_CONFIG.owner.toLowerCase()) {
          if (DOM.unlockError) DOM.unlockError.classList.remove('hidden');
          return;
        }

        if (!state.saltBase64 || !state.verifierObj) {
          const cached = localStorage.getItem('cipher_offline_vault');
          if (cached) {
            try {
              const payload = JSON.parse(cached);
              state.saltBase64 = payload.salt;
              state.verifierObj = payload.verifier;
              state.cachedPayload = payload;
            } catch(err) {}
          }
        }

        if (!state.saltBase64 || !state.verifierObj) {
          const remote = await GitHubDB.fetchVaultFile();
          if (remote && remote.payload) {
            state.fileSha = remote.sha;
            state.saltBase64 = remote.payload.salt;
            state.verifierObj = remote.payload.verifier;
            state.cachedPayload = remote.payload;
            localStorage.setItem('cipher_offline_vault', JSON.stringify(remote.payload));
            localStorage.setItem('cipher_offline_sha', remote.sha);
          }
        }

        if (!state.saltBase64 || !state.verifierObj) {
          showToast('Session expired. Please sign in with GitHub to fetch your vault.', 'warning');
          if (DOM.githubAuthStep) DOM.githubAuthStep.classList.remove('hidden');
          if (DOM.unlockForm) DOM.unlockForm.classList.add('hidden');
          return;
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
        console.error('Unlock Error:', err);
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
        let decrypted = await CryptoEngine.decryptData(payload.vault, key);
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
            i.tags = i.tags.split(/[,#\s]+/).map(t => t.trim()).filter(Boolean);
          }
          if (!Array.isArray(i.tags)) {
            i.tags = [];
          }
        });
        state.vaultItems = items;
        // Auto-purge trash items older than 30 days on every vault load
        await purgeExpiredTrashItems();
      } else {
        state.vaultItems = [];
      }
      updateLastSyncTime();
    } catch (err) {
      showToast('Error loading from Private GitHub DB', 'error');
      state.isSyncBroken = true;
    }
  }

  async function saveVaultToGitHub() {
    if (!state.masterKey) return;
    if (state.isSyncBroken) {
      showToast('CRITICAL: Sync disabled due to a previous load error to prevent data loss. Please refresh the page.', 'error');
      return;
    }
    let payload = null;
    try {
      showToast('Syncing with Private GitHub Repo...', 'info');
      const vaultData = { items: state.vaultItems, customOrders: state.customOrders };
      const encryptedVault = await CryptoEngine.encryptData(vaultData, state.masterKey);
      
      payload = {
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
      if (payload) {
        state.cachedPayload = payload;
        localStorage.setItem('cipher_offline_vault', JSON.stringify(payload));
      }
      showToast('Saved offline. Sync failed!', 'warning');
    }
  }

  function unlockVault() {
    if (DOM.authOverlay) DOM.authOverlay.classList.remove('active');
    if (DOM.app) DOM.app.classList.remove('blur-content');
    const lp = document.getElementById('landing-page');
    if (lp) lp.classList.remove('active');

    const savedView = sessionStorage.getItem('cipher_active_view');
    const savedCat = sessionStorage.getItem('cipher_active_category');
    const savedTag = sessionStorage.getItem('cipher_active_tag');

    if (savedCat) state.currentCategory = savedCat;
    if (savedTag) state.selectedTag = savedTag;
    
    // Update sidebar UI state
    document.querySelectorAll('.sidebar-nav .nav-item').forEach(b => b.classList.remove('active'));
    
    if (savedView === 'view-settings') {
      const settingsBtn = document.querySelector('.nav-item[data-category="settings"]');
      if (settingsBtn) settingsBtn.classList.add('active');
      if (DOM.viewSettings) {
        document.querySelectorAll('.view-section').forEach(v => v.classList.remove('active'));
        DOM.viewSettings.classList.add('active');
      }
    } else if (savedView === 'view-auth') {
      const authBtn = document.getElementById('nav-auth');
      if (authBtn) authBtn.classList.add('active');
      if (DOM.viewAuth) {
        document.querySelectorAll('.view-section').forEach(v => v.classList.remove('active'));
        DOM.viewAuth.classList.add('active');
        render2FAAuthenticatorView();
      }
    } else {
      if (!state.selectedTag) {
        const catBtn = document.querySelector(`.nav-item[data-category="${state.currentCategory}"]`);
        if (catBtn) catBtn.classList.add('active');
      }
      if (DOM.viewVault) {
        document.querySelectorAll('.view-section').forEach(v => v.classList.remove('active'));
        DOM.viewVault.classList.add('active');
      }
    }

    renderVault();
    resetAutoLockTimer();
    startTOTPTimer();
    
    // Proactive Stale Password Check
    const staleCount = state.vaultItems.filter(item => {
      if (item.type !== 'login' || !item.password) return false;
      const pwdTime = item.passwordUpdatedAt || item.updatedAt || item.createdAt || Date.now();
      return ((Date.now() - pwdTime) / (1000 * 60 * 60 * 24)) >= 30;
    }).length;

    if (staleCount > 0) {
      setTimeout(() => {
        showToast(`Security Alert: ${staleCount} password(s) are outdated (> 30 days). Check Health Audit!`, 'error');
      }, 1500);
    }
  }

  function lockVault() {
    state.masterKey = null;
    state.vaultItems = [];
    sessionStorage.removeItem('cipher_active_pass');
    if (DOM.authOverlay) DOM.authOverlay.classList.add('active');
    if (DOM.app) DOM.app.classList.add('blur-content');
    const lp = document.getElementById('landing-page');
    if (lp) lp.classList.remove('active');
    
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
      card.style.border = '1px solid var(--bg-hover)';
      card.style.background = 'var(--bg-hover)';
      card.setAttribute('data-totp-secret', item.totp);

      card.innerHTML = `
        <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:0.85rem; width:100%;">
          <div style="display:flex; align-items:center; gap:0.75rem; flex:1; overflow:hidden;">
            <div style="width:40px; height:40px; border-radius:10px; background:var(--bg-hover); border:1px solid var(--border-color); color:var(--accent-cyan); display:flex; align-items:center; justify-content:center; font-size:1.15rem; flex-shrink:0;">
              <i class="fa-solid fa-shield-halved"></i>
            </div>
            <div style="overflow:hidden; min-width:0;">
              <h4 style="margin:0; font-size:1.05rem; color:#fff; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(item.title)}</h4>
              <span style="font-size:0.8rem; color:var(--text-muted); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; display:block;">${escapeHtml(item.username || 'No Username')}</span>
            </div>
          </div>
          <span class="totp-sec-countdown badge-pill good" style="font-size:0.78rem; flex-shrink:0; padding:0.25rem 0.65rem;">${secLeft}s</span>
        </div>

        <div style="background:rgba(8,11,18,0.9); border:1px solid var(--border-color); padding:1rem 1.25rem; border-radius:12px; display:flex; align-items:center; justify-content:space-between; margin-bottom:0.85rem; width:100%;">
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


  function getIconHtml(item) {
    let iconHtml = '<i class="fa-solid fa-globe"></i>';
    if (item.type === 'card') iconHtml = '<i class="fa-regular fa-credit-card"></i>';
    if (item.type === 'bank') iconHtml = '<i class="fa-solid fa-building-columns"></i>';
    if (item.type === 'note') iconHtml = '<i class="fa-regular fa-note-sticky"></i>';
    return iconHtml;
  }

  async function generateItemPreviewHtml(item) {
    let rowsHtml = '';

    function createDetailRow(label, value, isSecret = false) {
      if (!value) return '';
      const rowId = 'prev_val_' + Math.random().toString(36).substr(2, 6);
      const isMonospace = isSecret || label.toLowerCase().includes('pin');
      return `
        <div class="preview-row">
          <span style="font-size:0.65rem; color:var(--text-muted); opacity:0.6; text-transform:uppercase; font-weight:600; letter-spacing:0.05em; display:block; margin-bottom:0.15rem;">${escapeHtml(label)}</span>
          <div style="display:flex; align-items:center; justify-content:space-between; gap:0.5rem;">
            <span id="${rowId}" style="font-family:${isMonospace ? 'var(--font-mono)' : 'inherit'}; font-size:1.1rem; color:var(--text-light); word-break:break-all; overflow-wrap:anywhere; flex:1; min-width:0; padding-right:0.5rem;">${isSecret ? '••••••••••••' : escapeHtml(value)}</span>
            <div class="preview-actions" style="display:flex; gap:0.25rem; flex-shrink:0;">
              ${isSecret ? `
                <button type="button" class="btn-icon btn-toggle-row-vis" data-target="${rowId}" data-real="${escapeHtml(value)}" title="Show/Hide" style="background:transparent; border:none; color:var(--text-muted);">
                  <i class="fa-regular fa-eye"></i>
                </button>
              ` : ''}
              <button type="button" class="btn-icon btn-copy-row-val" data-val="${escapeHtml(value)}" title="Copy" style="background:transparent; border:none; color:var(--text-muted);">
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
      if (item.mobile) rowsHtml += createDetailRow('Mobile Number', item.mobile);
      rowsHtml += createDetailRow('Password', item.password, true);
      
      if (item.totp) {
        const totpData = await TOTPEngine.generateTOTP(item.totp);
        const codeDisplay = totpData ? totpData.code : '------';
        const rawCode = totpData ? totpData.rawCode : '';
        const secLeft = totpData ? totpData.secondsLeft : 30;

        rowsHtml += `
          <div data-totp-secret="${escapeHtml(item.totp)}" class="preview-row">
            <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:0.15rem;">
              <span style="font-size:0.65rem; color:var(--text-muted); opacity:0.6; text-transform:uppercase; font-weight:600; letter-spacing:0.05em;">
                LIVE 2FA <span class="totp-sec-countdown" style="font-weight:400; text-transform:none;">(${secLeft}s)</span>
              </span>
            </div>
            <div style="display:flex; align-items:center; justify-content:space-between; gap:0.5rem;">
              <span class="totp-code-display" style="font-family:var(--font-mono); font-size:1.25rem; color:var(--text-light); font-weight:600; letter-spacing:0.15em; word-break:break-all;">${codeDisplay}</span>
              <div class="preview-actions" style="display:flex; gap:0.25rem; flex-shrink:0;">
                <button type="button" class="btn-icon btn-copy-totp-val" data-val="${rawCode}" title="Copy 2FA Code" style="background:transparent; border:none; color:var(--text-muted);">
                  <i class="fa-regular fa-copy"></i>
                </button>
              </div>
            </div>
          </div>
        `;
      }

      rowsHtml += createDetailRow('Website URL', item.url);
      
      if (item.backupCodes) {
        rowsHtml += `
          <div class="preview-row">
            <span style="font-size:0.65rem; color:var(--text-muted); opacity:0.6; text-transform:uppercase; font-weight:600; letter-spacing:0.05em; display:block; margin-bottom:0.15rem;">BACKUP CODES</span>
            <div style="display:flex; align-items:flex-start; justify-content:space-between; gap:0.5rem;">
              <span style="font-family:var(--font-mono); font-size:1rem; color:var(--text-light); white-space:pre-wrap; word-break:break-all; line-height:1.5;">${escapeHtml(item.backupCodes)}</span>
              <div class="preview-actions" style="display:flex; gap:0.25rem; flex-shrink:0;">
                <button type="button" class="btn-icon btn-copy-row-val" data-val="${escapeHtml(item.backupCodes)}" title="Copy All Codes" style="background:transparent; border:none; color:var(--text-muted);">
                  <i class="fa-regular fa-copy"></i>
                </button>
              </div>
            </div>
          </div>
        `;
      }
    } else if (item.type === 'card') {
      let rawNum = (item.cardnumber || '').replace(/\s+/g, '');
      let displayNum = rawNum.replace(/(.{4})/g, '$1 ').trim();
      if (!displayNum) displayNum = '•••• •••• •••• ••••';

      rowsHtml += `
        <div class="cc-3d-wrapper" onclick="this.classList.toggle('flipped')">
          <div class="cc-inner">
            <div class="cc-front">
              <div style="display:flex; justify-content:space-between; align-items:flex-start; width:100%; margin-bottom:1.5rem;">
                <div class="cc-chip"></div>
                <div class="cc-contactless" style="color:#fff;"><i class="fa-solid fa-wifi" style="transform:rotate(90deg); font-size:1.5rem; opacity:0.8;"></i></div>
              </div>
              <div style="margin-top:auto;">
                <div class="cc-number">${escapeHtml(displayNum)}</div>
                <div class="cc-details">
                  <div style="flex:1;">
                    <div class="cc-label">Cardholder</div>
                    <div class="cc-value">${escapeHtml(item.cardholder || 'YOUR NAME')}</div>
                  </div>
                  <div style="text-align:center; padding:0 0.5rem;">
                    <div class="cc-label">Valid Thru</div>
                    <div class="cc-value">${escapeHtml(item.exp || 'MM/YY')}</div>
                  </div>
                </div>
              </div>
            </div>
            <div class="cc-back">
              <div class="cc-stripe"></div>
              <div class="cc-cvv-box">
                <span style="font-size:0.6rem; color:#666; margin-right:auto; letter-spacing:0.1em; text-transform:uppercase;">CVV</span>
                ${escapeHtml(item.cvv || '•••')}
              </div>
              <div style="padding:1.5rem 1.5rem 0 1.5rem; color:#fff; opacity:0.4; font-size:0.55rem; text-align:center; margin-top:auto; line-height:1.4;">
                This card is strictly non-transferable and remains the property of the issuing entity. If found, please return to the nearest bank branch.
              </div>
            </div>
          </div>
          <div style="position:absolute; inset:0; z-index:10; background:transparent;"></div>
        </div>
      `;
      
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
          <div class="preview-row">
            <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:0.25rem;">
              <span style="font-size:0.65rem; color:var(--text-muted); opacity:0.6; text-transform:uppercase; font-weight:600; letter-spacing:0.05em;">
                SECURE NOTE
              </span>
              <button type="button" class="btn-icon btn-copy-row-val preview-actions" data-val="${escapeHtml(item.notes)}" title="Copy Note Content" style="background:transparent; border:none; color:var(--text-muted);">
                <i class="fa-regular fa-copy"></i>
              </button>
            </div>
            <div style="font-family:inherit; font-size:1.05rem; color:var(--text-light); line-height:1.6; white-space:pre-wrap; word-break:break-all; overflow-wrap:anywhere;">${(function(t) {
              const escaped = escapeHtml(t);
              const urlRegex = /(https?:\/\/[^\s]+)/g;
              return escaped.replace(urlRegex, function(url) {
                return '<span style="display:inline-block; margin:0.1rem 0;"><a href="' + url + '" target="_blank" rel="noopener noreferrer" style="color:var(--accent-purple); text-decoration:underline; vertical-align:middle;">' + url + '</a><button type="button" class="btn-icon btn-copy-inline-url" data-val="' + url + '" title="Copy Link" style="background:rgba(255,255,255,0.08); border:none; color:var(--text-muted); cursor:pointer; font-size:0.75rem; padding:0.15rem 0.35rem; border-radius:4px; margin-left:0.35rem; vertical-align:middle; transition:all 0.2s ease;"><i class="fa-regular fa-copy"></i></button></span>';
              });
            })(item.notes)}</div>
          </div>
        `;
      }
    }

    if (item.passwordHistory && item.passwordHistory.length > 0) {
      let historyRows = item.passwordHistory.map(hist => {
        const hId = 'hist_val_' + Math.random().toString(36).substr(2, 6);
        return `
          <div style="display:flex; align-items:center; justify-content:space-between; gap:0.5rem; padding:0.4rem 0; border-bottom:1px solid rgba(255,255,255,0.05);">
            <div style="flex:1; min-width:0;">
              <div style="font-size:0.7rem; color:var(--text-muted); margin-bottom:0.1rem;">${formatDate(hist.date)}</div>
              <div id="${hId}" style="font-family:var(--font-mono); font-size:0.95rem; color:var(--text-light); word-break:break-all;">••••••••</div>
            </div>
            <div class="preview-actions" style="display:flex; gap:0.25rem; flex-shrink:0;">
              <button type="button" class="btn-icon btn-toggle-row-vis" data-target="${hId}" data-real="${escapeHtml(hist.password)}" title="Show/Hide" style="background:transparent; border:none; color:var(--text-muted);">
                <i class="fa-regular fa-eye"></i>
              </button>
              <button type="button" class="btn-icon btn-copy-row-val" data-val="${escapeHtml(hist.password)}" title="Copy" style="background:transparent; border:none; color:var(--text-muted);">
                <i class="fa-regular fa-copy"></i>
              </button>
            </div>
          </div>
        `;
      }).join('');
      
      const accordionId = 'hist_acc_' + Math.random().toString(36).substr(2, 6);
      rowsHtml += `
        <div class="preview-row" style="margin-top:0.75rem;">
          <button type="button" onclick="const b = document.getElementById('${accordionId}'); b.style.display = b.style.display === 'none' ? 'block' : 'none'; const i = this.querySelector('i.chevron'); i.style.transform = b.style.display === 'none' ? 'rotate(0deg)' : 'rotate(180deg)';" style="width:100%; display:flex; align-items:center; justify-content:space-between; background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.05); padding:0.6rem 0.75rem; border-radius:var(--radius-md); color:var(--text-light); font-size:0.8rem; font-weight:500; cursor:pointer; transition:all 0.2s ease;">
            <span><i class="fa-solid fa-clock-rotate-left" style="margin-right:0.4rem; color:var(--text-muted);"></i> View Password History (${item.passwordHistory.length})</span>
            <i class="fa-solid fa-chevron-down chevron" style="color:var(--text-muted); transition:transform 0.2s ease;"></i>
          </button>
          <div id="${accordionId}" style="display:none; background:rgba(0,0,0,0.2); border-radius:var(--radius-sm); padding:0 0.5rem; margin-top:0.35rem; border:1px solid rgba(255,255,255,0.02);">
            ${historyRows}
          </div>
        </div>
      `;
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

    if (item.updatedAt) {
      rowsHtml += `
        <div style="font-size:0.75rem; color:#64748b; margin-top:0.5rem; text-align:right;">
          Last modified: ${formatDate(item.updatedAt)}
        </div>
      `;
    }
    
    return rowsHtml;
  }

  function bindPreviewActionListeners(contentEl) {
    if (!contentEl) return;
    
    contentEl.querySelectorAll('.btn-copy-row-val').forEach(btn => {
      btn.addEventListener('click', () => copyToClipboard(btn.dataset.val, 'Copied to clipboard!', btn));
    });

    contentEl.querySelectorAll('.btn-copy-totp-val').forEach(btn => {
      btn.addEventListener('click', () => copyToClipboard(btn.dataset.val, '2FA Code copied!', btn));
    });

    contentEl.querySelectorAll('.btn-copy-inline-url').forEach(btn => {
      btn.addEventListener('click', () => copyToClipboard(btn.dataset.val, 'Link copied!', btn));
    });

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

  // --- PREVIEW LOGIC (Inline Detail View) ---
  async function openPreviewModal(id) {
    const item = state.vaultItems.find(i => i.id === id);
    if (!item) return;

    const iconEl = document.getElementById('preview-icon');
    const titleEl = document.getElementById('preview-title');
    const catBadge = document.getElementById('preview-cat-badge');
    const contentEl = document.getElementById('preview-body-content');
    const editBtn = document.getElementById('btn-preview-edit');
    const backBtn = document.getElementById('btn-preview-back');

    let iconHtml = getIconHtml(item);
    if (iconEl) iconEl.innerHTML = iconHtml;

    if (titleEl) titleEl.textContent = item.title;
    if (catBadge) catBadge.textContent = (item.type || 'login').toUpperCase();

    if (contentEl) {
      contentEl.innerHTML = await generateItemPreviewHtml(item);
      bindPreviewActionListeners(contentEl);
    }

    if (editBtn) {
      editBtn.onclick = () => {
        openEditModal(item.id);
      };
    }

    const shareBtn = document.getElementById('btn-preview-share');
    if (shareBtn) {
      shareBtn.onclick = () => {
        generateShareLink(item.id);
      };
    }

    if (backBtn) {
      backBtn.onclick = () => {
        switchView(DOM.viewVault);
      };
    }

    switchView(DOM.viewPreview);
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
  }

  // --- RENDER VAULT ITEMS ---
  async function renderVault() {
    const items = getFilteredAndSortedItems();
    updateCountsAndStats();

    if (DOM.vaultStatsGrid) {
      if ((!state.currentCategory || state.currentCategory === 'all') && !state.searchQuery && !state.selectedTag) {
        DOM.vaultStatsGrid.style.display = '';
      } else {
        DOM.vaultStatsGrid.style.display = 'none';
      }
    }

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

    // Trash warning banner
    if (state.currentCategory === 'trash') {
      const banner = document.createElement('div');
      banner.style.cssText = `
        grid-column: 1 / -1;
        display: flex;
        align-items: center;
        gap: 0.85rem;
        padding: 0.85rem 1.1rem;
        border-radius: 12px;
        background: rgba(245,158,11,0.1);
        border: 1px solid rgba(245,158,11,0.3);
        color: #f59e0b;
        font-size: 0.85rem;
        margin-bottom: 0.25rem;
      `;
      banner.innerHTML = `
        <i class="fa-solid fa-triangle-exclamation" style="font-size:1.1rem; flex-shrink:0;"></i>
        <span>
          <strong>Items in Trash are permanently deleted after 30 days.</strong>
          Restore items before the deadline to keep them.
        </span>
      `;
      fragment.appendChild(banner);
    }

    cards.forEach(card => fragment.appendChild(card));
    DOM.itemsContainer.appendChild(fragment);
  }

  async function createItemCard(item) {
    const card = document.createElement('div');
    card.className = 'item-card glass-panel';
    card.dataset.id = item.id;
    
    if (!state.searchQuery) {
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

    let iconHtml = getIconHtml(item);

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
              <button type="button" class="dropdown-item btn-share">
                <i class="fa-solid fa-share-nodes"></i>
                <span>Share Securely</span>
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
          <div style="font-family:var(--font-mono); font-size:0.85rem; color:#f8fafc; line-height:1.5; white-space:pre-wrap; word-break:break-all; overflow-wrap:anywhere; max-height:85px; overflow:hidden; width:100%; flex: 1; min-width: 0;">${escapeHtml(item.notes)}</div>
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
        if (state.selectedTag) {
          sessionStorage.setItem('cipher_active_tag', state.selectedTag);
        } else {
          sessionStorage.removeItem('cipher_active_tag');
        }
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
          if (m !== menuDropdown) {
            m.classList.add('hidden');
            const parentCard = m.closest('.item-card');
            if (parentCard) parentCard.classList.remove('dropdown-open');
          }
        });
        const isHidden = menuDropdown.classList.toggle('hidden');
        const parentCard = card;
        if (parentCard) {
          if (!isHidden) {
            parentCard.classList.add('dropdown-open');
          } else {
            parentCard.classList.remove('dropdown-open');
          }
        }
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

    const btnShare = card.querySelector('.btn-share');
    if (btnShare) {
      btnShare.addEventListener('click', (e) => {
        e.stopPropagation();
        if (menuDropdown) menuDropdown.classList.add('hidden');
        generateShareLink(item.id);
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
        (i.mobile && i.mobile.toLowerCase().includes(q)) ||
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
      if (state.sortBy === 'custom') {
        let viewKey = 'all';
        if (state.selectedTag) {
          viewKey = 'label:' + state.selectedTag;
        } else if (state.currentCategory !== 'all') {
          viewKey = 'category:' + state.currentCategory;
        }
        const orderList = state.customOrders[viewKey] || [];
        let idxA = orderList.indexOf(String(a.id));
        let idxB = orderList.indexOf(String(b.id));
        if (idxA === -1) idxA = 999999;
        if (idxB === -1) idxB = 999999;
        
        if (idxA !== idxB) return idxA - idxB;
        // fallback to created date if not found in custom order
        return (b.createdAt || 0) - (a.createdAt || 0);
      }
      if (state.sortBy === 'title') return (a.title || '').localeCompare(b.title || '');
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
            if (typeof switchView === 'function' && DOM.viewVault) switchView(DOM.viewVault);
            if (typeof closeMobileMenu === 'function') closeMobileMenu();
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
        let isStale = false;
        if (item.type === 'login') {
          const pwdTime = item.passwordUpdatedAt || item.updatedAt || item.createdAt || Date.now();
          const daysOld = (Date.now() - pwdTime) / (1000 * 60 * 60 * 24);
          if (daysOld >= 30) isStale = true;
        }
        if (st.score === 'weak' || st.score === 'fair' || isStale) weakCount++;

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
    if (!DOM.viewItemEdit) return;
    if (DOM.modalItemTitle) DOM.modalItemTitle.textContent = 'Add New Vault Item';
    if (DOM.itemId) DOM.itemId.value = '';
    if (DOM.itemForm) DOM.itemForm.reset();
    if (DOM.itemType) DOM.itemType.value = 'login';
    if (DOM.itemTags) DOM.itemTags.value = '';
    if (DOM.customFieldsContainer) DOM.customFieldsContainer.innerHTML = '';
    switchCategoryFields('login');
    if (DOM.itemStrengthBar) DOM.itemStrengthBar.className = 'strength-bar';
    switchView(DOM.viewItemEdit);
  }

  function openEditModal(id) {
    const item = state.vaultItems.find(i => i.id === id);
    if (!item || !DOM.viewItemEdit) return;

    if (DOM.modalItemTitle) DOM.modalItemTitle.textContent = 'Edit Vault Item';
    if (DOM.itemId) DOM.itemId.value = item.id;
    if (DOM.itemType) DOM.itemType.value = item.type || 'login';
    if (DOM.itemTitleInput) DOM.itemTitleInput.value = item.title || '';
    if (DOM.itemUsername) DOM.itemUsername.value = item.username || '';
    if (DOM.itemEmail) DOM.itemEmail.value = item.email || '';
    if (DOM.itemMobile) DOM.itemMobile.value = item.mobile || '';
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

    switchView(DOM.viewItemEdit);
  }

  function closeModal() {
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
    if (fNote) {
      fNote.classList.toggle('hidden', type !== 'note');
      // Force height recalculation once element is rendered for any visible auto-expand textareas
      setTimeout(() => {
        document.querySelectorAll('textarea.auto-expand').forEach(ta => ta.dispatchEvent(new Event('input')));
      }, 10);
    }
  }

  async function handleSaveItem(e) {
    if (e) e.preventDefault();
    const id = DOM.itemId ? DOM.itemId.value : '';
    const type = DOM.itemType ? DOM.itemType.value : 'login';
    const title = DOM.itemTitleInput ? DOM.itemTitleInput.value.trim() : '';

    if (!title) {
      showToast('Please enter a title for this item!', 'error');
      if (DOM.itemTitleInput) DOM.itemTitleInput.focus();
      return;
    }

    const rawTags = DOM.itemTags 
      ? DOM.itemTags.value.split(/[,#\s]+/).map(t => t.trim().toLowerCase()).filter(t => t.length > 0) 
      : [];
    
    // Deduplicate and sanitize tags
    const cleanTags = Array.from(new Set(rawTags)).filter(t => /^[a-z0-9_-]+$/i.test(t));
    
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
      mobile: DOM.itemMobile ? DOM.itemMobile.value.trim() : '',
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
      tags: cleanTags,
      customFields: customFields,
      favorite: id ? (state.vaultItems.find(i => i.id === id)?.favorite || false) : false,
      archived: id ? (state.vaultItems.find(i => i.id === id)?.archived || false) : false,
      deleted: id ? (state.vaultItems.find(i => i.id === id)?.deleted || false) : false,
      orderIndex: id ? (state.vaultItems.find(i => i.id === id)?.orderIndex || 0) : -Date.now(),
      updatedAt: Date.now(),
      createdAt: id ? (state.vaultItems.find(i => i.id === id)?.createdAt || Date.now()) : Date.now(),
      passwordUpdatedAt: id ? (state.vaultItems.find(i => i.id === id)?.passwordUpdatedAt || Date.now()) : Date.now(),
      passwordHistory: id ? (state.vaultItems.find(i => i.id === id)?.passwordHistory || []) : []
    };

    if (id) {
      const idx = state.vaultItems.findIndex(i => i.id === id);
      if (idx !== -1) {
        const oldItem = state.vaultItems[idx];
        if (oldItem.password !== itemData.password) {
          itemData.passwordUpdatedAt = Date.now();
          if (oldItem.password) {
            itemData.passwordHistory.push({
              password: oldItem.password,
              date: Date.now()
            });
          }
          // Keep only the last 5 passwords
          if (itemData.passwordHistory.length > 5) {
            itemData.passwordHistory = itemData.passwordHistory.slice(-5);
          }
        }
        state.vaultItems[idx] = itemData;
      }
    } else {
      state.vaultItems.unshift(itemData);
    }

    await renderVault();
    if (DOM.viewAuth && DOM.viewAuth.classList.contains('active')) render2FAAuthenticatorView();

    switchView(DOM.viewVault);
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
    state.vaultItems[idx].deletedAt = Date.now(); // timestamp for 30-day auto-delete
    await saveVaultToGitHub();
    renderVault();
    showToast('Item moved to Trash', 'info', 'Auto-deleted after 30 days');
  }

  async function restoreFromTrash(id) {
    const idx = state.vaultItems.findIndex(i => i.id === id);
    if (idx === -1) return;
    state.vaultItems[idx].deleted = false;
    delete state.vaultItems[idx].deletedAt;
    await saveVaultToGitHub();
    renderVault();
    showToast('Item restored', 'success');
  }

  async function purgeExpiredTrashItems() {
    const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;
    const now = Date.now();
    const before = state.vaultItems.length;
    state.vaultItems = state.vaultItems.filter(item => {
      if (!item.deleted) return true;
      // Keep if no timestamp (legacy items — give them grace period from now)
      if (!item.deletedAt) {
        item.deletedAt = now; // stamp them now, delete in 30 days
        return true;
      }
      return (now - item.deletedAt) < THIRTY_DAYS_MS;
    });
    const purged = before - state.vaultItems.length;
    if (purged > 0) {
      await saveVaultToGitHub();
      console.info(`Auto-purged ${purged} trash item(s) older than 30 days.`);
    }
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
        background:${isChecked ? 'var(--bg-hover)' : 'rgba(255,255,255,0.03)'};
        border:1px solid ${isChecked ? 'var(--bg-hover)' : 'rgba(255,255,255,0.08)'};
        cursor:pointer; transition:all 0.15s ease;
      `;

      row.innerHTML = `
        <div style="display:flex; align-items:center; gap:0.75rem; overflow:hidden; flex:1;">
          <input type="checkbox" class="label-checkbox" data-tag="${escapeHtml(tag)}" ${isChecked ? 'checked' : ''} style="width:18px; height:18px; accent-color:var(--accent-purple); cursor:pointer; flex-shrink:0;">
          <span style="font-size:0.9rem; font-weight:600; color:${isChecked ? '#fff' : 'var(--text-muted)'}; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">#${escapeHtml(tag)}</span>
        </div>
        <div style="display:flex; align-items:center; gap:0.5rem; flex-shrink:0;">
          <span class="badge-pill label-badge" style="font-size:0.7rem; background:${isChecked ? 'var(--bg-hover)' : 'rgba(255,255,255,0.06)'}; color:${isChecked ? 'var(--accent-purple)' : 'var(--text-dim)'};">${isChecked ? 'Assigned' : 'Unassigned'}</span>
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
          row.style.background = 'var(--bg-hover)';
          row.style.borderColor = 'var(--border-color)';
          if (badge) {
            badge.textContent = 'Assigned';
            badge.style.background = 'var(--bg-hover)';
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
        
        let isStale = false;
        if (item.type === 'login') {
          const pwdTime = item.passwordUpdatedAt || item.updatedAt || item.createdAt || Date.now();
          const daysOld = (Date.now() - pwdTime) / (1000 * 60 * 60 * 24);
          if (daysOld >= 30) isStale = true;
        }

        if (st.score === 'weak' || st.score === 'fair' || isStale) {
          weakItems.push({ ...item, _isStale: isStale, _stScore: st.score });
        }
        
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
              <div style="flex:1; min-width:0; padding-right:1rem; word-break:break-all; overflow-wrap:anywhere;">
                <strong>${escapeHtml(item.title)}</strong> <span style="color:var(--text-muted); font-size:0.85rem;">(${escapeHtml(item.username || 'No user')})</span>
                ${item._isStale ? '<span class="badge-pill ml-2" style="white-space:nowrap; background:#fbbf24; color:#000;"><i class="fa-solid fa-triangle-exclamation"></i> Outdated</span>' : ''}
                ${item._stScore === 'weak' || item._stScore === 'fair' ? '<span class="badge-pill weak ml-2" style="white-space:nowrap;">Weak</span>' : ''}
              </div>
              <button class="btn btn-outline btn-sm btn-edit" data-id="${item.id}">Fix Password</button>
            </div>
          `).join('')}

          ${reusedItems.map(item => `
            <div class="item-body mt-2">
              <div style="flex:1; min-width:0; padding-right:1rem; word-break:break-all; overflow-wrap:anywhere;">
                <strong>${escapeHtml(item.title)}</strong> <span style="color:var(--text-muted); font-size:0.85rem;">(${escapeHtml(item.username || 'No user')})</span>
                <span class="badge-pill fair ml-2" style="white-space:nowrap;">Reused</span>
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

  // --- SECURE SHARING ---
  async function generateShareLink(id) {
    const item = state.vaultItems.find(i => i.id === id);
    if (!item) return;

    const rawKey = window.crypto.getRandomValues(new Uint8Array(32));
    const shareKeyHex = Array.from(rawKey).map(b => b.toString(16).padStart(2, '0')).join('');
    
    // Create a compact payload excluding empty fields and internal metadata
    const sharePayload = {};
    for (const key in item) {
      const val = item[key];
      if (val !== '' && val !== null && val !== undefined &&
          key !== 'id' && key !== 'passwordHistory' && 
          key !== 'favorite' && key !== 'deleted' && key !== 'archived' && 
          key !== 'orderIndex' && key !== 'createdAt' && key !== 'passwordUpdatedAt') {
        if (Array.isArray(val) && val.length === 0) continue;
        sharePayload[key] = val;
      }
    }
    sharePayload.expiresAt = Date.now() + 86400000; // 24 hours

    try {
      const cryptoKey = await window.crypto.subtle.importKey(
        'raw',
        rawKey,
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
      );

      const encryptedData = await CryptoEngine.encryptData(sharePayload, cryptoKey);
      
      const baseUrl = window.location.href.split('?')[0].split('#')[0];
      const compactData = `${encryptedData.iv}.${encryptedData.ciphertext}`;
      const shareUrl = `${baseUrl}?share=${encodeURIComponent(compactData)}#${shareKeyHex}`;

      await navigator.clipboard.writeText(shareUrl);
      showToast('Secure Share Link Copied! (Valid for 24hrs)', 'success');
    } catch (e) {
      console.error(e);
      showToast('Failed to generate share link', 'error');
    }
  };

  // --- EXPORT & IMPORT ---
  async function exportEncryptedBackup() {
    try {
      const vaultData = { items: state.vaultItems, customOrders: state.customOrders };
      const encryptedVault = await CryptoEngine.encryptData(vaultData, state.masterKey);
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
            let decData = await CryptoEngine.decryptData(imported.vault, state.masterKey);
            let decItems = [];
            if (decData && !Array.isArray(decData) && decData.items) {
              decItems = decData.items;
              if (decData.customOrders) {
                if (!state.customOrders) state.customOrders = {};
                for (let key in decData.customOrders) {
                  if (!state.customOrders[key]) state.customOrders[key] = [];
                  state.customOrders[key] = [...new Set([...state.customOrders[key], ...decData.customOrders[key]])];
                }
              }
            } else {
              decItems = decData || [];
            }
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
      // sessionStorage.clear(); // Removed as session keys are now in localStorage
      state.masterKey = null;
      state.vaultItems = [];
      location.reload();
    }
  }

  // --- SAFE EVENT LISTENERS SETUP ---
  function setupEventListeners() {
    const btnItemEditBack = document.getElementById('btn-item-edit-back');
    if (btnItemEditBack) {
      btnItemEditBack.addEventListener('click', () => {
        switchView(DOM.viewVault);
      });
    }
    
    const btnItemEditCancel = document.getElementById('btn-item-edit-cancel');
    if (btnItemEditCancel) {
      btnItemEditCancel.addEventListener('click', () => {
        switchView(DOM.viewVault);
      });
    }

    if (DOM.setupForm) DOM.setupForm.addEventListener('submit', handleSetup);
    if (DOM.unlockForm) DOM.unlockForm.addEventListener('submit', handleUnlock);
    if (DOM.btnLockNow) DOM.btnLockNow.addEventListener('click', lockVault);
    
    document.querySelectorAll('.btn-switch-github').forEach(btn => {
      btn.addEventListener('click', () => {
        if (confirm("Are you sure you want to switch GitHub accounts? This will clear your current local session.")) {
          localStorage.removeItem('cipher_gh_token');
          localStorage.removeItem('cipher_offline_vault');
          localStorage.removeItem('cipher_offline_sha');
          sessionStorage.removeItem('cipher_active_pass');
          window.location.reload();
        }
      });
    });

    // Dashboard Stat Cards Click Handlers
    const cardStatTotal = document.getElementById('card-stat-total');
    if (cardStatTotal) cardStatTotal.addEventListener('click', () => { 
      const navAll = document.querySelector('.nav-item[data-category="all"]');
      if (navAll) navAll.click(); 
    });
    
    const cardStatScore = document.getElementById('card-stat-score');
    if (cardStatScore) cardStatScore.addEventListener('click', () => { if (DOM.navSec) DOM.navSec.click(); });
    
    const cardStatReused = document.getElementById('card-stat-reused');
    if (cardStatReused) cardStatReused.addEventListener('click', () => { if (DOM.navSec) DOM.navSec.click(); });
    
    const cardStatWeak = document.getElementById('card-stat-weak');
    if (cardStatWeak) cardStatWeak.addEventListener('click', () => { if (DOM.navSec) DOM.navSec.click(); });


    document.addEventListener('click', (e) => {
      if (!e.target.closest('.card-dropdown-wrapper')) {
        document.querySelectorAll('.card-dropdown-menu').forEach(m => {
          m.classList.add('hidden');
          const card = m.closest('.item-card');
          if (card) card.classList.remove('dropdown-open');
        });
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

    if (localStorage.getItem('sidebar_collapsed') === 'true') {
      if (DOM.app) DOM.app.classList.add('sidebar-collapsed');
    }
    const desktopSidebarClose = document.getElementById('desktop-sidebar-close');
    if (desktopSidebarClose) {
      desktopSidebarClose.addEventListener('click', () => {
        if (DOM.app) DOM.app.classList.add('sidebar-collapsed');
        localStorage.setItem('sidebar_collapsed', 'true');
      });
    }

    if (DOM.mobileMenuToggle) {
      DOM.mobileMenuToggle.addEventListener('click', () => {
        if (window.innerWidth <= 992) {
          openMobileMenu();
        } else {
          if (DOM.app) DOM.app.classList.remove('sidebar-collapsed');
          localStorage.setItem('sidebar_collapsed', 'false');
        }
      });
    }
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
        sessionStorage.setItem('cipher_active_category', state.currentCategory);
        sessionStorage.removeItem('cipher_active_tag');
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
      if (e.key === 'Escape') {
        const activeModals = document.querySelectorAll('.modal-overlay.active');
        if (activeModals.length > 0) closeModal();
      }
    });
  }

  function switchView(targetView) {
    if (!targetView) return;
    document.querySelectorAll('.view-section').forEach(v => v.classList.remove('active'));
    targetView.classList.add('active');
    sessionStorage.setItem('cipher_active_view', targetView.id);
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

  function copyToClipboard(text, msg, btnElement = null) {
    navigator.clipboard.writeText(text).then(() => {
      showToast(msg || 'Copied to clipboard!', 'success');
      if (btnElement) {
        const icon = btnElement.tagName.toLowerCase() === 'i' ? btnElement : btnElement.querySelector('i');
        if (icon) {
          const origClass = icon.className;
          icon.className = 'fa-solid fa-check';
          icon.style.color = 'var(--accent-purple)';
          setTimeout(() => { 
            icon.className = origClass; 
            icon.style.color = '';
          }, 2000);
        }
      }
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
    if (str === null || str === undefined) return '';
    return String(str).replace(/[&<>"']/g, function (m) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m];
    });
  }

  function csvEscape(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/"/g, '""').replace(/\n/g, ' ');
  }

  function formatDate(timestamp) {
    if (!timestamp || isNaN(timestamp)) return 'Recently';
    const date = new Date(timestamp);
    return date.toLocaleDateString('en-IN', { month: 'short', day: 'numeric', year: 'numeric' });
  }

  // --- CUSTOM SELECT UI (Replaces native selects) ---
  function initCustomSelects() {
    const selects = document.querySelectorAll('select.form-select');
    selects.forEach(select => {
      const wrapper = document.createElement('div');
      wrapper.className = 'custom-select-wrapper';
      
      const trigger = document.createElement('div');
      trigger.className = 'custom-select-trigger';
      
      const textSpan = document.createElement('span');
      textSpan.textContent = select.options[select.selectedIndex]?.text || '';
      
      const icon = document.createElement('i');
      icon.className = 'fa-solid fa-chevron-down';
      
      trigger.appendChild(textSpan);
      trigger.appendChild(icon);
      
      const menu = document.createElement('div');
      menu.className = 'custom-select-menu';
      menu.style.display = 'none';
      
      Array.from(select.options).forEach(opt => {
        const item = document.createElement('div');
        item.className = 'custom-select-option';
        item.textContent = opt.text;
        item.dataset.value = opt.value;
        if (opt.selected) item.classList.add('selected');
        
        item.addEventListener('click', (e) => {
          e.stopPropagation();
          select.value = opt.value;
          select.dispatchEvent(new Event('change'));
          textSpan.textContent = opt.text;
          Array.from(menu.children).forEach(c => c.classList.remove('selected'));
          item.classList.add('selected');
          wrapper.classList.remove('open');
          menu.style.display = 'none';
        });
        menu.appendChild(item);
      });
      
      trigger.addEventListener('click', (e) => {
        e.stopPropagation();
        const isOpen = wrapper.classList.contains('open');
        document.querySelectorAll('.custom-select-wrapper').forEach(w => {
          w.classList.remove('open');
          const m = w.querySelector('.custom-select-menu');
          if(m) m.style.display = 'none';
        });
        
        if (!isOpen) {
          wrapper.classList.add('open');
          menu.style.display = 'flex';
        }
      });
      
      wrapper.appendChild(trigger);
      wrapper.appendChild(menu);
      
      select.parentNode.insertBefore(wrapper, select);
      wrapper.appendChild(select);
      select.style.display = 'none';
      
      // Override value setter to sync custom UI when changed programmatically
      const originalDescriptor = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value');
      Object.defineProperty(select, 'value', {
        get: function() { return originalDescriptor.get.call(this); },
        set: function(val) {
          originalDescriptor.set.call(this, val);
          const option = Array.from(this.options).find(o => o.value === val);
          if (option) {
            textSpan.textContent = option.text;
            Array.from(menu.children).forEach(c => {
              if (c.dataset.value === val) c.classList.add('selected');
              else c.classList.remove('selected');
            });
          }
        }
      });
      
      select.addEventListener('change', () => {
        const option = Array.from(select.options).find(o => o.value === select.value);
        if (option) {
          textSpan.textContent = option.text;
          Array.from(menu.children).forEach(c => {
            if (c.dataset.value === select.value) c.classList.add('selected');
            else c.classList.remove('selected');
          });
        }
      });
    });
    
    document.addEventListener('click', () => {
      document.querySelectorAll('.custom-select-wrapper').forEach(w => {
        w.classList.remove('open');
        const m = w.querySelector('.custom-select-menu');
        if(m) m.style.display = 'none';
      });
    });

    // Listen for form resets to sync custom UI
    document.addEventListener('reset', (e) => {
      setTimeout(() => {
        const selectsInForm = e.target.querySelectorAll('select.form-select');
        selectsInForm.forEach(select => {
          select.dispatchEvent(new Event('change'));
        });
      }, 0);
    });
  }

  // --- INITIALIZATION ---
  async function init() {
    // Handle GitHub OAuth Redirect
    if (window.location.hash.startsWith('#oauth_token=')) {
      // Use URLSearchParams to safely parse hash (handles = inside token values)
      const hashParams = new URLSearchParams(window.location.hash.slice(1));
      const token = hashParams.get('oauth_token');
      if (token && token.length > 20 && /^(gho_|ghp_|github_pat_)/.test(token)) {
        localStorage.setItem('cipher_gh_token', token.trim());
      }
      // Force auth overlay so new users land on setup form, not landing page
      sessionStorage.setItem('cipher_ui_state', 'login');
      // Clean URL hash
      window.history.replaceState(null, null, window.location.pathname + window.location.search);
    }

    const urlParams = new URLSearchParams(window.location.search);
    const sharedData = urlParams.get('share');
    
    if (sharedData) {
      document.getElementById('auth-overlay').classList.remove('active');
      document.getElementById('shared-credential-overlay').classList.add('active');
      const shareKey = window.location.hash.substring(1);
      
      try {
        if (!shareKey) throw new Error('No decryption key found in URL hash');
        
        const rawKey = new Uint8Array(shareKey.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        const cryptoKey = await window.crypto.subtle.importKey(
          'raw',
          rawKey,
          { name: 'AES-GCM' },
          false,
          ['encrypt', 'decrypt']
        );
        
        const decoded = decodeURIComponent(sharedData);
        let encryptedObj;
        if (decoded.includes('{')) {
          encryptedObj = JSON.parse(decoded);
        } else {
          const parts = decoded.split('.');
          encryptedObj = { iv: parts[0], ciphertext: parts[1] };
        }
        
        const item = await CryptoEngine.decryptData(encryptedObj, cryptoKey);
        
        if (Date.now() > item.expiresAt) {
          throw new Error('Link Expired');
        }
        
        document.getElementById('shared-credential-status').innerHTML = `<i class="fa-solid fa-circle-check text-green"></i> Decrypted successfully.`;
        
        let html = `<div style="font-size:1.2rem; font-weight:700; color:#fff; margin-bottom:1rem; text-align:center;">
          ${item.type === 'card' ? '<i class="fa-regular fa-credit-card"></i>' : (item.type === 'bank' ? '<i class="fa-solid fa-building-columns"></i>' : (item.type === 'note' ? '<i class="fa-regular fa-note-sticky"></i>' : '<i class="fa-solid fa-globe"></i>'))} 
          ${escapeHtml(item.title)}
          <div style="font-size:0.65rem; color:var(--text-muted); text-transform:uppercase; margin-top:0.25rem;">${escapeHtml(item.type || 'login')}</div>
        </div>`;
        
        html += await generateItemPreviewHtml(item);

        const contentEl = document.getElementById('shared-credential-content');
        contentEl.innerHTML = html;
        contentEl.style.display = 'block';
        bindPreviewActionListeners(contentEl);
        
      } catch (err) {
        document.getElementById('shared-credential-status').innerHTML = `<span class="text-danger"><i class="fa-solid fa-triangle-exclamation"></i> Invalid or Expired Link</span>`;
      }
      
      document.getElementById('btn-shared-go-home').addEventListener('click', () => {
        window.location.href = window.location.href.split('?')[0].split('#')[0];
      });
      
      return;
    }

    initCustomSelects();
    setupEventListeners();
    
    if (DOM.btnGithubLogin) {
      DOM.btnGithubLogin.addEventListener('click', () => {
        window.location.href = '/auth/login';
      });
    }
    
    await checkMasterStatus();
    updateGeneratorView();
    
    // --- TEST HOOKS (DO NOT COMMIT) ---
    window.testState = state;
    window.testRenderVault = renderVault;
  }

  document.addEventListener('DOMContentLoaded', init);
})();

// --- LANDING PAGE LOGIC ---
document.addEventListener('DOMContentLoaded', () => {
  const landingPage = document.getElementById('landing-page');
  const authOverlay = document.getElementById('auth-overlay');
  
  if (landingPage && authOverlay) {
    const uiState = sessionStorage.getItem('cipher_ui_state');
    const hasData = localStorage.getItem('cipher_offline_vault');
    
    if (uiState === 'login') {
      landingPage.classList.remove('active');
      authOverlay.classList.add('active');
    } else if (uiState === 'landing') {
      landingPage.classList.add('active');
      authOverlay.classList.remove('active');
    } else {
      if (hasData) {
        landingPage.classList.remove('active');
        authOverlay.classList.add('active');
        sessionStorage.setItem('cipher_ui_state', 'login');
      } else {
        landingPage.classList.add('active');
        authOverlay.classList.remove('active');
        sessionStorage.setItem('cipher_ui_state', 'landing');
      }
    }
    
    // Hide FOUC shield after resolving initial view
    setTimeout(() => {
      const shield = document.getElementById('fouc-shield');
      if (shield) {
        shield.style.opacity = '0';
        setTimeout(() => shield.remove(), 200);
      }
    }, 10);

    const goToAuth = () => {
      landingPage.classList.remove('active');
      authOverlay.classList.add('active');
      sessionStorage.setItem('cipher_ui_state', 'login');
    };
    
    const goToHome = () => {
      authOverlay.classList.remove('active');
      landingPage.classList.add('active');
      sessionStorage.setItem('cipher_ui_state', 'landing');
    };

    document.getElementById('btn-landing-login')?.addEventListener('click', goToAuth);
    document.getElementById('btn-landing-cta')?.addEventListener('click', goToAuth);
    document.getElementById('btn-hero-cta')?.addEventListener('click', goToAuth);
    
    document.getElementById('btn-back-home')?.addEventListener('click', goToHome);
    
    document.getElementById('btn-hero-github')?.addEventListener('click', () => {
        window.open('https://github.com/sachinmandawi/ciphervault-password-manager', '_blank');
    });
  }

  // Mobile Drag and Drop Polyfill Init
  if (typeof MobileDragDrop !== 'undefined' && MobileDragDrop.polyfill) {
    MobileDragDrop.polyfill({
      dragImageTranslateOverride: MobileDragDrop.scrollBehaviourDragImageTranslateOverride,
      holdToDrag: 400
    });
    window.addEventListener('touchmove', function() {}, {passive: false});
  }
});
