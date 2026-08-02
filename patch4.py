import re

with open('app.js', 'r', encoding='utf8') as f:
    code = f.read()

# 1. Add DOM.itemBackupCodes
code = re.sub(
    r"    itemUrl: document\.getElementById\('item-url'\),",
    "    itemUrl: document.getElementById('item-url'),\n    itemBackupCodes: document.getElementById('item-backup-codes'),",
    code
)

# 2. Reset itemBackupCodes in openAddModal/editItem
code = re.sub(
    r"    if \(DOM\.itemUrl\) DOM\.itemUrl\.value = '';",
    "    if (DOM.itemUrl) DOM.itemUrl.value = '';\n    if (DOM.itemBackupCodes) DOM.itemBackupCodes.value = '';",
    code
)

# 3. Set itemBackupCodes in editItem
code = re.sub(
    r"    if \(DOM\.itemUrl\) DOM\.itemUrl\.value = item\.url \|\| '';",
    "    if (DOM.itemUrl) DOM.itemUrl.value = item.url || '';\n    if (DOM.itemBackupCodes) DOM.itemBackupCodes.value = item.backupCodes || '';",
    code
)

# 4. Save itemBackupCodes in handleSaveItem
code = re.sub(
    r"      url: DOM\.itemUrl \? DOM\.itemUrl\.value\.trim\(\) : '',",
    "      url: DOM.itemUrl ? DOM.itemUrl.value.trim() : '',\n      backupCodes: DOM.itemBackupCodes ? DOM.itemBackupCodes.value.trim() : '',",
    code
)

# 5. Add to preview modal
preview_code = """      if (item.url) rowsHtml += createDetailRow('Website URL', item.url);
      
      if (item.backupCodes) {
        rowsHtml += `
          <div class="detail-row">
            <span class="detail-label">2FA BACKUP / RECOVERY CODES</span>
            <div class="detail-value-wrapper">
              <span class="detail-value" style="white-space: pre-wrap; font-family: var(--font-mono); font-size: 0.85rem; line-height: 1.4;">${escapeHtml(item.backupCodes)}</span>
              <button type="button" class="btn-icon btn-copy-row-val" data-val="${escapeHtml(item.backupCodes)}" title="Copy Codes">
                <i class="fa-regular fa-copy"></i>
              </button>
            </div>
          </div>
        `;
      }"""

code = re.sub(
    r"      if \(item\.url\) rowsHtml \+= createDetailRow\('Website URL', item\.url\);",
    preview_code,
    code
)

with open('app.js', 'w', encoding='utf8') as f:
    f.write(code)

print("Patch 4 applied.")
