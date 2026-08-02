import re

with open('app.js', 'r', encoding='utf8') as f:
    code = f.read()

# 1. Add DOM elements
code = re.sub(
    r"    itemTags: document\.getElementById\('item-tags'\),",
    "    itemTags: document.getElementById('item-tags'),\n    customFieldsContainer: document.getElementById('custom-fields-container'),\n    btnAddCustomField: document.getElementById('btn-add-custom-field'),",
    code
)

# 2. Add custom field row generator and event listeners
custom_field_logic = """
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
"""
code = code.replace("  // --- Global Application State ---", custom_field_logic + "\n  // --- Global Application State ---")

# 3. Clear custom fields on openAddModal (same place as itemTags)
code = re.sub(
    r"    if \(DOM\.itemTags\) DOM\.itemTags\.value = '';",
    "    if (DOM.itemTags) DOM.itemTags.value = '';\n    if (DOM.customFieldsContainer) DOM.customFieldsContainer.innerHTML = '';",
    code
)

# 4. Populate custom fields in editItem
edit_custom_fields_logic = """    if (DOM.itemTags) DOM.itemTags.value = item.tags ? item.tags.map(t => `#${t}`).join(', ') : '';
    
    if (DOM.customFieldsContainer) {
      DOM.customFieldsContainer.innerHTML = '';
      if (item.customFields && Array.isArray(item.customFields)) {
        item.customFields.forEach(cf => {
          DOM.customFieldsContainer.appendChild(createCustomFieldRow(cf.label, cf.value, cf.isSecret));
        });
      }
    }"""
code = re.sub(
    r"    if \(DOM\.itemTags\) DOM\.itemTags\.value = item\.tags \? item\.tags\.map\(t => `#\$\{t\}`\)\.join\(', '\) : '';",
    edit_custom_fields_logic,
    code
)

# 5. Extract custom fields in handleSaveItem
save_custom_fields_logic = """    const rawTags = DOM.itemTags ? DOM.itemTags.value.split(/[,#\\s]+/).map(t => t.trim().toLowerCase()).filter(t => t.length > 0) : [];
    
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
    }"""
code = re.sub(
    r"    const rawTags = DOM\.itemTags \? DOM\.itemTags\.value\.split\(\/\[,\#\\\\s\]\+\/\)\.map\(t => t\.trim\(\)\.toLowerCase\(\)\)\.filter\(t => t\.length > 0\) : \[\];",
    save_custom_fields_logic,
    code
)

code = re.sub(
    r"      tags: Array\.from\(new Set\(rawTags\)\),",
    "      tags: Array.from(new Set(rawTags)),\n      customFields: customFields,",
    code
)

# 6. Render custom fields in openViewModal
preview_logic = """    }

    if (item.customFields && Array.isArray(item.customFields) && item.customFields.length > 0) {
      item.customFields.forEach(cf => {
        rowsHtml += createDetailRow(cf.label || 'Custom Field', cf.value, cf.isSecret);
      });
    }"""
code = re.sub(
    r"    \}[\r\n\s]+if \(item\.tags && item\.tags\.length > 0\)",
    preview_logic + "\n\n    if (item.tags && item.tags.length > 0)",
    code
)

# 7. Add to search filter in renderVault
search_logic = """        (i.url && i.url.toLowerCase().includes(q)) ||
        (i.customFields && i.customFields.some(cf => 
          (cf.label && cf.label.toLowerCase().includes(q)) || 
          (cf.value && cf.value.toLowerCase().includes(q))
        ))"""
code = re.sub(
    r"        \(i\.url && i\.url\.toLowerCase\(\)\.includes\(q\)\)",
    search_logic,
    code
)

with open('app.js', 'w', encoding='utf8') as f:
    f.write(code)

print("Patch 5 applied.")
