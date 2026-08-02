import re

with open('app.js', 'r', encoding='utf8') as f:
    code = f.read()

# 1. Add DOM.itemEmail
code = re.sub(
    r"    itemUsername: document\.getElementById\('item-username'\),",
    "    itemUsername: document.getElementById('item-username'),\n    itemEmail: document.getElementById('item-email'),",
    code
)

# 2. Reset itemEmail in closeModal / openAddModal (not needed since we just clear the whole form usually, wait, closeModal manually clears values)
# Wait, let's see how it's cleared. I'll just clear itemEmail anywhere itemUsername is cleared.
code = re.sub(
    r"    if \(DOM\.itemUsername\) DOM\.itemUsername\.value = '';",
    "    if (DOM.itemUsername) DOM.itemUsername.value = '';\n    if (DOM.itemEmail) DOM.itemEmail.value = '';",
    code
)

# 3. Set itemEmail in openAddModal/editItem
code = re.sub(
    r"    if \(DOM\.itemUsername\) DOM\.itemUsername\.value = item\.username \|\| '';",
    "    if (DOM.itemUsername) DOM.itemUsername.value = item.username || '';\n    if (DOM.itemEmail) DOM.itemEmail.value = item.email || '';",
    code
)

# 4. Save itemEmail in handleSaveItem
code = re.sub(
    r"      username: DOM\.itemUsername \? DOM\.itemUsername\.value\.trim\(\) : '',",
    "      username: DOM.itemUsername ? DOM.itemUsername.value.trim() : '',\n      email: DOM.itemEmail ? DOM.itemEmail.value.trim() : '',",
    code
)

# 5. Search filtering
code = re.sub(
    r"        \(i\.username && i\.username\.toLowerCase\(\)\.includes\(q\)\) \|\|",
    "        (i.username && i.username.toLowerCase().includes(q)) ||\n        (i.email && i.email.toLowerCase().includes(q)) ||",
    code
)

# 6. Card subtitle
code = re.sub(
    r"let subText = item\.username \|\| item\.cardnumber \|\| item\.accountno \|\| item\.bankname \|\| 'Secure Item';",
    "let subText = [item.username, item.email].filter(Boolean).join(' • ') || item.cardnumber || item.accountno || item.bankname || 'Secure Item';",
    code
)

with open('app.js', 'w', encoding='utf8') as f:
    f.write(code)

print("Patch applied.")
