import re

# 1. Update index.html
with open('index.html', 'r', encoding='utf8') as f:
    html = f.read()

mobile_html = """
            <div class="form-row mt-2">
              <div class="form-group flex-1">
                <label for="item-mobile">Mobile Number</label>
                <input type="tel" id="item-mobile" placeholder="+1 234 567 8900">
              </div>
            </div>
"""

html = re.sub(
    r"(<div class=\"form-row mt-2\">\s*<div class=\"form-group flex-1\">\s*<label for=\"item-url\">Website URL)",
    mobile_html.strip('\n') + r"\n\n            \1",
    html
)

with open('index.html', 'w', encoding='utf8') as f:
    f.write(html)


# 2. Update app.js
with open('app.js', 'r', encoding='utf8') as f:
    js = f.read()

# DOM
js = re.sub(
    r"    itemEmail: document\.getElementById\('item-email'\),",
    "    itemEmail: document.getElementById('item-email'),\n    itemMobile: document.getElementById('item-mobile'),",
    js
)

# openAddModal reset
js = re.sub(
    r"    if \(DOM\.itemEmail\) DOM\.itemEmail\.value = '';",
    "    if (DOM.itemEmail) DOM.itemEmail.value = '';\n    if (DOM.itemMobile) DOM.itemMobile.value = '';",
    js
)

# editItem populate
js = re.sub(
    r"    if \(DOM\.itemEmail\) DOM\.itemEmail\.value = item\.email \|\| '';",
    "    if (DOM.itemEmail) DOM.itemEmail.value = item.email || '';\n    if (DOM.itemMobile) DOM.itemMobile.value = item.mobile || '';",
    js
)

# handleSaveItem save
js = re.sub(
    r"      email: DOM\.itemEmail \? DOM\.itemEmail\.value\.trim\(\) : '',",
    "      email: DOM.itemEmail ? DOM.itemEmail.value.trim() : '',\n      mobile: DOM.itemMobile ? DOM.itemMobile.value.trim() : '',",
    js
)

# openViewModal display
js = re.sub(
    r"      if \(item\.email\) rowsHtml \+= createDetailRow\('Email', item\.email\);",
    "      if (item.email) rowsHtml += createDetailRow('Email', item.email);\n      if (item.mobile) rowsHtml += createDetailRow('Mobile Number', item.mobile);",
    js
)

# search filter
js = re.sub(
    r"        \(i\.email && i\.email\.toLowerCase\(\)\.includes\(q\)\) \|\|",
    "        (i.email && i.email.toLowerCase().includes(q)) ||\n        (i.mobile && i.mobile.toLowerCase().includes(q)) ||",
    js
)

with open('app.js', 'w', encoding='utf8') as f:
    f.write(js)

print("Patch 6 applied successfully.")
