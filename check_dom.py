import re

with open('app.js', encoding='utf-8') as f:
    js = f.read()

ids_in_js = re.findall(r"getElementById\('([^']+)'\)", js)
classes_in_js = re.findall(r"querySelector\('\.([^']+)'\)", js)
ids_with_hash = re.findall(r"querySelector\('#([^']+)'\)", js)
classes_with_query_all = re.findall(r"querySelectorAll\('\.([^']+)'\)", js)

with open('index.html', encoding='utf-8') as f:
    html = f.read()

html_ids = re.findall(r'id="([^"]+)"', html)
html_classes = re.findall(r'class="([^"]+)"', html)
html_classes_flat = set()
for cls in html_classes:
    for c in cls.split():
        html_classes_flat.add(c)

missing_ids = [i for i in set(ids_in_js + ids_with_hash) if i not in html_ids and "view-vault" not in i]
missing_classes = [c for c in set(classes_in_js + classes_with_query_all) if c.split(' ')[-1].split('.')[-1] not in html_classes_flat]

print("Missing IDs:", missing_ids)
# Note: classes can be tricky due to composite selectors, so we just check if the last class in the selector is missing
missing_c = []
for c in set(classes_in_js + classes_with_query_all):
    last_class = c.split(' ')[-1].split('.')[-1]
    if last_class not in html_classes_flat and ':' not in last_class:
        missing_c.append(c)

print("Missing Classes:", missing_c)
