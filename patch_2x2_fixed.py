import re

with open('styles.css', 'r', encoding='utf-8') as f:
    css = f.read()

css = re.sub(r'grid-template-columns:\s*1fr\s*!important;\s*/\* Stack them on small mobile.*?\*/', 'grid-template-columns: repeat(2, 1fr) !important;', css)

with open('styles.css', 'w', encoding='utf-8') as f:
    f.write(css)

print("Fixed the stats-grid media query to be 2x2 properly.")
