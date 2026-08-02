import re

with open('styles.css', 'r', encoding='utf-8') as f:
    css = f.read()

if 'min-width: 0' not in css.split('.item-title-block {')[1].split('}')[0]:
    css = css.replace(
        ".item-title-block {\n  flex: 1;",
        ".item-title-block {\n  flex: 1;\n  min-width: 0;"
    )

if 'min-width: 0' not in css.split('.stat-details {')[1].split('}')[0]:
    css = css.replace(
        ".stat-details {\n  display: flex;",
        ".stat-details {\n  display: flex;\n  flex: 1;\n  min-width: 0;"
    )

if 'white-space: nowrap' not in css.split('.stat-label {')[1].split('}')[0]:
    css = css.replace(
        ".stat-label {\n  font-size: 0.8rem;",
        ".stat-label {\n  font-size: 0.8rem;\n  white-space: nowrap;\n  overflow: hidden;\n  text-overflow: ellipsis;"
    )

with open('styles.css', 'w', encoding='utf-8') as f:
    f.write(css)

print("CSS fixed for flexbox intrinsic size overflow.")
