import re

def fix_overflow():
    with open('styles.css', 'r', encoding='utf-8') as f:
        css = f.read()

    # Remove overflow: hidden from .item-card, .stat-card
    if 'overflow: hidden;' in css.split('.item-card, .stat-card {')[1]:
        css = css.replace(
            '.item-card, .stat-card {\n  max-width: 100%;\n  box-sizing: border-box;\n  overflow: hidden;\n  word-wrap: break-word;\n}',
            '.item-card, .stat-card {\n  max-width: 100%;\n  box-sizing: border-box;\n  overflow: visible;\n  word-wrap: break-word;\n}'
        )

    with open('styles.css', 'w', encoding='utf-8') as f:
        f.write(css)

fix_overflow()
print("Fixed overflow: hidden on item cards")
