import re

def fix_mobile_cards():
    with open('styles.css', 'r', encoding='utf-8') as f:
        css = f.read()

    # 1. Stack stats grid on mobile
    # Find @media (max-width: 600px) and replace grid-template-columns: repeat(2, 1fr) with 1fr
    if 'grid-template-columns: repeat(2, 1fr) !important;' in css:
        css = css.replace(
            'grid-template-columns: repeat(2, 1fr) !important;',
            'grid-template-columns: 1fr !important; /* Stacked for mobile */'
        )

    # 2. Add strict overflow hidden and max width rules at the end of the file
    strict_rules = """
/* STRICT MOBILE LAYOUT ENFORCEMENT */
html, body {
  overflow-x: hidden !important;
  max-width: 100vw !important;
  width: 100vw !important;
  margin: 0;
  padding: 0;
}

.app-container {
  overflow-x: hidden !important;
  max-width: 100vw !important;
  width: 100vw !important;
}

.content-scroll {
  overflow-x: hidden !important;
  max-width: 100vw !important;
  width: 100% !important;
  padding-right: 1.25rem !important;
  padding-left: 1.25rem !important;
}

.item-card, .stat-card {
  max-width: 100%;
  box-sizing: border-box;
  overflow: hidden;
  word-wrap: break-word;
}
"""
    if "/* STRICT MOBILE LAYOUT ENFORCEMENT */" not in css:
        css += "\n" + strict_rules

    with open('styles.css', 'w', encoding='utf-8') as f:
        f.write(css)

fix_mobile_cards()
print("Mobile cards layout strict enforcement applied.")
