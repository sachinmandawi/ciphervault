import re

def simplify_search_bar():
    with open('styles.css', 'r', encoding='utf-8') as f:
        css = f.read()

    # Make the input inside InputContainer completely transparent and borderless
    if '.InputContainer .input {' in css:
        css = re.sub(
            r'\.InputContainer \.input \{.*?(?=\})\}',
            '.InputContainer .input {\n  width: 100%;\n  height: 100%;\n  border: none !important;\n  outline: none !important;\n  background: transparent !important;\n  font-size: 0.9em;\n  color: var(--text-color) !important;\n  caret-color: rgb(255, 81, 0);\n}',
            css,
            flags=re.DOTALL
        )
        
    # Remove the inner border divider
    if '.border {' in css:
        css = re.sub(
            r'\.border \{.*?(?=\})\}',
            '.border {\n  display: none !important;\n}',
            css,
            flags=re.DOTALL
        )

    with open('styles.css', 'w', encoding='utf-8') as f:
        f.write(css)

simplify_search_bar()
print("Search bar simplified: removed inner border and enforced borderless input.")
