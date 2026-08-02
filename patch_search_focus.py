import re

def fix_search_focus():
    with open('styles.css', 'r', encoding='utf-8') as f:
        css = f.read()

    # Make the inner input fully transparent and borderless even on focus
    if '.InputContainer .input {' in css:
        if '.InputContainer .input:focus' not in css:
            css = css.replace(
                '.InputContainer .input {',
                '.InputContainer .input, .InputContainer .input:focus, .InputContainer .input:active {\n  background: transparent !important;\n  border: none !important;\n  box-shadow: none !important;\n  outline: none !important;\n}\n\n.InputContainer .input {'
            )

    with open('styles.css', 'w', encoding='utf-8') as f:
        f.write(css)

fix_search_focus()
print("Fixed double background/border on search input focus.")
