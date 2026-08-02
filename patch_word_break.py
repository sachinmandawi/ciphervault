import re

def fix_word_breaks():
    with open('app.js', 'r', encoding='utf-8') as f:
        js = f.read()

    # Fix notes display string breaking
    if 'word-break:break-word;' in js:
        js = js.replace(
            'word-break:break-word;',
            'word-break:break-all; overflow-wrap:anywhere;'
        )
    
    with open('app.js', 'w', encoding='utf-8') as f:
        f.write(js)

    with open('styles.css', 'r', encoding='utf-8') as f:
        css = f.read()

    # Fix item-pass-hidden breaking
    if 'word-break: break-all;' not in css.split('.item-pass-hidden {')[1]:
        css = css.replace(
            '.item-pass-hidden {\n\n  letter-spacing: 0.15em;',
            '.item-pass-hidden {\n\n  letter-spacing: 0.15em;\n  word-break: break-all;\n  overflow-wrap: anywhere;\n  display: inline-block;\n  max-width: 100%;'
        )

    with open('styles.css', 'w', encoding='utf-8') as f:
        f.write(css)

fix_word_breaks()
print("Word breaks fixed in app.js and styles.css")
