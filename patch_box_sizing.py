import re

with open('styles.css', 'r', encoding='utf-8') as f:
    css = f.read()

# Check if global box-sizing exists
if '* {' not in css or 'box-sizing: border-box' not in css.split('* {')[1].split('}')[0]:
    global_reset = """
*, *::before, *::after {
  box-sizing: border-box;
}

"""
    # Insert it right after :root {} block, or at the top
    # Actually just put it after the header comment
    css = re.sub(r'(/\* =+ \*/\s*)', r'\1' + global_reset, css, count=1)
    
    with open('styles.css', 'w', encoding='utf-8') as f:
        f.write(css)
    print("Added global box-sizing reset to fix horizontal overflow.")
else:
    print("Global box-sizing already exists.")
