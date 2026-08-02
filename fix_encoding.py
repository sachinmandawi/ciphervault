import re

with open('styles.css', 'rb') as f:
    raw = f.read()

# If powershell appended UTF-16, it has \x00 bytes.
# Let's decode it safely. We can just replace \x00 with nothing.
cleaned = raw.replace(b'\x00', b'')

text = cleaned.decode('utf-8', errors='ignore')

# Remove the previously appended media query
text = re.sub(r'@media\s*\(max-width:\s*900px\)\s*\{\s*\.hide-mobile\s*\{\s*display:\s*none\s*!important;\s*\}\s*\}', '', text)

# Add it back cleanly at the end
text = text.strip() + "\n\n@media (max-width: 900px) {\n  .hide-mobile { display: none !important; }\n}\n"

with open('styles.css', 'w', encoding='utf-8') as f:
    f.write(text)

print("CSS encoding fixed.")
