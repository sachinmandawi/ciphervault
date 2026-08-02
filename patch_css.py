import re

with open('styles.css', 'r', encoding='utf-8') as f:
    css = f.read()

# Append CSS for color swatches and card colors at the end of the file
new_css = """

/* --- Color Swatches --- */
.color-swatch {
  width: 28px;
  height: 28px;
  border-radius: 50%;
  cursor: pointer;
  border: 2px solid transparent;
  transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
}

.color-swatch:hover {
  transform: scale(1.1);
}

.color-swatch.active {
  border-color: #fff;
  transform: scale(1.15);
  box-shadow: 0 0 10px rgba(255, 255, 255, 0.3);
}

/* --- Item Card Colors --- */
.item-card[data-color="red"] { border-top: 3px solid #ef4444; }
.item-card[data-color="blue"] { border-top: 3px solid #3b82f6; }
.item-card[data-color="green"] { border-top: 3px solid #10b981; }
.item-card[data-color="yellow"] { border-top: 3px solid #f59e0b; }
.item-card[data-color="purple"] { border-top: 3px solid #8b5cf6; }
.item-card[data-color="default"] { border-top: 3px solid transparent; }
"""

if ".color-swatch" not in css:
    with open('styles.css', 'w', encoding='utf-8') as f:
        f.write(css + new_css)
    print("Added CSS for color swatches.")
else:
    print("CSS for color swatches already exists.")

