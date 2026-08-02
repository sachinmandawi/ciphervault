import re

with open('app.js', 'r', encoding='utf-8') as f:
    js = f.read()

# 1. Remove state.currentColor
js = re.sub(r"\s*currentColor:\s*'default',", "", js)

# 2. Remove DOM.colorSwatches mapping
js = re.sub(r"\s*colorSwatches:\s*document\.querySelectorAll\('\.color-swatch'\),", "", js)

# 3. Remove color logic in openAddModal
# Finding: state.currentColor = 'default'; ... if (def) def.classList.add('active'); }
js = re.sub(r"\s*state\.currentColor = 'default';\s*if \(DOM\.colorSwatches\) \{[\s\S]*?def\.classList\.add\('active'\);\s*\}", "", js)

# 4. Remove color logic in openEditModal
js = re.sub(r"\s*state\.currentColor = item\.color \|\| 'default';\s*if \(DOM\.colorSwatches\) \{[\s\S]*?activeSwatch\.classList\.add\('active'\);\s*\}", "", js)

# 5. Remove color from handleSaveItem
js = re.sub(r"\s*color:\s*state\.currentColor \|\| 'default',", "", js)

# 6. Remove event listeners
js = re.sub(r"\s*if \(DOM\.colorSwatches\) \{[\s\S]*?DOM\.colorSwatches\.forEach\(swatch => \{[\s\S]*?\}\);\s*\}\s*\}\);", "", js) # This regex might be tricky, let's just do it carefully.
# Wait, let's just replace the exact block.
listener_block = """    if (DOM.colorSwatches) {
      DOM.colorSwatches.forEach(swatch => {
        swatch.addEventListener('click', (e) => {
          DOM.colorSwatches.forEach(s => s.classList.remove('active'));
          e.target.classList.add('active');
          state.currentColor = e.target.dataset.color || 'default';
        });
      });
    }"""
js = js.replace(listener_block, "")

with open('app.js', 'w', encoding='utf-8') as f:
    f.write(js)
    print("Cleaned up app.js")
