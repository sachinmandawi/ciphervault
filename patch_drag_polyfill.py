import re

def add_drag_polyfill():
    with open('index.html', 'r', encoding='utf-8') as f:
        html = f.read()

    polyfill_html = """
  <!-- Mobile Drag and Drop Polyfill -->
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/mobile-drag-drop@2.3.0-rc.2/default.css">
  <script src="https://cdn.jsdelivr.net/npm/mobile-drag-drop@2.3.0-rc.2/index.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/mobile-drag-drop@2.3.0-rc.2/scroll-behaviour.min.js"></script>
  <script>
    window.addEventListener('DOMContentLoaded', () => {
      MobileDragDrop.polyfill({
        dragImageTranslateOverride: MobileDragDrop.scrollBehaviourDragImageTranslateOverride
      });
      
      // Polyfill requirement: avoid touch scrolling while dragging
      window.addEventListener('touchmove', function() {}, {passive: false});
    });
  </script>
  <script src="app.js"></script>"""

    if "MobileDragDrop.polyfill" not in html:
        html = html.replace('<script src="app.js"></script>', polyfill_html)

    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(html)

add_drag_polyfill()
print("Added mobile-drag-drop polyfill to index.html")
