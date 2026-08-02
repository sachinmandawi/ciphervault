import re

def revert_and_fix_2x2():
    with open('styles.css', 'r', encoding='utf-8') as f:
        css = f.read()

    # Restore 2 columns for .stats-grid on mobile
    if 'grid-template-columns: 1fr !important; /* Stacked for mobile */' in css:
        css = css.replace(
            'grid-template-columns: 1fr !important; /* Stacked for mobile */',
            'grid-template-columns: repeat(2, 1fr) !important; /* Restored to 2x2 grid */'
        )

    # Let's ensure text wraps inside the stat card labels so they don't force width
    
    # We will find .stat-label and make sure it wraps properly
    # Previously I set it to white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    # I should change that to allow wrapping.
    
    if 'white-space: nowrap;' in css.split('.stat-label {')[1]:
        css = css.replace(
            ".stat-label {\n  font-size: 0.8rem;\n  white-space: nowrap;\n  overflow: hidden;\n  text-overflow: ellipsis;",
            ".stat-label {\n  font-size: 0.75rem;\n  white-space: normal;\n  line-height: 1.2;"
        )

    with open('styles.css', 'w', encoding='utf-8') as f:
        f.write(css)

revert_and_fix_2x2()
print("Stats grid reverted to 2x2 and text wrapping allowed for small screens.")
