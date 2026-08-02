from html.parser import HTMLParser
from collections import Counter

class MyHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.tags = []
        self.classes = set()

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        for attr in attrs:
            if attr[0] == 'id':
                self.ids.append(attr[1])
            if attr[0] == 'class':
                self.classes.update(attr[1].split())

    def handle_endtag(self, tag):
        if self.tags and self.tags[-1] == tag:
            self.tags.pop()

def check_html():
    with open('index.html', 'r', encoding='utf-8') as f:
        html = f.read()
    
    parser = MyHTMLParser()
    try:
        parser.feed(html)
    except Exception as e:
        print(f"HTML Parsing Error: {e}")
        return

    # Check for duplicate IDs
    id_counts = Counter(parser.ids)
    duplicates = {k: v for k, v in id_counts.items() if v > 1}
    
    if duplicates:
        print(f"Duplicate IDs found: {duplicates}")
    else:
        print("No duplicate IDs found.")

    if parser.tags:
        print(f"Unclosed tags detected: {parser.tags}")
    else:
        print("All tags properly closed.")

if __name__ == "__main__":
    check_html()
