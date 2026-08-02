from playwright.sync_api import sync_playwright

def check_console_errors():
    errors = []
    def on_page_error(error):
        errors.append(f"Page Error: {error}")
    
    def on_console(msg):
        if msg.type == 'error':
            errors.append(f"Console Error: {msg.text}")
            
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.on("pageerror", on_page_error)
        page.on("console", on_console)
        
        try:
            page.goto("file:///d:/appmd/index.html")
            page.wait_for_timeout(2000) # Give time for JS to run
            
            # Interact with search
            page.type("#search-input", "test")
            page.click("#clear-search")
            
            # Interact with modal
            page.click("#btn-add-item")
            page.wait_for_timeout(500)
            page.click("#cancel-btn")
            
            # Interact with generator
            page.click("#btn-gen-nav")
            page.wait_for_timeout(500)
            page.click("#btn-generate")
            
        except Exception as e:
            errors.append(f"Automation Error: {str(e)}")
            
        browser.close()
        
    return errors

if __name__ == "__main__":
    errs = check_console_errors()
    if errs:
        print("Found errors:")
        for e in errs:
            print(e)
    else:
        print("No console or runtime errors found.")
