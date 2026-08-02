const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  
  // Navigate to local server
  await page.goto('http://127.0.0.1:8000');
  
  // Wait for auth modal to appear
  await page.waitForSelector('#auth-modal', { state: 'visible' });
  
  // Fill in login details
  // The default test user might not exist, but we can register one if needed.
  // Wait, the vault is loaded from GitHub. I need the actual password.
  // Actually, I can just register a new account on a clean localStorage for testing,
  // but this is testing the offline cache or the real GitHub vault.
  // I don't know the user's master password to login!
  
  // Let me just check if there are any syntax errors in the console.
  page.on('console', msg => console.log('PAGE LOG:', msg.text()));
  page.on('pageerror', error => console.log('PAGE ERROR:', error.message));

  await page.waitForTimeout(2000);
  await browser.close();
})();
