def patch_boot():
    with open('app.js', 'r', encoding='utf-8') as f:
        js = f.read()
        
    old = """        let items = await CryptoEngine.decryptData(payload.vault, key);
        if (Array.isArray(items)) {
          items.forEach(i => {
            if (typeof i.tags === 'string') {
              i.tags = i.tags.split(/[,#\\s]+/).map(t => t.trim()).filter(Boolean);
            }
            if (!Array.isArray(i.tags)) {
              i.tags = [];
            }
          });
          state.vaultItems = items;"""
          
    new = """        let decrypted = await CryptoEngine.decryptData(payload.vault, key);
        let items = [];
        if (Array.isArray(decrypted)) {
          items = decrypted;
          state.customOrders = {};
        } else if (decrypted && Array.isArray(decrypted.items)) {
          items = decrypted.items;
          state.customOrders = decrypted.customOrders || {};
        }

        items.forEach(i => {
          if (typeof i.tags === 'string') {
            i.tags = i.tags.split(/[,#\\s]+/).map(t => t.trim()).filter(Boolean);
          }
          if (!Array.isArray(i.tags)) {
            i.tags = [];
          }
        });
        state.vaultItems = items;"""
        
    js = js.replace(old, new)
    
    with open('app.js', 'w', encoding='utf-8') as f:
        f.write(js)

patch_boot()
print("Boot logic patched.")
