# Complete Setup Guide - Crash Analyzer with Server Authentication

---

## 📋 COMPLETE DEPLOYMENT CHECKLIST

### PHASE 1: GitHub Setup (5 minutes)

- [ ] Create GitHub account: https://github.com/signup
- [ ] Create new repo: https://github.com/new
  - Name: `crash-analyzer-backend`
  - Type: Public
- [ ] Add files to repo:
  - server.js
  - package.json
  - .env.example
  - .gitignore
  - Procfile
  - admin-db.json
  - README.md

### PHASE 2: Railway Deployment (10 minutes)

- [ ] Go to: https://railway.app/
- [ ] Login with GitHub
- [ ] Click "New Project"
- [ ] Select "Deploy from GitHub"
- [ ] Choose `crash-analyzer-backend` repo
- [ ] Wait for deployment (2-5 minutes)
- [ ] Copy your Railway URL (e.g., https://crash-analyzer-backend.up.railway.app)

### PHASE 3: Configure Environment Variables (2 minutes)

In Railway dashboard:
- [ ] Go to "Variables" tab
- [ ] Add PORT: `3000`
- [ ] Add ADMIN_PASSWORD_HASH: `f2cac0b4c2388b5457f46f71c7bb22d6d094629d7e1ad57283ee43d8e9bfeec6`
- [ ] Add NODE_ENV: `production`
- [ ] Save/redeploy

### PHASE 4: Update HTML File (10 minutes)

In CRASH_ANALYZER_FINAL.html:

**Find this at the very top of `<script>` section (around line 194):**
```javascript
<script>
    let expiryInterval = null;
```

**Add this line IMMEDIATELY after `<script>`:**
```javascript
<script>
    // Server URL for admin authentication
    const SERVER_URL = 'https://your-railway-url.com';
    // Example: const SERVER_URL = 'https://crash-analyzer-backend.up.railway.app';
    
    let expiryInterval = null;
```

**Replace the old `loginAdmin()` function with this new one:**

Find the old function (around line 387):
```javascript
async function loginAdmin() {
    // Check if locked
    if (isAdminLocked()) {
        // ... old code ...
    }
    
    const code = document.getElementById('adminCode').value.trim();
    const err = document.getElementById('adminErr');
    
    err.style.display = 'none';
    
    try {
        const codeHash = await hashCodeStrong(code);
        
        if (codeHash === ADMIN_CODE_HASH) {
            // ... old code ...
        }
    }
}
```

**Replace with:**
```javascript
async function loginAdmin() {
    const code = document.getElementById('adminCode').value.trim();
    const err = document.getElementById('adminErr');
    
    if (!code) {
        err.style.display = 'block';
        err.innerHTML = '❌ Please enter password!';
        return;
    }
    
    err.style.display = 'none';
    
    try {
        // Send password to server for verification
        const response = await fetch(`${SERVER_URL}/api/admin/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password: code })
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            // Correct password - open admin panel
            document.getElementById('adminAuth').style.display = 'none';
            document.getElementById('admin').style.display = 'block';
            refreshKeysList();
            checkAdminLockOnLoad();
        } else if (response.status === 423 && data.locked) {
            // Admin locked
            err.style.display = 'block';
            err.innerHTML = `🔒 ADMIN LOCKED!<br>Too many failed attempts.<br>Locked for ${data.remainingMinutes || 1440} more minutes.`;
            document.getElementById('adminCode').style.display = 'none';
            document.querySelector('button[onclick="loginAdmin()"]').style.display = 'none';
        } else {
            // Wrong password
            const remaining = data.attemptsRemaining || 0;
            err.style.display = 'block';
            
            if (remaining > 0) {
                err.innerHTML = `❌ Invalid password!<br><br>⚠️ ${remaining} attempts remaining.<br>After 5 wrong attempts, admin will be locked for 24 hours.`;
            } else {
                err.innerHTML = `❌ WRONG PASSWORD!<br><br>🔒 ADMIN PANEL IS NOW LOCKED!<br>Locked for 24 hours.`;
            }
        }
    } catch (error) {
        console.error('Login error:', error);
        err.style.display = 'block';
        err.innerHTML = `❌ Connection error: ${error.message}<br><br>Make sure SERVER_URL is correct:<br>${SERVER_URL}`;
    }
}
```

**Also update the `changeAdminPassword()` function to use server (around line 320):**

Find:
```javascript
async function changeAdminPassword() {
    // Check if locked
    if (isAdminLocked()) {
        // ... old code ...
    }
    
    const currentPassword = prompt('🔐 Enter CURRENT admin password to change it:');
```

Replace with:
```javascript
async function changeAdminPassword() {
    const currentPassword = prompt('🔐 Enter CURRENT admin password:');
    if (!currentPassword) return;
    
    try {
        // Verify current password with server
        const response = await fetch(`${SERVER_URL}/api/admin/change-password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                currentPassword: currentPassword,
                newPassword: 'temp' // We'll ask for real password after verification
            })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            if (response.status === 423 && data.locked) {
                alert(`🔒 ADMIN LOCKED!\n\nToo many failed attempts.\nLocked for ${data.remainingMinutes || 1440} more minutes.`);
            } else {
                const remaining = data.attemptsRemaining || 0;
                alert(`❌ WRONG CURRENT PASSWORD!\n\n${remaining} attempts remaining.\nAfter 5 wrong attempts, admin will be locked for 24 hours.`);
            }
            return;
        }
        
        // Current password verified - ask for new password
        const newPassword = prompt('🔑 Enter NEW admin password (minimum 8 characters):');
        if (!newPassword || newPassword.length < 8) {
            alert('❌ Password must be at least 8 characters!');
            return;
        }
        
        const verifyPassword = prompt('🔑 Verify NEW admin password:');
        if (newPassword !== verifyPassword) {
            alert('❌ Passwords do not match!');
            return;
        }
        
        // Now get the hash for the new password
        const newHash = await hashCodeStrong(newPassword);
        
        alert(`✅ PASSWORD CHANGE INSTRUCTIONS:\n\nNew password created!\n\nHash: ${newHash}\n\n1. Go to Railway dashboard\n2. Go to "Variables"\n3. Update ADMIN_PASSWORD_HASH to:\n${newHash}\n4. Save & redeploy\n\nNew password will work after server restarts!`);
        
    } catch (error) {
        console.error('Password change error:', error);
        alert(`❌ Connection error: ${error.message}\n\nMake sure SERVER_URL is set correctly!`);
    }
}
```

### PHASE 5: Test Server Connection (5 minutes)

**Test 1: Health Check**
Open browser developer console and run:
```javascript
fetch('https://your-railway-url.com/health').then(r => r.json()).then(d => console.log(d))
```

Should show: `{status: "OK", message: "Server is running"}`

**Test 2: Admin Login**
```javascript
fetch('https://your-railway-url.com/api/admin/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({password: 'XNhck*qoOo%^Elq!$B6Q^DpPhiUCkSBs'})
}).then(r => r.json()).then(d => console.log(d))
```

Should show: `{success: true, message: "Login successful", token: "..."}`

**Test 3: Wrong Password**
```javascript
fetch('https://your-railway-url.com/api/admin/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({password: 'wrongpassword'})
}).then(r => r.json()).then(d => console.log(d))
```

Should show: `{success: false, message: "Invalid password", attemptsRemaining: 4}`

### PHASE 6: Final Testing (5 minutes)

- [ ] Save updated HTML file
- [ ] Open in browser
- [ ] Click "ADMIN"
- [ ] Enter correct password: `XNhck*qoOo%^Elq!$B6Q^DpPhiUCkSBs`
- [ ] Should open admin panel ✅
- [ ] Click "Change Password"
- [ ] Try wrong current password 5 times
- [ ] Admin should lock ✅
- [ ] Verify message shows lock time
- [ ] Test USER mode still works ✅
- [ ] Test seed analysis still works ✅

---

## 🔧 TROUBLESHOOTING

### "Connection error" when trying to login

**Problem:** Cannot connect to server

**Solution:**
1. Check SERVER_URL is correct
2. Copy exact URL from Railway dashboard
3. Check if Railway deployment completed
4. Test health endpoint: `https://your-url/health`

### Wrong password works / allows login

**Problem:** Server not verifying correctly

**Solution:**
1. Check ADMIN_PASSWORD_HASH is correct
2. Verify hash matches original password
3. Check .env file in Railway dashboard
4. Redeploy server

### Lockout not working

**Problem:** Can try more than 5 times

**Solution:**
1. Check admin-db.json exists on server
2. Verify server logs for errors
3. Clear browser localStorage
4. Hard refresh (Ctrl+Shift+R)

### Admin panel shows but buttons don't work

**Problem:** Server buttons not responding

**Solution:**
1. Check browser console for errors
2. Verify server still running
3. Check network tab in developer tools
4. Restart Railway deployment

---

## 📊 WHAT WORKS NOW

✅ **User Mode:** Completely unchanged
✅ **Seed Analysis:** Completely unchanged
✅ **Timing Features:** Completely unchanged
✅ **Design/UI:** Completely unchanged
✅ **Admin Password:** Server-verified (uncrackable!)
✅ **5-Attempt Lockout:** Server-tracked
✅ **Password Change:** Server-verified
✅ **File Integrity Check:** Still works locally

---

## 🚀 AFTER DEPLOYMENT

1. **Save this setup guide** - for future reference
2. **Bookmark Railway URL** - for admin access
3. **Keep admin password safe** - only you know it
4. **Monitor Railway logs** - for any issues
5. **Test monthly** - ensure everything still works

---

## 📞 QUICK REFERENCE

**Railway Dashboard:** https://railway.app/
**Your Server:** https://your-railway-url.com
**Admin Password:** XNhck*qoOo%^Elq!$B6Q^DpPhiUCkSBs
**Password Hash:** f2cac0b4c2388b5457f46f71c7bb22d6d094629d7e1ad57283ee43d8e9bfeec6

---

**Setup Complete!** Your Crash Analyzer is now SECURE with server-side authentication! 🔒
