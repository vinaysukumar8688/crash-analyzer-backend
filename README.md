# Crash Analyzer Backend Server

Complete backend server for secure admin authentication with 5-attempt lockout protection.

## Features

✅ SHA-256 password hashing with salt
✅ 5-attempt lockout (24 hours)
✅ Server-side password verification
✅ Login history tracking
✅ CORS enabled for frontend
✅ Express.js REST API

## Files Included

```
crash-analyzer-backend/
├── server.js              - Main Express server
├── package.json           - Node.js dependencies
├── .env.example           - Environment variables template
├── .gitignore             - Hide secrets from GitHub
├── Procfile               - Railway deployment config
├── admin-db.json          - Login attempts database
└── README.md              - This file
```

## Admin Credentials

**Admin Password:** `XNhck*qoOo%^Elq!$B6Q^DpPhiUCkSBs`
**Password Hash:** `f2cac0b4c2388b5457f46f71c7bb22d6d094629d7e1ad57283ee43d8e9bfeec6`

## Setup Instructions

### Step 1: Create GitHub Repository

1. Go to https://github.com/new
2. Name: `crash-analyzer-backend`
3. Description: "Crash Analyzer Backend Server"
4. Choose: Public (so Railway can deploy)
5. Click "Create repository"

### Step 2: Upload Files to GitHub

1. Clone your new repo or upload files directly
2. Add all files from this folder:
   - server.js
   - package.json
   - .env.example
   - .gitignore
   - Procfile
   - admin-db.json
   - README.md
3. Commit and push to main branch

### Step 3: Connect to Railway

1. Go to https://railway.app/
2. Click "New Project"
3. Choose "Deploy from GitHub"
4. Select your `crash-analyzer-backend` repo
5. Click "Deploy"

### Step 4: Set Environment Variables in Railway

1. In Railway project dashboard
2. Go to "Variables"
3. Add these:

```
PORT=3000
ADMIN_PASSWORD_HASH=f2cac0b4c2388b5457f46f71c7bb22d6d094629d7e1ad57283ee43d8e9bfeec6
NODE_ENV=production
```

### Step 5: Deploy

1. Railway auto-deploys from GitHub
2. Wait for deployment to complete
3. You'll get a URL like: `https://crash-analyzer-backend.up.railway.app/`
4. Copy this URL - you'll need it in the HTML file

## API Endpoints

### 1. Health Check
```
GET /health
Response: { status: "OK", message: "Server is running" }
```

### 2. Admin Login
```
POST /api/admin/login
Body: { "password": "XNhck*qoOo%^Elq!$B6Q^DpPhiUCkSBs" }

Success (200):
{
  "success": true,
  "message": "Login successful",
  "token": "admin-session-1234567890"
}

Wrong Password (401):
{
  "success": false,
  "message": "Invalid password",
  "attemptsRemaining": 4,
  "attemptsUsed": 1
}

Locked (423):
{
  "success": false,
  "locked": true,
  "message": "Admin locked for 24 hours",
  "remainingMinutes": 1440
}
```

### 3. Change Password
```
POST /api/admin/change-password
Body: { 
  "currentPassword": "XNhck*qoOo%^Elq!$B6Q^DpPhiUCkSBs",
  "newPassword": "NewPassword123"
}

Response includes: newHash for the new password
```

### 4. Admin Status
```
GET /api/admin/status
Response:
{
  "locked": false,
  "attempts": 0,
  "maxAttempts": 5,
  "remainingMinutes": 0,
  "lockoutDurationHours": 24
}
```

## HTML File Configuration

Update `CRASH_ANALYZER_FINAL_SERVER.html` with your Railway URL:

```javascript
// At top of <script> section:
const SERVER_URL = 'https://your-railway-url.com';
```

Example:
```javascript
const SERVER_URL = 'https://crash-analyzer-backend.up.railway.app';
```

## Testing

### Test Health Check
```
curl https://your-railway-url.com/health
```

### Test Admin Login
```
curl -X POST https://your-railway-url.com/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"password":"XNhck*qoOo%^Elq!$B6Q^DpPhiUCkSBs"}'
```

### Test Wrong Password (Should show attempt counter)
```
curl -X POST https://your-railway-url.com/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"password":"wrongpassword"}'
```

## Lockout Behavior

- **Attempt 1-4:** Shows "attempts remaining" message
- **Attempt 5:** Admin locked for 24 hours
- **After 24 hours:** Automatically unlocked, attempts reset

## Security Features

✅ SHA-256 + Salt hashing (server-side)
✅ Passwords never stored in plain text
✅ 5-attempt automatic lockout
✅ 24-hour lockout duration
✅ CORS enabled for your domain
✅ Login history tracking
✅ Secrets in .env (not in GitHub)

## Environment Variables (.env)

Create a `.env` file in root directory (NOT in GitHub):

```
PORT=3000
ADMIN_PASSWORD_HASH=f2cac0b4c2388b5457f46f71c7bb22d6d094629d7e1ad57283ee43d8e9bfeec6
NODE_ENV=production
```

**IMPORTANT:** Railway will auto-detect .env in your repo if you upload it, but it's better to set variables in Railway dashboard.

## Troubleshooting

### Server not responding
- Check if Railway deployment completed
- Check Railway logs for errors
- Verify environment variables are set

### Password not working
- Make sure you're using correct password
- Check that ADMIN_PASSWORD_HASH matches in .env
- Clear browser cache and try again

### CORS errors
- CORS is enabled in server.js
- Make sure SERVER_URL in HTML matches your Railway URL
- Check browser console for detailed error messages

### Admin locked
- Wait 24 hours for automatic unlock
- Or restart server (resets in-memory counter)
- Database keeps record in admin-db.json

## Changing Admin Password

1. Login to admin panel
2. Click "Change Password"
3. Enter current password
4. Enter new password
5. Server returns new hash
6. Update Railway environment variable with new hash
7. Restart server (automatic on Railway)

## Local Development

To run locally:

```bash
# Install dependencies
npm install

# Create .env file with values from .env.example
cp .env.example .env

# Start server
npm start
# or
node server.js

# Server runs on http://localhost:3000
```

## Production Notes

- All passwords hashed with SHA-256 + Salt
- Lockout data stored in admin-db.json
- No database credentials in code
- HTTPS enforced on Railway
- Logs available in Railway dashboard

## Support

For issues or questions:
1. Check server logs in Railway dashboard
2. Verify all environment variables
3. Test endpoints with curl
4. Check browser console for frontend errors

---

**Backend Version:** 1.0.0
**Node.js Required:** 18.x
**Last Updated:** August 2024
