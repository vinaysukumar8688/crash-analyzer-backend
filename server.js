const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Constants
const SALT = 'x7q2m9k1p8n5v3c6x4z9';
const MAX_ATTEMPTS = 5;
const LOCKOUT_DURATION = 24 * 60 * 60 * 1000; // 24 hours
const DB_FILE = path.join(__dirname, 'admin-db.json');

// Admin password hash (from env or hardcoded)
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || 'f2cac0b4c2388b5457f46f71c7bb22d6d094629d7e1ad57283ee43d8e9bfeec6';

// Initialize database
function initDatabase() {
    if (!fs.existsSync(DB_FILE)) {
        const initialData = {
            attempts: 0,
            lockedUntil: 0,
            loginHistory: []
        };
        fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2));
    }
}

// Read database
function readDatabase() {
    try {
        const data = fs.readFileSync(DB_FILE, 'utf8');
        return JSON.parse(data);
    } catch (e) {
        return { attempts: 0, lockedUntil: 0, loginHistory: [] };
    }
}

// Write database
function writeDatabase(data) {
    try {
        fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
    } catch (e) {
        console.error('Error writing database:', e);
    }
}

// Hash function (same as client-side)
async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password + SALT);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

// Node.js compatible hash function
function hashPasswordSync(password) {
    return crypto.createHash('sha256').update(password + SALT).digest('hex');
}

// Check if admin is locked
function isAdminLocked() {
    const db = readDatabase();
    const now = Date.now();
    
    if (db.lockedUntil && now < db.lockedUntil) {
        return true; // Still locked
    }
    
    if (db.lockedUntil && now >= db.lockedUntil) {
        // Lockout expired, reset
        db.attempts = 0;
        db.lockedUntil = 0;
        writeDatabase(db);
        return false;
    }
    
    return false;
}

// Record failed attempt
function recordFailedAttempt() {
    const db = readDatabase();
    db.attempts += 1;
    
    if (db.attempts >= MAX_ATTEMPTS) {
        // Lock for 24 hours
        db.lockedUntil = Date.now() + LOCKOUT_DURATION;
        db.loginHistory.push({
            timestamp: new Date().toISOString(),
            event: 'LOCKED_5_FAILED_ATTEMPTS',
            attempts: db.attempts
        });
        writeDatabase(db);
        return true; // Locked now
    } else {
        db.loginHistory.push({
            timestamp: new Date().toISOString(),
            event: 'FAILED_LOGIN',
            attemptsLeft: MAX_ATTEMPTS - db.attempts
        });
        writeDatabase(db);
        return false; // Not locked yet
    }
}

// Reset attempts on successful login
function resetAttempts() {
    const db = readDatabase();
    db.attempts = 0;
    db.lockedUntil = 0;
    db.loginHistory.push({
        timestamp: new Date().toISOString(),
        event: 'SUCCESSFUL_LOGIN',
        attemptsReset: true
    });
    writeDatabase(db);
}

// API Endpoints

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'OK', message: 'Server is running' });
});

// Admin login endpoint
app.post('/api/admin/login', (req, res) => {
    try {
        const { password } = req.body;

        if (!password) {
            return res.status(400).json({
                success: false,
                message: 'Password required'
            });
        }

        // Check if locked
        if (isAdminLocked()) {
            const db = readDatabase();
            const remainingTime = Math.ceil((db.lockedUntil - Date.now()) / 1000 / 60);
            return res.status(423).json({
                success: false,
                locked: true,
                message: `Admin locked for ${remainingTime} more minutes`,
                remainingMinutes: remainingTime
            });
        }

        // Hash password
        const passwordHash = hashPasswordSync(password);

        // Verify password
        if (passwordHash !== ADMIN_PASSWORD_HASH) {
            // Wrong password
            const locked = recordFailedAttempt();
            const db = readDatabase();
            const remaining = MAX_ATTEMPTS - db.attempts;

            if (locked) {
                return res.status(423).json({
                    success: false,
                    locked: true,
                    message: 'Admin locked for 24 hours after 5 failed attempts',
                    attemptsUsed: MAX_ATTEMPTS
                });
            } else {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid password',
                    attemptsRemaining: remaining,
                    attemptsUsed: db.attempts
                });
            }
        }

        // Correct password
        resetAttempts();
        return res.json({
            success: true,
            message: 'Login successful',
            token: 'admin-session-' + Date.now()
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error',
            error: error.message
        });
    }
});

// Change password endpoint
app.post('/api/admin/change-password', (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'Current and new password required'
            });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({
                success: false,
                message: 'New password must be at least 8 characters'
            });
        }

        // Check if locked
        if (isAdminLocked()) {
            const db = readDatabase();
            const remainingTime = Math.ceil((db.lockedUntil - Date.now()) / 1000 / 60);
            return res.status(423).json({
                success: false,
                locked: true,
                message: `Admin locked for ${remainingTime} more minutes`,
                remainingMinutes: remainingTime
            });
        }

        // Verify current password
        const currentHash = hashPasswordSync(currentPassword);

        if (currentHash !== ADMIN_PASSWORD_HASH) {
            // Wrong current password
            const locked = recordFailedAttempt();
            const db = readDatabase();
            const remaining = MAX_ATTEMPTS - db.attempts;

            if (locked) {
                return res.status(423).json({
                    success: false,
                    locked: true,
                    message: 'Admin locked for 24 hours after 5 failed attempts'
                });
            } else {
                return res.status(401).json({
                    success: false,
                    message: 'Current password is incorrect',
                    attemptsRemaining: remaining
                });
            }
        }

        // Current password correct - reset attempts
        resetAttempts();

        // Hash new password
        const newHash = hashPasswordSync(newPassword);

        // Return new hash for user to update
        return res.json({
            success: true,
            message: 'Current password verified',
            newHash: newHash,
            instruction: 'Update ADMIN_PASSWORD_HASH in server with this value',
            newHashValue: newHash,
            updateEnv: `ADMIN_PASSWORD_HASH=${newHash}`
        });

    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error',
            error: error.message
        });
    }
});

// Get admin status
app.get('/api/admin/status', (req, res) => {
    try {
        const db = readDatabase();
        const locked = isAdminLocked();
        let remainingTime = 0;

        if (locked) {
            remainingTime = Math.ceil((db.lockedUntil - Date.now()) / 1000 / 60);
        }

        return res.json({
            locked: locked,
            attempts: db.attempts,
            maxAttempts: MAX_ATTEMPTS,
            remainingMinutes: remainingTime,
            lockoutDurationHours: 24
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Start server
initDatabase();
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`🚀 Crash Analyzer Backend Server running on port ${PORT}`);
    console.log(`📊 Admin authentication enabled`);
    console.log(`🔐 5-attempt lockout system active`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('Server shutting down...');
    process.exit(0);
});
