const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: false
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Constants
const SALT = 'x7q2m9k1p8n5v3c6x4z9';
const DB_FILE = path.join(__dirname, 'admin-db.json');

const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || 'f2cac0b4c2388b5457f46f71c7bb22d6d094629d7e1ad57283ee43d8e9bfeec6';

function initDatabase() {
    if (!fs.existsSync(DB_FILE)) {
        const initialData = {
            loginHistory: []
        };
        fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2));
    }
}

function readDatabase() {
    try {
        const data = fs.readFileSync(DB_FILE, 'utf8');
        return JSON.parse(data);
    } catch (e) {
        return { loginHistory: [] };
    }
}

function writeDatabase(data) {
    try {
        fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
    } catch (e) {
        console.error('Error writing database:', e);
    }
}

function hashPasswordSync(password) {
    return crypto.createHash('sha256').update(password + SALT).digest('hex');
}

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'Server is running',
        timestamp: new Date().toISOString()
    });
});

// Diagnostic endpoint
app.get('/api/diagnostic', (req, res) => {
    try {
        const db = readDatabase();
        res.json({
            status: 'OK',
            server: 'Running',
            database: 'Connected',
            lockoutSystem: 'DISABLED',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({
            status: 'ERROR',
            message: error.message
        });
    }
});

// Admin login endpoint - NO LOCKOUT SYSTEM
app.post('/api/admin/login', (req, res) => {
    try {
        const { password } = req.body;

        if (!password) {
            return res.status(400).json({
                success: false,
                message: 'Password required'
            });
        }

        // Hash password
        const passwordHash = hashPasswordSync(password);

        // Verify password
        if (passwordHash !== ADMIN_PASSWORD_HASH) {
            // Wrong password - no lockout, just message
            const db = readDatabase();
            db.loginHistory.push({
                timestamp: new Date().toISOString(),
                event: 'FAILED_LOGIN',
                message: 'Invalid password attempt'
            });
            writeDatabase(db);
            
            return res.status(401).json({
                success: false,
                message: 'Invalid password'
            });
        }

        // Correct password
        const db = readDatabase();
        db.loginHistory.push({
            timestamp: new Date().toISOString(),
            event: 'SUCCESSFUL_LOGIN',
            message: 'Admin logged in successfully'
        });
        writeDatabase(db);
        
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

// Change password endpoint - NO LOCKOUT SYSTEM
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

        const currentHash = hashPasswordSync(currentPassword);

        if (currentHash !== ADMIN_PASSWORD_HASH) {
            // Wrong password - no lockout
            const db = readDatabase();
            db.loginHistory.push({
                timestamp: new Date().toISOString(),
                event: 'FAILED_PASSWORD_CHANGE_ATTEMPT',
                message: 'Invalid current password'
            });
            writeDatabase(db);
            
            return res.status(401).json({
                success: false,
                message: 'Current password is incorrect'
            });
        }

        // Current password correct
        const db = readDatabase();
        db.loginHistory.push({
            timestamp: new Date().toISOString(),
            event: 'PASSWORD_CHANGE_VERIFIED',
            message: 'Current password verified for change'
        });
        writeDatabase(db);

        const newHash = hashPasswordSync(newPassword);

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

        return res.json({
            locked: false,
            lockoutSystem: 'DISABLED',
            message: 'No lockout system - unlimited login attempts allowed',
            timestamp: new Date().toISOString()
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

const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Crash Analyzer Backend Server running on port ${PORT}`);
    console.log(`📊 Admin authentication enabled`);
    console.log(`✅ Lockout system: DISABLED`);
    console.log(`✅ Server ready to accept requests`);
});

server.on('error', (err) => {
    console.error('Server error:', err);
    process.exit(1);
});

process.on('SIGTERM', () => {
    console.log('Server shutting down...');
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});  
