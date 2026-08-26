const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// DATABASE CONNECTION
const pool = new Pool({
    connectionString: process.env.DATABASE_URL
});

pool.on('error', (err) => {
    console.error('❌ Database error:', err);
});

// Active sessions tracker
let activeSessions = {};

// ========================================
// ADMIN LOGIN ENDPOINT
// ========================================
app.post('/api/admin/login', async (req, res) => {
    try {
        const { password } = req.body;
        
        if (!password) {
            return res.json({ success: false, reason: 'No password provided' });
        }
        
        // Hash the password
        const hash = crypto.createHash('sha256').update(password).digest('hex');
        const ADMIN_HASH = process.env.ADMIN_PASSWORD_HASH;
        
        console.log('🔐 Login attempt');
        console.log('Provided hash:', hash);
        console.log('Expected hash:', ADMIN_HASH);
        
        if (hash === ADMIN_HASH) {
            console.log('✅ Login successful!');
            return res.json({ success: true });
        } else {
            console.log('❌ Wrong password');
            return res.json({ success: false, reason: 'Wrong password' });
        }
    } catch (error) {
        console.error('❌ Login error:', error);
        return res.json({ success: false, reason: 'Server error' });
    }
});

// ========================================
// SAVE KEY ENDPOINT (ADMIN)
// ========================================
app.post('/api/admin/save-key', async (req, res) => {
    try {
        const { key, exp } = req.body;
        
        console.log('📥 Save key request received');
        console.log('Key:', key);
        console.log('Expiry:', exp);
        
        if (!key || !exp) {
            console.log('❌ Missing key or exp');
            return res.json({
                success: false,
                reason: 'Missing key or expiry'
            });
        }

        console.log('💾 Inserting into database...');
        
        const result = await pool.query(
            'INSERT INTO keys (key_string, exp, active) VALUES ($1, $2, true) RETURNING id',
            [key, exp]
        );

        console.log('✅ Key saved successfully! ID:', result.rows[0].id);
        
        return res.json({
            success: true,
            id: result.rows[0].id,
            message: 'Key saved to database'
        });

    } catch (error) {
        console.error('❌ Save key error:', error);
        
        if (error.code === '23505') {
            return res.json({
                success: false,
                reason: 'Key already exists'
            });
        }
        
        return res.status(500).json({
            success: false,
            reason: 'Server error: ' + error.message
        });
    }
});

// ========================================
// VALIDATE KEY ENDPOINT (USER)
// ========================================
app.post('/api/user/validate-key', async (req, res) => {
    try {
        const { key } = req.body;
        
        console.log('🔍 Validate key request:', key);

        if (!key) {
            return res.json({
                valid: false,
                reason: 'No key provided'
            });
        }

        console.log('🔎 Searching database...');
        
        const result = await pool.query(
            'SELECT * FROM keys WHERE key_string = $1 AND active = true',
            [key]
        );

        if (result.rows.length === 0) {
            console.log('❌ Key not found in database');
            return res.json({
                valid: false,
                reason: 'Key not found'
            });
        }

        const dbKey = result.rows[0];
        const now = Date.now();

        console.log('⏰ Checking expiry...');
        console.log('Current time:', now);
        console.log('Key expiry:', dbKey.exp);

        if (now > dbKey.exp) {
            console.log('❌ Key expired');
            return res.json({
                valid: false,
                reason: 'Key expired'
            });
        }

        if (!dbKey.active) {
            console.log('❌ Key disabled');
            return res.json({
                valid: false,
                reason: 'Key disabled'
            });
        }

        // Add session tracking
        const sessionId = 'session_' + Math.random().toString(36).substring(7);
        
        // Remove any old sessions for this same key (prevent duplicates)
        Object.keys(activeSessions).forEach(sid => {
            if (activeSessions[sid].key === key) {
                delete activeSessions[sid];
                console.log('🗑️ Removed old session for key:', key);
            }
        });
        
        // Add new session
        activeSessions[sessionId] = { key, timestamp: Date.now() };
        console.log('✅ New session created:', sessionId);
        console.log('📊 Current active sessions:', Object.keys(activeSessions).length);
        
        // Clean up expired sessions (older than 1 minute = inactive)
        Object.keys(activeSessions).forEach(sid => {
            if (Date.now() - activeSessions[sid].timestamp > 1 * 60 * 1000) {
                delete activeSessions[sid];
                console.log('🗑️ Removed inactive session:', sid);
            }
        });

        console.log('✅ Key is valid!');
        return res.json({
            valid: true,
            reason: 'Key is valid',
            exp: dbKey.exp,
            sessionId: sessionId
        });

    } catch (error) {
        console.error('❌ Validate key error:', error);
        return res.status(500).json({
            valid: false,
            reason: 'Server error'
        });
    }
});

// ========================================
// USER HEARTBEAT ENDPOINT
// ========================================
app.post('/api/user/heartbeat', (req, res) => {
    try {
        const { sessionId } = req.body;
        
        if (sessionId && activeSessions[sessionId]) {
            activeSessions[sessionId].timestamp = Date.now();
        }
        
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false });
    }
});

// ========================================
// USER LOGOUT ENDPOINT
// ========================================
app.post('/api/user/logout', (req, res) => {
    try {
        const { sessionId } = req.body;
        
        console.log('🚪 Logout request received:', sessionId);
        
        if (sessionId && activeSessions[sessionId]) {
            delete activeSessions[sessionId];
            console.log('✅ Session removed:', sessionId);
            console.log('📊 Active sessions now:', Object.keys(activeSessions).length);
            return res.json({ success: true });
        } else {
            console.log('⚠️ Session not found:', sessionId);
            return res.json({ success: false, reason: 'Session not found' });
        }
    } catch (error) {
        console.error('❌ Logout error:', error);
        res.json({ success: false, error: error.message });
    }
});

// ========================================
// GET ACTIVE USERS
// ========================================
app.get('/api/stats/active-users', (req, res) => {
    try {
        const now = Date.now();
        let activeCount = 0;
        const activeSids = [];
        
        // Count sessions with heartbeat in last 1 minute (only active users)
        Object.keys(activeSessions).forEach(sid => {
            if (now - activeSessions[sid].timestamp < 1 * 60 * 1000) {
                activeCount++;
                activeSids.push(sid);
            }
        });

        console.log('📊 Active sessions:', activeCount, activeSids);
        
        return res.json({
            activeUsers: activeCount || 0,
            timestamp: now
        });
    } catch (error) {
        console.error('❌ Get active users error:', error);
        return res.json({ activeUsers: 0 });
    }
});

// ========================================
// HEALTH CHECK
// ========================================
app.get('/health', (req, res) => {
    res.json({ status: 'OK', service: 'Crash Analyzer API' });
});

// ========================================
// START SERVER
// ========================================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`🚀 Crash Analyzer API running on port ${PORT}`);
    console.log(`📊 Database: Connected`);
    console.log(`🔐 Admin system: Ready`);
});

process.on('SIGTERM', () => {
    console.log('Shutting down gracefully...');
    pool.end();
    process.exit(0);
});
