const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// DATABASE
const pool = new Pool({
    connectionString: process.env.DATABASE_URL
});

pool.on('error', (err) => {
    console.error('Database error:', err);
});

// ========================================
// ADMIN LOGIN
// ========================================
app.post('/api/admin/login', async (req, res) => {
    try {
        const { password } = req.body;
        
        if (!password) {
            return res.json({ success: false, reason: 'No password' });
        }
        
        const hash = crypto.createHash('sha256').update(password).digest('hex');
        const ADMIN_HASH = process.env.ADMIN_PASSWORD_HASH;
        
        if (hash === ADMIN_HASH) {
            return res.json({ success: true });
        } else {
            return res.json({ success: false, reason: 'Wrong password' });
        }
    } catch (error) {
        console.error('Login error:', error);
        return res.json({ success: false, reason: 'Server error' });
    }
});

// ========================================
// VALIDATE KEY (SIMPLE - KEY ONLY!)
// ========================================
app.post('/api/user/validate-key', async (req, res) => {
    try {
        const { key } = req.body;

        if (!key) {
            return res.json({
                valid: false,
                reason: 'No key provided'
            });
        }

        const result = await pool.query(
            'SELECT * FROM keys WHERE key_string = $1 AND active = true',
            [key]
        );

        if (result.rows.length === 0) {
            return res.json({
                valid: false,
                reason: 'Key not found'
            });
        }

        const dbKey = result.rows[0];
        const now = Date.now();

        if (now > dbKey.exp) {
            return res.json({
                valid: false,
                reason: 'Key expired'
            });
        }

        return res.json({
            valid: true,
            reason: 'Key is valid'
        });

    } catch (error) {
        console.error('Validate key error:', error);
        return res.status(500).json({
            valid: false,
            reason: 'Server error'
        });
    }
});

// ========================================
// SAVE KEY (ADMIN)
// ========================================
app.post('/api/admin/save-key', async (req, res) => {
    try {
        const { key, exp } = req.body;

        if (!key || !exp) {
            return res.json({
                success: false,
                reason: 'Missing key or expiry'
            });
        }

        const result = await pool.query(
            'INSERT INTO keys (key_string, exp, active) VALUES ($1, $2, true) RETURNING id',
            [key, exp]
        );

        return res.json({
            success: true,
            id: result.rows[0].id
        });

    } catch (error) {
        console.error('Save key error:', error);
        
        if (error.code === '23505') {
            return res.json({
                success: false,
                reason: 'Key already exists'
            });
        }

        return res.status(500).json({
            success: false,
            reason: 'Server error'
        });
    }
});

// ========================================
// DELETE KEY (ADMIN)
// ========================================
app.post('/api/admin/delete-key', async (req, res) => {
    try {
        const { key } = req.body;

        const result = await pool.query(
            'DELETE FROM keys WHERE key_string = $1',
            [key]
        );

        if (result.rowCount === 0) {
            return res.json({
                success: false,
                reason: 'Key not found'
            });
        }

        return res.json({
            success: true
        });

    } catch (error) {
        console.error('Delete key error:', error);
        return res.status(500).json({
            success: false,
            reason: 'Server error'
        });
    }
});

// ========================================
// DISABLE KEY (ADMIN)
// ========================================
app.post('/api/admin/disable-key', async (req, res) => {
    try {
        const { key } = req.body;

        const result = await pool.query(
            'UPDATE keys SET active = false WHERE key_string = $1',
            [key]
        );

        if (result.rowCount === 0) {
            return res.json({
                success: false,
                reason: 'Key not found'
            });
        }

        return res.json({
            success: true
        });

    } catch (error) {
        console.error('Disable key error:', error);
        return res.status(500).json({
            success: false,
            reason: 'Server error'
        });
    }
});

// ========================================
// GET ALL KEYS (ADMIN)
// ========================================
app.post('/api/admin/get-keys', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, key_string, exp, active, created_at FROM keys ORDER BY created_at DESC'
        );

        return res.json({
            success: true,
            keys: result.rows
        });

    } catch (error) {
        console.error('Get keys error:', error);
        return res.status(500).json({
            success: false,
            reason: 'Server error'
        });
    }
});

// ========================================
// HEALTH CHECK
// ========================================
app.get('/health', (req, res) => {
    res.json({ status: 'OK' });
});

// ========================================
// START SERVER
// ========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Crash Analyzer API running on port ${PORT}`);
    console.log(`📊 Database: Connected`);
});

process.on('SIGTERM', () => {
    pool.end();
    process.exit(0);
});
