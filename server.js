// ========================================
// CRASH ANALYZER SECURE SERVER
// Deploy this to Railway
// ========================================

const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// ========================================
// DATABASE CONNECTION
// ========================================

const pool = new Pool({
    connectionString: process.env.DATABASE_URL
});

pool.on('error', (err) => {
    console.error('Database error:', err);
});

// ========================================
// API 1: VALIDATE USER KEY
// ========================================

app.post('/api/user/validate-key', async (req, res) => {
    try {
        const { key, pin, device } = req.body;

        if (!key || !pin || !device) {
            return res.json({
                valid: false,
                reason: 'Missing key, pin, or device'
            });
        }

        const result = await pool.query(
            'SELECT * FROM keys WHERE key_string = $1 AND active = true',
            [key]
        );

        if (result.rows.length === 0) {
            return res.json({
                valid: false,
                reason: 'Key not found or disabled'
            });
        }

        const dbKey = result.rows[0];
        const now = Date.now();

        if (dbKey.pin !== pin) {
            return res.json({
                valid: false,
                reason: 'Wrong PIN'
            });
        }

        if (dbKey.device !== device) {
            return res.json({
                valid: false,
                reason: 'Wrong device ID'
            });
        }

        if (now > dbKey.exp) {
            return res.json({
                valid: false,
                reason: 'Key expired'
            });
        }

        if (!dbKey.active) {
            return res.json({
                valid: false,
                reason: 'Key disabled'
            });
        }

        return res.json({
            valid: true,
            reason: 'Key is valid',
            expiresAt: dbKey.exp
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
// API 2: SAVE KEY (ADMIN)
// ========================================

app.post('/api/admin/save-key', async (req, res) => {
    try {
        const { key, pin, device, exp, adminToken } = req.body;

        const SECRET = process.env.ADMIN_SECRET_TOKEN || 'default-secret';
        if (adminToken !== SECRET) {
            return res.status(401).json({
                success: false,
                reason: 'Unauthorized'
            });
        }

        if (!key || !pin || !device || !exp) {
            return res.json({
                success: false,
                reason: 'Missing required fields'
            });
        }

        const result = await pool.query(
            'INSERT INTO keys (key_string, pin, device, exp, active) VALUES ($1, $2, $3, $4, true) RETURNING id',
            [key, pin, device, exp]
        );

        return res.json({
            success: true,
            reason: 'Key saved to database',
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
// API 3: DELETE KEY (ADMIN)
// ========================================

app.post('/api/admin/delete-key', async (req, res) => {
    try {
        const { key, adminToken } = req.body;

        const SECRET = process.env.ADMIN_SECRET_TOKEN || 'default-secret';
        if (adminToken !== SECRET) {
            return res.status(401).json({
                success: false,
                reason: 'Unauthorized'
            });
        }

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
            success: true,
            reason: 'Key deleted'
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
// API 4: DISABLE KEY (ADMIN)
// ========================================

app.post('/api/admin/disable-key', async (req, res) => {
    try {
        const { key, adminToken } = req.body;

        const SECRET = process.env.ADMIN_SECRET_TOKEN || 'default-secret';
        if (adminToken !== SECRET) {
            return res.status(401).json({
                success: false,
                reason: 'Unauthorized'
            });
        }

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
            success: true,
            reason: 'Key disabled'
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
// API 5: GET ALL KEYS (ADMIN)
// ========================================

app.post('/api/admin/get-keys', async (req, res) => {
    try {
        const { adminToken } = req.body;

        const SECRET = process.env.ADMIN_SECRET_TOKEN || 'default-secret';
        if (adminToken !== SECRET) {
            return res.status(401).json({
                success: false,
                reason: 'Unauthorized'
            });
        }

        const result = await pool.query(
            'SELECT id, key_string, device, exp, active, created_at FROM keys ORDER BY created_at DESC'
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
    res.json({ status: 'OK', service: 'Crash Analyzer API' });
});

// ========================================
// START SERVER
// ========================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Crash Analyzer API running on port ${PORT}`);
});

process.on('SIGTERM', () => {
    pool.end();
    process.exit(0);
});
