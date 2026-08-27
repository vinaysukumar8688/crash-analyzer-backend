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
        const { key, exp, created_at } = req.body;
        
        console.log('📥 Save key request received');
        console.log('Key:', key);
        console.log('Expiry:', exp);
        console.log('Created at:', created_at);
        
        if (!key || !exp || !created_at) {
            console.log('❌ Missing key, exp, or created_at');
            return res.json({
                success: false,
                reason: 'Missing key, expiry, or created_at'
            });
        }

        console.log('💾 Inserting into database...');
        
        const result = await pool.query(
            'INSERT INTO keys (key_string, exp, active, created_at) VALUES ($1, $2, true, $3) RETURNING id',
            [key, exp, created_at]
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

        // CHECK IF KEY IS ALREADY IN USE ON ANOTHER DEVICE
        const keyInUse = Object.keys(activeSessions).some(sid => {
            return activeSessions[sid].key === key;
        });
        
        if (keyInUse) {
            console.log('❌ Key already in use on another device');
            return res.json({
                valid: false,
                reason: 'Key already in use on another device'
            });
        }

        // ========================================
        // FROZEN TIME FOR UNUSED → ACTIVE ON LOGIN
        // ========================================
        let finalExp = dbKey.exp;
        
        if (!dbKey.login_time) {
            const originalDuration = dbKey.exp - dbKey.created_at;
            finalExp = Date.now() + originalDuration;
            
            await pool.query(
                'UPDATE keys SET exp = $1, login_time = $2 WHERE id = $3',
                [finalExp, Date.now(), dbKey.id]
            );
            
            console.log('✅ Key activated! Timer started from now');
        }

        const sessionId = 'session_' + Math.random().toString(36).substring(7);
        activeSessions[sessionId] = { key, timestamp: Date.now() };
        console.log('✅ New session created:', sessionId);
        console.log('📊 Current active sessions:', Object.keys(activeSessions).length);
        
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
            exp: finalExp,
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
// GET ALL KEYS ENDPOINT (ADMIN)
// ========================================
app.get('/api/admin/get-all-keys', async (req, res) => {
    try {
        console.log('📋 Getting all keys...');
        
        const result = await pool.query(
            'SELECT id, key_string, exp, active, created_at FROM keys ORDER BY created_at DESC'
        );

        console.log('✅ Found', result.rows.length, 'keys');
        
        return res.json({
            success: true,
            keys: result.rows
        });

    } catch (error) {
        console.error('❌ Get all keys error:', error);
        return res.status(500).json({
            success: false,
            reason: 'Server error'
        });
    }
});

// ========================================
// RESET KEY ENDPOINT (ADMIN)
// ========================================
app.post('/api/admin/reset-key', async (req, res) => {
    try {
        const { keyId, keyString, newExpiry } = req.body;
        
        console.log('🔄 Reset key request:', keyId);
        console.log('New expiry:', newExpiry);

        if (!keyId || !newExpiry) {
            return res.json({
                success: false,
                reason: 'Missing keyId or newExpiry'
            });
        }

        // Update key expiry in database
        const result = await pool.query(
            'UPDATE keys SET exp = $1 WHERE id = $2 RETURNING id, key_string, exp',
            [newExpiry, keyId]
        );

        if (result.rows.length === 0) {
            return res.json({
                success: false,
                reason: 'Key not found'
            });
        }

        // Clear session for this key (remove device lock)
        Object.keys(activeSessions).forEach(sid => {
            if (activeSessions[sid].key === keyString) {
                delete activeSessions[sid];
                console.log('🗑️ Cleared session for key:', keyString);
            }
        });

        console.log('✅ Key reset successfully!');
        
        return res.json({
            success: true,
            message: 'Key extended successfully',
            key: result.rows[0]
        });

    } catch (error) {
        console.error('❌ Reset key error:', error);
        return res.status(500).json({
            success: false,
            reason: 'Server error: ' + error.message
        });
    }
});

// ========================================
// DELETE KEY ENDPOINT (ADMIN)
// ========================================
app.post('/api/admin/delete-key', async (req, res) => {
    try {
        const { keyId } = req.body;
        
        console.log('🗑️ Delete key request:', keyId);

        if (!keyId) {
            return res.json({
                success: false,
                reason: 'Missing keyId'
            });
        }

        // Get key string before deleting
        const getResult = await pool.query(
            'SELECT key_string FROM keys WHERE id = $1',
            [keyId]
        );

        if (getResult.rows.length === 0) {
            return res.json({
                success: false,
                reason: 'Key not found'
            });
        }

        const keyString = getResult.rows[0].key_string;

        // Delete from database
        await pool.query(
            'DELETE FROM keys WHERE id = $1',
            [keyId]
        );

        // Clear session for this key
        Object.keys(activeSessions).forEach(sid => {
            if (activeSessions[sid].key === keyString) {
                delete activeSessions[sid];
                console.log('🗑️ Cleared session for deleted key');
            }
        });

        console.log('✅ Key deleted successfully!');
        
        return res.json({
            success: true,
            message: 'Key deleted successfully'
        });

    } catch (error) {
        console.error('❌ Delete key error:', error);
        return res.status(500).json({
            success: false,
            reason: 'Server error: ' + error.message
        });
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
// CHECK IF KEY IS ACTIVE (USER LOGGED IN)
// ========================================
app.get('/api/admin/check-key-active/:keyString', (req, res) => {
    try {
        const { keyString } = req.params;
        const isActive = Object.keys(activeSessions).some(sid => {
            return activeSessions[sid].key === keyString;
        });
        return res.json({ isActive });
    } catch (error) {
        console.error('❌ Check key active error:', error);
        return res.json({ isActive: false });
    }
});
// ========================================
// ANALYZE SEED ENDPOINT (USER)
// ========================================
app.post('/api/user/analyze-seed', async (req, res) => {
    try {
        const { seed } = req.body;
        
        if (!seed || seed.length < 20) {
            return res.json({
                pattern: '⏳ WAIT'
            });
        }

        // 💖 3x-10x: 2+ vowels at positions 5-10 AND 1+ vowel at 18-25
        const vowels = 'AEIOUAEIOUAEIOU';
        const vowelsAt510 = (seed[5] && vowels.includes(seed[5].toUpperCase())) + 
                            (seed[6] && vowels.includes(seed[6].toUpperCase())) +
                            (seed[7] && vowels.includes(seed[7].toUpperCase())) +
                            (seed[8] && vowels.includes(seed[8].toUpperCase())) +
                            (seed[9] && vowels.includes(seed[9].toUpperCase())) +
                            (seed[10] && vowels.includes(seed[10].toUpperCase()));
        const vowelsAt1825 = (seed[18] && vowels.includes(seed[18].toUpperCase())) +
                             (seed[19] && vowels.includes(seed[19].toUpperCase())) +
                             (seed[20] && vowels.includes(seed[20].toUpperCase())) +
                             (seed[21] && vowels.includes(seed[21].toUpperCase())) +
                             (seed[22] && vowels.includes(seed[22].toUpperCase())) +
                             (seed[23] && vowels.includes(seed[23].toUpperCase())) +
                             (seed[24] && vowels.includes(seed[24].toUpperCase())) +
                             (seed[25] && vowels.includes(seed[25].toUpperCase()));
        
        if (vowelsAt510 >= 2 && vowelsAt1825 >= 1) {
            return res.json({ pattern: '💖 3x-10x' });
        }

        // 🔴 CRASH: 2+ S/N at positions 6-10 AND 1+ S/N at 15-20
        const sn = 'SN';
        const snAt610 = (seed[6] && sn.includes(seed[6].toUpperCase())) +
                        (seed[7] && sn.includes(seed[7].toUpperCase())) +
                        (seed[8] && sn.includes(seed[8].toUpperCase())) +
                        (seed[9] && sn.includes(seed[9].toUpperCase())) +
                        (seed[10] && sn.includes(seed[10].toUpperCase()));
        const snAt1520 = (seed[15] && sn.includes(seed[15].toUpperCase())) +
                         (seed[16] && sn.includes(seed[16].toUpperCase())) +
                         (seed[17] && sn.includes(seed[17].toUpperCase())) +
                         (seed[18] && sn.includes(seed[18].toUpperCase())) +
                         (seed[19] && sn.includes(seed[19].toUpperCase())) +
                         (seed[20] && sn.includes(seed[20].toUpperCase()));
        
        if (snAt610 >= 2 && snAt1520 >= 1) {
            return res.json({ pattern: '🔴 CRASH' });
        }

        // 💙 4x: 1+ K/Z/X at positions 6-10 AND 2+ K/Z/X at 12+
        const kzx = 'KZX';
        const kzxAt610 = (seed[6] && kzx.includes(seed[6].toUpperCase())) +
                         (seed[7] && kzx.includes(seed[7].toUpperCase())) +
                         (seed[8] && kzx.includes(seed[8].toUpperCase())) +
                         (seed[9] && kzx.includes(seed[9].toUpperCase())) +
                         (seed[10] && kzx.includes(seed[10].toUpperCase()));
        const kzxAt12plus = seed.substring(12).split('').reduce((count, c) => {
            return count + (kzx.includes(c.toUpperCase()) ? 1 : 0);
        }, 0);
        
        if (kzxAt610 >= 1 && kzxAt12plus >= 2) {
            return res.json({ pattern: '💙 4x' });
        }

        // 💎 3x-100x: 1+ rare letters (y/v/z) at positions 2-5
        const rare = 'YVZ';
        const rareAt25 = (seed[2] && rare.includes(seed[2].toUpperCase())) +
                         (seed[3] && rare.includes(seed[3].toUpperCase())) +
                         (seed[4] && rare.includes(seed[4].toUpperCase())) +
                         (seed[5] && rare.includes(seed[5].toUpperCase()));
        
        if (rareAt25 >= 1) {
            return res.json({ pattern: '💎 3x-100x' });
        }

        // ⏳ WAIT: No pattern matched
        return res.json({ pattern: '⏳ WAIT' });

    } catch (error) {
        console.error('❌ Analyze seed error:', error);
        return res.json({ pattern: '⏳ WAIT' });
    }
});
// ========================================
// ANALYZE SEED ENDPOINT (USER)
// ========================================
app.post('/api/user/analyze-seed', async (req, res) => {
    try {
        const { seed } = req.body;
        
        // Check seed length - must be 40+ chars
        if (!seed || seed.length < 40) {
            return res.json({
                pattern: '❌ ENTER CORRECT SEED'
            });
        }

        // 💖 3x-10x: 2+ vowels at positions 5-10 AND 1+ vowel at 18-25
        const vowels = 'AEIOUAEIOUAEIOU';
        const vowelsAt510 = (seed[5] && vowels.includes(seed[5].toUpperCase())) + 
                            (seed[6] && vowels.includes(seed[6].toUpperCase())) +
                            (seed[7] && vowels.includes(seed[7].toUpperCase())) +
                            (seed[8] && vowels.includes(seed[8].toUpperCase())) +
                            (seed[9] && vowels.includes(seed[9].toUpperCase())) +
                            (seed[10] && vowels.includes(seed[10].toUpperCase()));
        const vowelsAt1825 = (seed[18] && vowels.includes(seed[18].toUpperCase())) +
                             (seed[19] && vowels.includes(seed[19].toUpperCase())) +
                             (seed[20] && vowels.includes(seed[20].toUpperCase())) +
                             (seed[21] && vowels.includes(seed[21].toUpperCase())) +
                             (seed[22] && vowels.includes(seed[22].toUpperCase())) +
                             (seed[23] && vowels.includes(seed[23].toUpperCase())) +
                             (seed[24] && vowels.includes(seed[24].toUpperCase())) +
                             (seed[25] && vowels.includes(seed[25].toUpperCase()));
        
        if (vowelsAt510 >= 2 && vowelsAt1825 >= 1) {
            return res.json({ pattern: '💖 3x-10x' });
        }

        // 🔴 CRASH: 2+ S/N at positions 6-10 AND 1+ S/N at 15-20
        const sn = 'SN';
        const snAt610 = (seed[6] && sn.includes(seed[6].toUpperCase())) +
                        (seed[7] && sn.includes(seed[7].toUpperCase())) +
                        (seed[8] && sn.includes(seed[8].toUpperCase())) +
                        (seed[9] && sn.includes(seed[9].toUpperCase())) +
                        (seed[10] && sn.includes(seed[10].toUpperCase()));
        const snAt1520 = (seed[15] && sn.includes(seed[15].toUpperCase())) +
                         (seed[16] && sn.includes(seed[16].toUpperCase())) +
                         (seed[17] && sn.includes(seed[17].toUpperCase())) +
                         (seed[18] && sn.includes(seed[18].toUpperCase())) +
                         (seed[19] && sn.includes(seed[19].toUpperCase())) +
                         (seed[20] && sn.includes(seed[20].toUpperCase()));
        
        if (snAt610 >= 2 && snAt1520 >= 1) {
            return res.json({ pattern: '🔴 CRASH' });
        }

        // 💙 4x: 1+ K/Z/X at positions 6-10 AND 2+ K/Z/X at 12+
        const kzx = 'KZX';
        const kzxAt610 = (seed[6] && kzx.includes(seed[6].toUpperCase())) +
                         (seed[7] && kzx.includes(seed[7].toUpperCase())) +
                         (seed[8] && kzx.includes(seed[8].toUpperCase())) +
                         (seed[9] && kzx.includes(seed[9].toUpperCase())) +
                         (seed[10] && kzx.includes(seed[10].toUpperCase()));
        const kzxAt12plus = seed.substring(12).split('').reduce((count, c) => {
            return count + (kzx.includes(c.toUpperCase()) ? 1 : 0);
        }, 0);
        
        if (kzxAt610 >= 1 && kzxAt12plus >= 2) {
            return res.json({ pattern: '💙 4x' });
        }

        // 💎 3x-100x: 1+ rare letters (y/v/z) at positions 2-5
        const rare = 'YVZ';
        const rareAt25 = (seed[2] && rare.includes(seed[2].toUpperCase())) +
                         (seed[3] && rare.includes(seed[3].toUpperCase())) +
                         (seed[4] && rare.includes(seed[4].toUpperCase())) +
                         (seed[5] && rare.includes(seed[5].toUpperCase()));
        
        if (rareAt25 >= 1) {
            return res.json({ pattern: '💎 3x-100x' });
        }

        // ⏳ WAIT FOR NEXT ROUND: No pattern matched
        return res.json({ pattern: '⏳ WAIT FOR NEXT ROUND' });

    } catch (error) {
        console.error('❌ Analyze seed error:', error);
        return res.json({ pattern: '⏳ WAIT FOR NEXT ROUND' });
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
