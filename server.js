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
        const hash = crypto.createHash('sha256').update(password).digest('hex');
        const ADMIN_HASH = process.env.ADMIN_PASSWORD_HASH;
        console.log('🔐 Login attempt');
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
        if (!key || !exp || !created_at) {
            return res.json({ success: false, reason: 'Missing key, expiry, or created_at' });
        }
        const result = await pool.query(
            'INSERT INTO keys (key_string, exp, active, created_at) VALUES ($1, $2, true, $3) RETURNING id',
            [key, exp, created_at]
        );
        console.log('✅ Key saved successfully! ID:', result.rows[0].id);
        return res.json({ success: true, id: result.rows[0].id, message: 'Key saved to database' });
    } catch (error) {
        console.error('❌ Save key error:', error);
        if (error.code === '23505') {
            return res.json({ success: false, reason: 'Key already exists' });
        }
        return res.status(500).json({ success: false, reason: 'Server error: ' + error.message });
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
            return res.json({ valid: false, reason: 'No key provided' });
        }
        const result = await pool.query(
            'SELECT * FROM keys WHERE key_string = $1 AND active = true',
            [key]
        );
        if (result.rows.length === 0) {
            console.log('❌ Key not found in database');
            return res.json({ valid: false, reason: 'Key not found' });
        }
        const dbKey = result.rows[0];
        const now = Date.now();
        if (now > dbKey.exp) {
            console.log('❌ Key expired');
            return res.json({ valid: false, reason: 'Key expired' });
        }
        const keyInUse = Object.keys(activeSessions).some(sid => {
            return activeSessions[sid].key === key;
        });
        if (keyInUse) {
            console.log('❌ Key already in use on another device');
            return res.json({ valid: false, reason: 'Key already in use on another device' });
        }
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
        Object.keys(activeSessions).forEach(sid => {
            if (Date.now() - activeSessions[sid].timestamp > 1 * 60 * 1000) {
                delete activeSessions[sid];
            }
        });
        return res.json({ valid: true, reason: 'Key is valid', exp: finalExp, sessionId: sessionId });
    } catch (error) {
        console.error('❌ Validate key error:', error);
        return res.status(500).json({ valid: false, reason: 'Server error' });
    }
});

// ========================================
// GET ALL KEYS ENDPOINT (ADMIN)
// ========================================
app.get('/api/admin/get-all-keys', async (req, res) => {
    try {
        console.log('📋 Getting all keys...');
        const result = await pool.query(
            'SELECT id, key_string, exp, active, created_at, login_time, created_by_reseller FROM keys ORDER BY created_at DESC'
        );
        return res.json({ success: true, keys: result.rows });
    } catch (error) {
        console.error('❌ Get all keys error:', error);
        return res.status(500).json({ success: false, reason: 'Server error' });
    }
});

// ========================================
// RESET KEY ENDPOINT (ADMIN)
// ========================================
app.post('/api/admin/reset-key', async (req, res) => {
    try {
        const { keyId, keyString, newExpiry } = req.body;
        if (!keyId || !newExpiry) {
            return res.json({ success: false, reason: 'Missing keyId or newExpiry' });
        }
        const result = await pool.query(
            'UPDATE keys SET exp = $1 WHERE id = $2 RETURNING id, key_string, exp',
            [newExpiry, keyId]
        );
        if (result.rows.length === 0) {
            return res.json({ success: false, reason: 'Key not found' });
        }
        Object.keys(activeSessions).forEach(sid => {
            if (activeSessions[sid].key === keyString) {
                delete activeSessions[sid];
            }
        });
        return res.json({ success: true, message: 'Key extended successfully', key: result.rows[0] });
    } catch (error) {
        console.error('❌ Reset key error:', error);
        return res.status(500).json({ success: false, reason: 'Server error: ' + error.message });
    }
});

// ========================================
// DELETE KEY ENDPOINT (ADMIN)
// ========================================
app.post('/api/admin/delete-key', async (req, res) => {
    try {
        const { keyId } = req.body;
        if (!keyId) {
            return res.json({ success: false, reason: 'Missing keyId' });
        }
        const getResult = await pool.query(
            'SELECT key_string FROM keys WHERE id = $1',
            [keyId]
        );
        if (getResult.rows.length === 0) {
            return res.json({ success: false, reason: 'Key not found' });
        }
        const keyString = getResult.rows[0].key_string;
        await pool.query('DELETE FROM keys WHERE id = $1', [keyId]);
        Object.keys(activeSessions).forEach(sid => {
            if (activeSessions[sid].key === keyString) {
                delete activeSessions[sid];
            }
        });
        return res.json({ success: true, message: 'Key deleted successfully' });
    } catch (error) {
        console.error('❌ Delete key error:', error);
        return res.status(500).json({ success: false, reason: 'Server error: ' + error.message });
    }
});

// ========================================
// GET ACTIVE USERS
// ========================================
app.get('/api/stats/active-users', (req, res) => {
    try {
        const now = Date.now();
        let activeCount = 0;
        Object.keys(activeSessions).forEach(sid => {
            if (now - activeSessions[sid].timestamp < 1 * 60 * 1000) {
                activeCount++;
            }
        });
        return res.json({ activeUsers: activeCount || 0, timestamp: now });
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
        if (sessionId && activeSessions[sessionId]) {
            delete activeSessions[sessionId];
            return res.json({ success: true });
        } else {
            return res.json({ success: false, reason: 'Session not found' });
        }
    } catch (error) {
        console.error('❌ Logout error:', error);
        res.json({ success: false, error: error.message });
    }
});

// ========================================
// CHECK IF KEY IS ACTIVE
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
// CHECK GRAPH ENDPOINT
// ========================================
app.post('/api/user/check-graph', async (req, res) => {
    try {
        const { l1, l2, l3 } = req.body;
        if (!l1 || !l2 || !l3) {
            return res.json({ result: '❌ ENTER ALL VALUES' });
        }
        const l1Val = parseInt(l1);
        const l2Val = parseInt(l2);
        const l3Val = parseInt(l3);
        if (l1Val >= 3 && l2Val >= 3 && l3Val >= 3) {
            return res.json({ result: '🔴 WORST GRAPH' });
        } else if (l1Val >= 3 && l2Val >= 3) {
            return res.json({ result: '🔴 WORST GRAPH' });
        } else if (l3Val >= 3 && l1Val < 3 && l2Val < 3) {
            return res.json({ result: '🟢 GOOD GRAPH' });
        } else if (l3Val >= 3 && l2Val >= 3) {
            return res.json({ result: '🔴 WORST GRAPH' });
        } else if (l2Val >= 3 && l3Val >= 3 && l1Val <= 3) {
            return res.json({ result: '🟡 PLAY 2 ROUNDS ONLY' });
        } else if (l1Val >= 3 && l2Val >= 2 && l3Val >= 2) {
            return res.json({ result: '🟡 PLAY 2 ROUNDS ONLY' });
        } else if (l1Val < 3 && l2Val < 3) {
            return res.json({ result: '💎 SUPER GRAPH' });
        } else if (l3Val >= 3 && l2Val < 3 && l1Val >= 3) {
            return res.json({ result: '🟢 GOOD GRAPH' });
        } else {
            return res.json({ result: '⚪ NEUTRAL GRAPH' });
        }
    } catch (error) {
        console.error('❌ Check graph error:', error);
        return res.json({ result: '❌ SERVER ERROR' });
    }
});

// ========================================
// GET OPTIMAL TIMES
// ========================================
app.get('/api/user/get-optimal-times', (req, res) => {
    try {
        const OPTIMAL_WINDOWS = [
            { start: 2, end: 4 },
            { start: 12, end: 13 },
            { start: 17, end: 18 },
            { start: 24, end: 25 },
            { start: 38, end: 39 },
            { start: 41, end: 42 },
            { start: 47, end: 48 },
            { start: 54, end: 55 },
            { start: 58, end: 59 }
        ];
        return res.json({ windows: OPTIMAL_WINDOWS });
    } catch (error) {
        console.error('❌ Get optimal times error:', error);
        return res.json({ windows: [] });
    }
});

// ============================================
// SEED ANALYSIS: CHECK 1 + CHECK 2 CRASH DETECTION
// ============================================

function countAtPositions(str, chars, startPos, endPos) {
  let count = 0;
  for (let i = startPos - 1; i < endPos && i < str.length; i++) {
    if (chars.includes(str[i].toUpperCase())) {
      count++;
    }
  }
  return count;
}

function countCharacters(str, chars) {
  let count = 0;
  for (let char of str) {
    if (chars.includes(char.toUpperCase())) {
      count++;
    }
  }
  return count;
}

// CHECK 1: Position-Based Analysis
function performCheck1(seed) {
  const crashPos610 = countAtPositions(seed, 'SN', 6, 10);
  const crashPos1520 = countAtPositions(seed, 'SN', 15, 20);
  if (crashPos610 >= 2 && crashPos1520 >= 1) {
    return '🔴 CRASH';
  }

  const vowelsPos510 = countAtPositions(seed, 'AEIOU', 5, 10);
const vowelsPos1825 = countAtPositions(seed, 'AEIOU', 18, 25);
const pos14Char = seed[13]; // Position 14 (0-indexed = 13)
const isPos14Letter = /[A-Za-z]/.test(pos14Char); // Check if it's a letter
if (vowelsPos510 >= 2 && vowelsPos1825 >= 1 && isPos14Letter) {
    return '💖 3x to 10x above';
}

  const kzxPos610 = countAtPositions(seed, 'KZX', 6, 10);
const kzxPos12Plus = countAtPositions(seed, 'KZX', 12, seed.length);

// NEW: Position pattern check for 2x to 4x
let pos4xMatches = 0;
if (/[A-Z]/.test(seed[10])) pos4xMatches++; // Pos 11: UPPERCASE
if (/[A-Z]/.test(seed[19])) pos4xMatches++; // Pos 20: UPPERCASE
if (/[a-z]/.test(seed[22])) pos4xMatches++; // Pos 23: lowercase
if (/[a-z]/.test(seed[24])) pos4xMatches++; // Pos 25: lowercase
if (/[A-Z]/.test(seed[27])) pos4xMatches++; // Pos 28: UPPERCASE
if (/[a-z]/.test(seed[36])) pos4xMatches++; // Pos 37: lowercase

// All 3 conditions must be TRUE
if (kzxPos610 >= 1 && kzxPos12Plus >= 2 && pos4xMatches >= 3) {
    return '💙 2x to 4x above';
}

  const rarePos25 = countAtPositions(seed, 'YVZ', 2, 5);
  if (rarePos25 >= 1) {
    return '💎 3x to 100x above';
  }

  return '⏳ WAIT';
}

// CHECK 2: Crash Detection Only (Count S/N >= 3)
function isCrash(seed) {
  const totalSN = countCharacters(seed, 'SN');
  return totalSN >= 3;
}

function analyzeSeed(seed) {
  if (!seed || seed.length < 40) {
    return { pattern: '❌ ENTER CORRECT SEED' };
  }

  // Step 1: Run CHECK 1
  const check1 = performCheck1(seed);

  // Step 2: Run CHECK 2 (crash detection only)
  const crashDetected = isCrash(seed);

  // Step 3: Apply Logic
  let finalResult = check1;
  
  // If CHECK 2 detects CRASH → Override and show CRASH (Safety First!)
  if (crashDetected && check1 !== '🔴 CRASH') {
    finalResult = '🔴 CRASH';
  }

  return {
    pattern: finalResult
  };
}

// ========================================
// ANALYZE SEED ENDPOINT
// ========================================
app.post('/api/user/analyze-seed', async (req, res) => {
    try {
        const { seed } = req.body;
        if (!seed || seed.length < 40) {
            return res.json({ pattern: '❌ ENTER CORRECT SEED' });
        }
        const analysis = analyzeSeed(seed);
        return res.json({
            pattern: analysis.pattern
        });
    } catch (error) {
        console.error('❌ Analyze seed error:', error);
        return res.json({ pattern: '⏳ WAIT' });
    }
});
 // ========================================
// RESELLER ENDPOINTS
// ========================================

// POST /api/admin/create-reseller - Admin creates reseller code
app.post('/api/admin/create-reseller', async (req, res) => {
    try {
        const { code, balance } = req.body;
        if (!code || balance === undefined) {
            return res.json({ success: false, reason: 'Missing code or balance' });
        }
        const result = await pool.query(
            'INSERT INTO resellers (code, balance, active) VALUES ($1, $2, true) RETURNING *',
            [code, balance]
        );
        console.log('✅ Reseller created:', code);
        return res.json({ success: true, reseller: result.rows[0] });
    } catch (error) {
        console.error('❌ Create reseller error:', error);
        if (error.code === '23505') {
            return res.json({ success: false, reason: 'Reseller code already exists' });
        }
        return res.json({ success: false, reason: error.message });
    }
});

// GET /api/admin/get-all-resellers - Admin gets all resellers
app.get('/api/admin/get-all-resellers', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, code, balance, created_at, active FROM resellers ORDER BY created_at DESC'
        );
        return res.json({ success: true, resellers: result.rows });
    } catch (error) {
        console.error('❌ Get resellers error:', error);
        return res.json({ success: false, reason: error.message });
    }
});

// POST /api/admin/add-reseller-balance - Admin adds balance to reseller
app.post('/api/admin/add-reseller-balance', async (req, res) => {
    try {
        const { code, amount } = req.body;
        if (!code || !amount) {
            return res.json({ success: false, reason: 'Missing code or amount' });
        }
        const result = await pool.query(
            'UPDATE resellers SET balance = balance + $1 WHERE code = $2 RETURNING *',
            [amount, code]
        );
        if (result.rows.length === 0) {
            return res.json({ success: false, reason: 'Reseller not found' });
        }
        console.log('✅ Balance added to:', code, 'New balance:', result.rows[0].balance);
        return res.json({ success: true, reseller: result.rows[0] });
    } catch (error) {
        console.error('❌ Add balance error:', error);
        return res.json({ success: false, reason: error.message });
    }
});

// POST /api/admin/remove-reseller - Admin removes/deletes reseller
app.post('/api/admin/remove-reseller', async (req, res) => {
    try {
        const { code } = req.body;
        if (!code) {
            return res.json({ success: false, reason: 'Missing code' });
        }
        const result = await pool.query('DELETE FROM resellers WHERE code = $1', [code]);
        if (result.rowCount === 0) {
            return res.json({ success: false, reason: 'Reseller not found' });
        }
        console.log('✅ Reseller deleted:', code);
        return res.json({ success: true });
    } catch (error) {
        console.error('❌ Remove reseller error:', error);
        return res.json({ success: false, reason: error.message });
    }
});

// POST /api/reseller/login - Reseller login with code
app.post('/api/reseller/login', async (req, res) => {
    try {
        const { code } = req.body;
        if (!code) {
            return res.json({ valid: false, reason: 'No code provided' });
        }
        const result = await pool.query(
            'SELECT * FROM resellers WHERE code = $1 AND active = true',
            [code]
        );
        if (result.rows.length === 0) {
            console.log('❌ Invalid reseller code:', code);
            return res.json({ valid: false, reason: 'Invalid reseller code' });
        }
        const reseller = result.rows[0];
        const sessionId = 'reseller_' + Math.random().toString(36).substring(7);
        activeSessions[sessionId] = { code, timestamp: Date.now() };
        console.log('✅ Reseller logged in:', code, 'Session:', sessionId);
        return res.json({ valid: true, sessionId, balance: reseller.balance });
    } catch (error) {
        console.error('❌ Reseller login error:', error);
        return res.json({ valid: false, reason: 'Server error' });
    }
});

// POST /api/reseller/save-key - Reseller creates key (deduct balance)
app.post('/api/reseller/save-key', async (req, res) => {
    try {
        const { code, key, exp, durationCost } = req.body;
        if (!code || !key || !exp || !durationCost) {
            return res.json({ success: false, reason: 'Missing required fields' });
        }
        
        // Get reseller
        const resellerResult = await pool.query(
            'SELECT * FROM resellers WHERE code = $1 AND active = true',
            [code]
        );
        if (resellerResult.rows.length === 0) {
            return res.json({ success: false, reason: 'Invalid reseller code' });
        }
        
        const reseller = resellerResult.rows[0];
        if (reseller.balance < durationCost) {
            return res.json({ success: false, reason: 'Insufficient balance. Need: ' + durationCost + ', Have: ' + reseller.balance });
        }
        
        // Create key
        await pool.query(
            'INSERT INTO keys (key_string, exp, active, created_at, created_by_reseller) VALUES ($1, $2, true, $3, $4)',
            [key, exp, Date.now(), code]
        );
        
        // Deduct balance
        const updateResult = await pool.query(
            'UPDATE resellers SET balance = balance - $1 WHERE code = $2 RETURNING balance',
            [durationCost, code]
        );
        
        const newBalance = updateResult.rows[0].balance;
        console.log('✅ Key created by reseller:', code, 'New balance:', newBalance);
        return res.json({ success: true, newBalance: newBalance });
    } catch (error) {
        console.error('❌ Save key error:', error);
        return res.json({ success: false, reason: error.message });
    }
});

// GET /api/reseller/get-balance/:code - Get reseller balance
app.get('/api/reseller/get-balance/:code', async (req, res) => {
    try {
        const { code } = req.params;
        const result = await pool.query(
            'SELECT balance FROM resellers WHERE code = $1 AND active = true',
            [code]
        );
        if (result.rows.length === 0) {
            return res.json({ valid: false, reason: 'Invalid reseller code' });
        }
        return res.json({ valid: true, balance: result.rows[0].balance });
    } catch (error) {
        console.error('❌ Get balance error:', error);
        return res.json({ valid: false });
    }
});
// GET /api/reseller/get-keys/:code - Get ONLY this reseller's keys
app.get('/api/reseller/get-keys/:code', async (req, res) => {
    try {
        const { code } = req.params;
        console.log('🔑 Getting reseller keys for:', code);  // ADD THIS LINE
        const result = await pool.query(
            'SELECT id, key_string, exp, active, created_at, created_by_reseller FROM keys WHERE created_by_reseller IS NOT NULL AND created_by_reseller = $1 ORDER BY created_at DESC',
            [code]
        );
        return res.json({ success: true, keys: result.rows });
    } catch (error) {
        console.error('❌ Get reseller keys error:', error);
        return res.json({ success: false, keys: [] });
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
