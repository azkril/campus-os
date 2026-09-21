const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// This will automatically grab the Database URL you paste into Render's dashboard!
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_key_for_logins';
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

app.use(express.json());

// Authentication Security
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Access denied.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token.' });
        req.user = user;
        next();
    });
};

// --- API ROUTES ---
app.post('/api/signup', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields required.' });

    try {
        const existing = await pool.query('SELECT id FROM students WHERE email = $1', [email]);
        if (existing.rows.length > 0) return res.status(409).json({ error: 'Email already in use.' });

        const hashed = await bcrypt.hash(password, 10);
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            const userRes = await client.query(
                'INSERT INTO students (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email',
                [name, email, hashed]
            );
            const user = userRes.rows[0];
            await client.query("INSERT INTO student_data (student_id, data) VALUES ($1, '{}'::jsonb)", [user.id]);
            await client.query('COMMIT');

            const token = jwt.sign({ id: user.id, name: user.name }, JWT_SECRET);
            res.status(201).json({ token, user });
        } catch (e) {
            await client.query('ROLLBACK');
            throw e;
        } finally {
            client.release();
        }
    } catch (err) {
        res.status(500).json({ error: 'Server error.' });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM students WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials.' });

        const user = result.rows[0];
        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) return res.status(401).json({ error: 'Invalid credentials.' });

        const token = jwt.sign({ id: user.id, name: user.name }, JWT_SECRET);
        res.status(200).json({ token, user: { id: user.id, name: user.name, email: user.email } });
    } catch (err) {
        res.status(500).json({ error: 'Server error.' });
    }
});

app.get('/api/data', auhenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT data FROM student_data WHERE student_id = $1', [req.user.id]);
        res.status(200).json({ data: result.rows[0].data });
    } catch (err) {
        res.status(500).json({ error: 'Server error.' });
    }
});

app.put('/api/data', authenticateToken, async (req, res) => {
    try {
        await pool.query('UPDATE student_data SET data = $1, updated_at = CURRENT_TIMESTAMP WHERE student_id = $2', [req.body.data, req.user.id]);
        res.status(200).json({ message: 'Saved' });
    } catch (err) {
        res.status(500).json({ error: 'Server error.' });
    }
});

// Serve Frontend
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));
app.use((req, res) => res.sendFile(path.join(publicPath, 'index.html')));

app.listen(PORT, () => console.log(`Server active on port ${PORT}`));
