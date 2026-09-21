const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET; 

// Database setup
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } 
});

app.use(express.json());

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
        req.user = user;
        next();
    });
};

// Health Check
app.get('/health', (req, res) => {
    res.status(200).json({ ok: true, service: 'CampusOS', time: new Date().toISOString() });
});

// Signup
app.post('/api/signup', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password || password.length < 6) {
        return res.status(400).json({ error: 'Valid name, email, and password (min 6 chars) are required.' });
    }

    try {
        const existingUser = await pool.query('SELECT id FROM students WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) {
            return res.status(409).json({ error: 'Email is already registered.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            const userResult = await client.query(
                'INSERT INTO students (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email',
                [name, email, hashedPassword]
            );
            const user = userResult.rows[0];

            await client.query(
                "INSERT INTO student_data (student_id, data) VALUES ($1, '{}'::jsonb)",
                [user.id]
            );
            await client.query('COMMIT');

            const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
            res.status(201).json({ token, user });
        } catch (e) {
            await client.query('ROLLBACK');
            throw e;
        } finally {
            client.release();
        }
    } catch (err) {
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

    try {
        const result = await pool.query('SELECT * FROM students WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials.' });

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(401).json({ error: 'Invalid credentials.' });

        const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
        res.status(200).json({ token, user: { id: user.id, name: user.name, email: user.email } });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// Get Current User Info
app.get('/api/me', authenticateToken, (req, res) => {
    res.status(200).json({ user: req.user });
});

// Get Student Data
app.get('/api/data', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT data FROM student_data WHERE student_id = $1', [req.user.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Data not found.' });
        res.status(200).json({ data: result.rows[0].data });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// Update Student Data
app.put('/api/data', authenticateToken, async (req, res) => {
    const { data } = req.body;
    if (!data) return res.status(400).json({ error: 'Data payload is required.' });

    try {
        await pool.query(
            'UPDATE student_data SET data = $1, updated_at = CURRENT_TIMESTAMP WHERE student_id = $2',
            [data, req.user.id]
        );
        res.status(200).json({ message: 'Data updated successfully.' });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// Serve frontend from the public folder
const frontendPath = path.join(__dirname, 'public');
app.use(express.static(frontendPath));

app.use((req, res, next) => {
    if (req.path.startsWith('/api/') || req.path.startsWith('/health')) {
        return res.status(404).json({ error: 'API route not found' });
    }
    res.sendFile(path.join(frontendPath, 'index.html'));
});

// Global Error Handler
app.use((err, req, res, next) => {
    res.status(500).json({ error: 'Something went wrong!' });
});

app.listen(PORT, () => {
    console.log(`CampusOS server running on port ${PORT}`);
});
