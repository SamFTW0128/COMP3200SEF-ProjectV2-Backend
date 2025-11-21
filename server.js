// server.js - CottonWar backend with CORS enabled

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const db = new sqlite3.Database('./foodtrack.db');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_ME_IN_PRODUCTION';

// 🔓 CORS: allow all origins (fine for a uni project)
app.use(cors());
// Optionally, if you want to restrict:
// app.use(cors({ origin: ['http://vanillacat.me', 'https://samftw0128.github.io'] }));

// Preflight support (OPTIONS)
app.options('*', cors());

app.use(express.json());

// Create tables if they don't exist
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('customer','restaurant','rider','admin')),
      location TEXT,
      vehicle_type TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      customer_id INTEGER NOT NULL,
      restaurant_id INTEGER NOT NULL,
      rider_id INTEGER,
      status TEXT NOT NULL,
      total_price REAL NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (customer_id) REFERENCES users(id),
      FOREIGN KEY (restaurant_id) REFERENCES users(id),
      FOREIGN KEY (rider_id) REFERENCES users(id)
    )
  `);
});

// Helper: generate JWT token
function createToken(user) {
  const payload = {
    id: user.id,
    userId: user.user_id,
    name: user.name,
    role: user.role
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

// Auth middleware
function authRequired(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Health check
app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

// Register
app.post('/api/register', async (req, res) => {
  const { id, name, password, role, location, deliveryMethod } = req.body;

  if (!id || !name || !password || !role) {
    return res.status(400).json({ error: 'Missing id, name, password or role' });
  }

  if (!['customer', 'restaurant', 'rider', 'admin'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }

  try {
    const password_hash = await bcrypt.hash(password, 10);

    db.run(
      `INSERT INTO users (user_id, name, password_hash, role, location, vehicle_type)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        id,
        name,
        password_hash,
        role,
        role === 'restaurant' ? (location || null) : null,
        role === 'rider' ? (deliveryMethod || null) : null
      ],
      function (err) {
        if (err) {
          if (err.message && err.message.includes('UNIQUE')) {
            return res.status(400).json({ error: 'User ID already exists' });
          }
          console.error(err);
          return res.status(500).json({ error: 'Database error' });
        }

        const user = {
          id: this.lastID,
          user_id: id,
          name,
          role,
          location: role === 'restaurant' ? location || null : null,
          vehicle_type: role === 'rider' ? deliveryMethod || null : null
        };

        const token = createToken(user);
        res.json({ user, token });
      }
    );
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/login', (req, res) => {
  const { id, password, role } = req.body;

  if (!id || !password) {
    return res.status(400).json({ error: 'Missing id or password' });
  }

  db.get(
    `SELECT * FROM users WHERE user_id = ?`,
    [id],
    async (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Database error' });
      }
      if (!row) {
        return res.status(400).json({ error: 'Invalid credentials' });
      }

      // if role is provided, enforce it
      if (role && row.role !== role) {
        return res.status(400).json({ error: 'Role mismatch' });
      }

      const match = await bcrypt.compare(password, row.password_hash);
      if (!match) {
        return res.status(400).json({ error: 'Invalid credentials' });
      }

      const token = createToken(row);
      const user = {
        id: row.id,
        user_id: row.user_id,
        name: row.name,
        role: row.role,
        location: row.location,
        vehicle_type: row.vehicle_type
      };

      res.json({ user, token });
    }
  );
});

// Current user
app.get('/api/me', authRequired, (req, res) => {
  res.json({ user: req.user });
});

// List orders for logged-in user
app.get('/api/orders', authRequired, (req, res) => {
  const { id, role } = req.user;

  let query = 'SELECT * FROM orders';
  let params = [];

  if (role === 'customer') {
    query += ' WHERE customer_id = ?';
    params = [id];
  } else if (role === 'restaurant') {
    query += ' WHERE restaurant_id = ?';
    params = [id];
  } else if (role === 'rider') {
    query += ' WHERE rider_id = ?';
    params = [id];
  }

  db.all(query, params, (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

// Create order (customer)
app.post('/api/orders', authRequired, (req, res) => {
  const { id, role } = req.user;
  if (role !== 'customer') {
    return res.status(403).json({ error: 'Only customers can create orders' });
  }

  const { restaurant_id, total_price } = req.body;
  if (!restaurant_id || total_price == null) {
    return res.status(400).json({ error: 'Missing restaurant_id or total_price' });
  }

  db.run(
    `INSERT INTO orders (customer_id, restaurant_id, status, total_price)
     VALUES (?, ?, ?, ?)`,
    [id, restaurant_id, 'pending', total_price],
    function (err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Database error' });
      }
      res.json({ id: this.lastID });
    }
  );
});

// Update order status
app.patch('/api/orders/:id', authRequired, (req, res) => {
  const { status, rider_id } = req.body;
  const orderId = req.params.id;

  if (!status) {
    return res.status(400).json({ error: 'Missing status' });
  }

  db.run(
    `UPDATE orders
     SET status = ?, rider_id = COALESCE(?, rider_id),
         updated_at = CURRENT_TIMESTAMP
     WHERE id = ?`,
    [status, rider_id || null, orderId],
    function (err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Database error' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Order not found' });
      }
      res.json({ ok: true });
    }
  );
});

app.listen(PORT, () => {
  console.log(`CottonWar backend listening on port ${PORT}`);
});
