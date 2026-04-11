const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

const JWT_SECRET = 'chat-app-secret-key-2024';
const PORT = process.env.PORT || 3000;

let db;

async function initDB() {
  const SQL = await initSqlJs();
  const filePath = path.join(__dirname, 'database.sqlite');
  
  if (fs.existsSync(filePath)) {
    const fileBuffer = fs.readFileSync(filePath);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }
  
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    displayName TEXT,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    senderId INTEGER NOT NULL,
    receiverId INTEGER,
    roomId TEXT,
    content TEXT NOT NULL,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(senderId) REFERENCES users(id),
    FOREIGN KEY(receiverId) REFERENCES users(id)
  )`);
  
  saveDB();
}

function saveDB() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(path.join(__dirname, 'database.sqlite'), buffer);
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'chat-app-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

function authMiddleware(req, res, next) {
  const token = req.session.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

app.post('/api/register', async (req, res) => {
  const { username, password, displayName } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  try {
    const hashed = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, password, displayName) VALUES (?, ?, ?)', [username, hashed, displayName || username]);
    saveDB();
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: 'Username already exists' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  const stmt = db.prepare('SELECT * FROM users WHERE username = ?');
  stmt.bind([username]);
  
  if (stmt.step()) {
    const user = stmt.getAsObject();
    stmt.free();
    
    if (await bcrypt.compare(password, user.password)) {
      const token = jwt.sign({ id: user.id, username: user.username, displayName: user.displayName }, JWT_SECRET, { expiresIn: '24h' });
      req.session.token = token;
      req.session.user = { id: user.id, username: user.username, displayName: user.displayName };
      return res.json({ token, user: { id: user.id, username: user.username, displayName: user.displayName } });
    }
  }
  
  res.status(401).json({ error: 'Invalid credentials' });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

app.get('/api/users', authMiddleware, (req, res) => {
  const stmt = db.prepare('SELECT id, username, displayName FROM users WHERE id != ?');
  stmt.bind([req.user.id]);
  
  const users = [];
  while (stmt.step()) {
    users.push(stmt.getAsObject());
  }
  stmt.free();
  res.json({ users });
});

app.get('/api/messages/:roomId', authMiddleware, (req, res) => {
  const { roomId } = req.params;
  const stmt = db.prepare('SELECT * FROM messages WHERE roomId = ? ORDER BY createdAt ASC LIMIT 100');
  stmt.bind([roomId]);
  
  const messages = [];
  while (stmt.step()) {
    messages.push(stmt.getAsObject());
  }
  stmt.free();
  res.json({ messages });
});

const activeUsers = new Map();

io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  
  socket.on('register', (userId) => {
    activeUsers.set(userId, { socket: socket.id, displayName: '' });
    socket.userId = userId;
  });
  
  socket.on('join-room', (roomId) => {
    socket.join(roomId);
  });
  
  socket.on('message', (data) => {
    const { roomId, senderId, content } = data;
    db.run('INSERT INTO messages (senderId, roomId, content) VALUES (?, ?, ?)', [senderId, roomId, content]);
    saveDB();
    io.to(roomId).emit('message', data);
  });

  // WebRTC Signaling
  socket.on('call-user', (data) => {
    const { to, from, fromName, roomId, offer } = data;
    const target = activeUsers.get(to);
    if (target) {
      io.to(target.socket).emit('call-incoming', { from, fromName, roomId, offer });
    }
  });
  
  socket.on('accept-call', (data) => {
    const { to, roomId, answer } = data;
    const target = activeUsers.get(to);
    if (target) {
      io.to(target.socket).emit('call-accepted', { roomId, answer });
    }
  });
  
  socket.on('reject-call', (data) => {
    const { to, roomId } = data;
    const target = activeUsers.get(to);
    if (target) {
      io.to(target.socket).emit('call-rejected', { roomId });
    }
  });
  
  socket.on('ice-candidate', (data) => {
    const { to, roomId, candidate } = data;
    const target = activeUsers.get(to);
    if (target) {
      io.to(target.socket).emit('ice-candidate', { roomId, candidate, from: socket.userId });
    }
  });
  
  socket.on('end-call', (data) => {
    const { roomId } = data;
    socket.to(roomId).emit('call-ended');
  });
  
  socket.on('toggle-video', (data) => {
    const { roomId, enabled, to } = data;
    socket.to(roomId).emit('peer-toggle-video', { enabled });
  });
  
  socket.on('toggle-audio', (data) => {
    const { roomId, enabled, to } = data;
    socket.to(roomId).emit('peer-toggle-audio', { enabled });
  });
  
  socket.on('screen-share', (data) => {
    const { roomId, sharing, to } = data;
    socket.to(roomId).emit('peer-screen-share', { sharing });
  });

  socket.on('disconnect', () => {
    if (socket.userId) {
      activeUsers.delete(socket.userId);
    }
    console.log('Client disconnected:', socket.id);
  });
});

async function start() {
  await initDB();
  server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

start();