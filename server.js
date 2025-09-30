require('dotenv').config();
const express = require('express');
const cors = require('cors');
const http = require('http');
const WebSocket = require('ws');
const uuid = require('uuid');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// ================== MongoDB Connection ==================
let mongodb;
let isConnected = false;

const memoryDB = {
  users: [],
  messages: [],
  rooms: ['general', 'random', 'help']
};

async function connectDB() {
  if (mongodb && isConnected) return mongodb;

  try {
    const { MongoClient } = await import('mongodb');
    const uri = process.env.MONGO_URI || "mongodb+srv://USERNAME:PASSWORD@CLUSTER.mongodb.net/whatsapp?retryWrites=true&w=majority";

    const client = new MongoClient(uri, {
      serverSelectionTimeoutMS: 5000,
      connectTimeoutMS: 10000,
    });

    await client.connect();
    mongodb = client.db('whatsapp');
    isConnected = true;
    console.log('✅ MongoDB Connected Successfully!');
    return mongodb;

  } catch (err) {
    console.log('⚠️  MongoDB connection failed, using memory storage');
    console.log('💡 Error details:', err.message);

    return {
      collection: (name) => ({
        find: (query = {}) => ({
          toArray: () => {
            const results = memoryDB[name].filter(item => {
              for (let key in query) if (item[key] !== query[key]) return false;
              return true;
            });
            return Promise.resolve(results);
          },
          sort: (sortBy) => ({ toArray: () => Promise.resolve(memoryDB[name]) })
        }),
        findOne: (query = {}) => {
          const result = memoryDB[name].find(item => {
            for (let key in query) if (item[key] !== query[key]) return false;
            return true;
          });
          return Promise.resolve(result);
        },
        insertOne: (doc) => {
          doc._id = Date.now().toString();
          memoryDB[name].push(doc);
          return Promise.resolve({ insertedId: doc._id });
        },
        updateOne: (query, update) => {
          const index = memoryDB[name].findIndex(item => {
            for (let key in query) if (item[key] !== query[key]) return false;
            return true;
          });
          if (index !== -1) memoryDB[name][index] = { ...memoryDB[name][index], ...update.$set };
          return Promise.resolve({ modifiedCount: 1 });
        },
        countDocuments: (query = {}) => {
          const count = memoryDB[name].filter(item => {
            for (let key in query) if (item[key] !== query[key]) return false;
            return true;
          }).length;
          return Promise.resolve(count);
        }
      })
    };
  }
}

// ================== App & WebSocket ==================
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// ================== Middleware ==================
app.use(cors({
  origin: [
    'http://localhost:5173',
    'http://localhost:3000',
    'https://whatsapp-n8xf.vercel.app',
    'https://whatsapp-60un.onrender.com'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE']
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ================== File Upload ==================
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });
app.use('/uploads', express.static(UPLOAD_DIR));

// ================== Utilities ==================
function generateToken() {
  return uuid.v4();
}

// ================== Routes ==================

// Health Check
app.get('/api/health', async (req, res) => {
  const db = await connectDB();
  res.json({
    status: '✅ Healthy',
    database: isConnected ? 'MongoDB' : 'Memory Storage',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// Sign Up
app.post('/api/sign_up', async (req, res) => {
  try {
    const { email, username, password } = req.body;
    if (!email || !username || !password) return res.status(400).json({ error: 'All fields are required' });

    const db = await connectDB();
    const users = db.collection('users');
    const exists = await users.findOne({ $or: [{ email }, { username }] });
    if (exists) return res.status(400).json({ error: 'User already exists' });

    const password_hash = await bcrypt.hash(password, 10);
    await users.insertOne({ email, username, password_hash, token: null, status: 'offline', createdAt: new Date().toISOString() });

    res.json({ success: true, message: 'Account created successfully!', user: { username, email } });
  } catch (err) {
    console.error('❌ Signup error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

    const db = await connectDB();
    const users = db.collection('users');
    const user = await users.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const valid = await bcrypt.compare(password, user.password_hash || '');
    if (!valid) return res.status(401).json({ error: 'Invalid password' });

    const token = generateToken();
    await users.updateOne({ email }, { $set: { token, status: 'online', lastLogin: new Date().toISOString() } });

    res.json({ success: true, message: `Welcome back, ${user.username}!`, user: { username: user.username, email: user.email, token } });
  } catch (err) {
    console.error('❌ Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get Users
app.get('/api/users', async (req, res) => {
  try {
    const db = await connectDB();
    const users = await db.collection('users').find({}).project({ password_hash: 0, token: 0 }).toArray();
    res.json({ success: true, count: users.length, users });
  } catch (err) {
    console.error('❌ Get users error:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Get Messages
app.get('/api/messages/:room', async (req, res) => {
  try {
    const { room } = req.params;
    const token = req.headers.authorization;
    if (!token) return res.status(401).json({ error: 'Authentication required' });

    const db = await connectDB();
    const users = db.collection('users');
    const messagesCollection = db.collection('messages');

    const user = await users.findOne({ token });
    if (!user) return res.status(401).json({ error: 'Invalid token' });

    const messages = await messagesCollection.find({ room }).sort({ timestamp: 1 }).toArray();
    res.json({ success: true, room, count: messages.length, messages });
  } catch (err) {
    console.error('❌ Get messages error:', err);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Send Message
app.post('/api/messages', async (req, res) => {
  try {
    const token = req.headers.authorization;
    const { content, room = 'general' } = req.body;
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    if (!content) return res.status(400).json({ error: 'Message cannot be empty' });

    const db = await connectDB();
    const users = db.collection('users');
    const messagesCollection = db.collection('messages');

    const user = await users.findOne({ token });
    if (!user) return res.status(401).json({ error: 'Invalid token' });

    const newMessage = { id: uuid.v4(), sender: user.username, content, room, timestamp: new Date().toISOString() };
    await messagesCollection.insertOne(newMessage);

    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) client.send(JSON.stringify({ type: 'message', data: newMessage }));
    });

    res.json({ success: true, message: 'Message sent successfully', data: newMessage });
  } catch (err) {
    console.error('❌ Send message error:', err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// WebSocket
wss.on('connection', (ws) => {
  console.log('🔌 New WebSocket connection');
  ws.user = null;

  ws.on('message', async (data) => {
    try {
      const message = JSON.parse(data);
      const db = await connectDB();
      const users = db.collection('users');

      if (message.type === 'auth') {
        const user = await users.findOne({ token: message.token });
        if (user) {
          ws.user = user;
          ws.send(JSON.stringify({ type: 'authSuccess', user: { username: user.username, email: user.email } }));
        }
      }

      if (message.type === 'message' && ws.user) {
        const messagesCollection = db.collection('messages');
        const newMessage = { id: uuid.v4(), sender: ws.user.username, content: message.content, room: message.room || 'general', timestamp: new Date().toISOString() };
        await messagesCollection.insertOne(newMessage);

        wss.clients.forEach(client => {
          if (client.readyState === WebSocket.OPEN) client.send(JSON.stringify({ type: 'message', data: newMessage }));
        });
      }
    } catch (err) {
      console.error('❌ WebSocket error:', err);
    }
  });
});

// Start server
const PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', async () => {
  console.log('='.repeat(60));
  console.log(`🚀 WhatsApp Server Running on Port ${PORT}`);
  const db = await connectDB();
  console.log(`💾 Database: ${isConnected ? 'MongoDB Connected' : 'Memory Storage'}`);
  console.log('='.repeat(60));
});
