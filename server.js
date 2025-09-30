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
const { MongoClient } = require('mongodb');

// ================== MongoDB Connection ==================
const user = encodeURIComponent(process.env.MONGO_USER);
const pass = encodeURIComponent(process.env.MONGO_PASS);
const cluster = process.env.MONGO_CLUSTER;
const dbName = process.env.MONGO_DB || 'whatsapp';

const uri = `mongodb+srv://${user}:${pass}@${cluster}/?retryWrites=true&w=majority&appName=whatsapp`;
const client = new MongoClient(uri, { serverSelectionTimeoutMS: 10000, connectTimeoutMS: 15000 });

let db;
async function connectDB() {
  if (db) return db;
  try {
    await client.connect();
    db = client.db(dbName);
    console.log('✅ Connected to MongoDB Atlas');
    return db;
  } catch (err) {
    console.error('❌ MongoDB connection error:', err.message);
    process.exit(1); // Stop server if DB is unavailable
  }
}

// ================== App & WebSocket ==================
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// ================== Middleware ==================
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());

// ================== File Upload ==================
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});
const upload = multer({ storage });
app.use('/uploads', express.static(UPLOAD_DIR));

// ================== Utility ==================
function generateToken() {
  return uuid.v4();
}

// ================== Routes ==================

// Health Check
app.get('/api/health', async (req, res) => {
  const db = await connectDB();
  res.json({ status: db ? 'Connected' : 'Disconnected', database: dbName, timestamp: new Date() });
});

// File Upload
app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
  res.json({ url: fileUrl });
});

// Signup
app.post('/api/sign_up', async (req, res) => {
  const { email, username, password } = req.body;
  if (!email || !username || !password) return res.status(400).json({ error: 'All fields required' });

  try {
    const db = await connectDB();
    const users = db.collection('users');

    if (await users.findOne({ email })) return res.status(400).json({ error: 'Email already exists' });

    const password_hash = await bcrypt.hash(password, 10);
    await users.insertOne({
      email,
      username,
      password_hash,
      token: null,
      status: "offline",
      createdAt: new Date().toISOString()
    });

    res.json({ message: 'User created successfully. Please login.' });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email & password required' });

  try {
    const db = await connectDB();
    const users = db.collection('users');
    const user = await users.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) return res.status(400).json({ error: 'Incorrect password' });

    const token = generateToken();
    await users.updateOne({ email }, { $set: { token, status: "online", lastLogin: new Date().toISOString() } });

    res.json({ user: { email: user.email, username: user.username, token } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get Users
app.get('/api/users', async (req, res) => {
  try {
    const db = await connectDB();
    const users = await db.collection('users').find({})
      .project({ password_hash: 0, token: 0 })
      .sort({ username: 1 })
      .toArray();
    res.json(users);
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Get Messages
app.get('/api/messages/:room', async (req, res) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Auth required' });

  try {
    const db = await connectDB();
    const users = db.collection('users');
    const messagesCollection = db.collection('messages');

    const user = await users.findOne({ token });
    if (!user) return res.status(401).json({ error: 'Invalid token' });

    const roomMessages = await messagesCollection.find({ room: req.params.room }).sort({ timestamp: 1 }).toArray();
    res.json(roomMessages);
  } catch (err) {
    console.error('Get messages error:', err);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// ================== WebSocket ==================
wss.on('connection', (ws) => {
  ws.user = null;

  ws.on('message', async (data) => {
    try {
      const message = JSON.parse(data);

      // Authentication
      if (message.type === 'auth') {
        const db = await connectDB();
        const users = db.collection('users');
        const user = await users.findOne({ token: message.token });
        if (user) {
          ws.user = user;
          ws.send(JSON.stringify({ type: 'authSuccess', user: { username: user.username } }));
        }
      }

      // Send message
      if (message.type === 'message' && ws.user) {
        const db = await connectDB();
        const messagesCollection = db.collection('messages');

        const newMessage = {
          id: uuid.v4(),
          sender: ws.user.username,
          content: message.content,
          room: message.room || 'general',
          timestamp: new Date().toISOString(),
          isFile: message.isFile || false,
          fileType: message.fileType || null
        };

        await messagesCollection.insertOne(newMessage);

        wss.clients.forEach(client => {
          if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({ type: 'message', data: newMessage }));
          }
        });
      }
    } catch (err) {
      console.error('WebSocket error:', err);
    }
  });
});

// ================== Start Server ==================
const PORT = process.env.PORT || 5000;
server.listen(PORT, async () => {
  console.log('='.repeat(50));
  console.log(`✅ Server running on port ${PORT}`);
  await connectDB();
  console.log(`✅ Health: http://localhost:${PORT}/api/health`);
  console.log('='.repeat(50));
});
