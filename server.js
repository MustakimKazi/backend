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

// ================== Environment Variables Check ==================
console.log('🔍 Environment Check:');
console.log('PORT:', process.env.PORT || '5000 (default)');
console.log('MONGO_USER:', process.env.MONGO_USER ? '✅ Set' : '❌ Missing');
console.log('MONGO_CLUSTER:', process.env.MONGO_CLUSTER ? '✅ Set' : '❌ Missing');

// ================== MongoDB Connection (Fixed SSL Issue) ==================
const user = process.env.MONGO_USER || 'mohdmustakimkazi_db_user';
const pass = process.env.MONGO_PASS || 'HugPu2kIqGxOdhNF';
const cluster = process.env.MONGO_CLUSTER || 'whatsapp.dzac4go.mongodb.net';
const dbName = process.env.MONGO_DB || 'whatsapp';

// Fixed connection string with SSL disabled for Render.com
const uri = `mongodb+srv://${user}:${pass}@${cluster}/${dbName}?retryWrites=true&w=majority&ssl=true`;

console.log('🔗 MongoDB URI:', `mongodb+srv://${user}:****@${cluster}/${dbName}`);

const client = new MongoClient(uri, {
  serverSelectionTimeoutMS: 10000,
  connectTimeoutMS: 15000,
  ssl: true,
  tlsAllowInvalidCertificates: false
});

let db;
let isConnected = false;

async function connectDB() {
  if (db && isConnected) return db;
  
  try {
    console.log('🔄 Connecting to MongoDB...');
    await client.connect();
    db = client.db(dbName);
    isConnected = true;
    
    console.log('✅ Connected to MongoDB Atlas');
    
    // Initialize collections if they don't exist
    await initializeCollections();
    
    return db;
  } catch (err) {
    console.error('❌ MongoDB connection error:', err.message);
    
    // Don't exit process on Render - just log error
    console.log('⚠️  Continuing without database connection');
    return null;
  }
}

// Initialize collections
async function initializeCollections() {
  try {
    const collections = await db.listCollections().toArray();
    const collectionNames = collections.map(c => c.name);
    
    if (!collectionNames.includes('users')) {
      await db.createCollection('users');
      console.log('✅ Users collection created');
    }
    
    if (!collectionNames.includes('messages')) {
      await db.createCollection('messages');
      console.log('✅ Messages collection created');
    }
  } catch (err) {
    console.log('⚠️  Collections may already exist');
  }
}

// ================== App & WebSocket ==================
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// ================== Middleware (Fixed for Render) ==================
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

// Increase payload size limit for file uploads
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ================== File Upload ==================
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  console.log('✅ Uploads directory created');
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});
const upload = multer({ 
  storage,
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});
app.use('/uploads', express.static(UPLOAD_DIR));

// ================== Utility ==================
function generateToken() {
  return uuid.v4();
}

// ================== Routes ==================

// Root route
app.get('/', (req, res) => {
  res.json({ 
    message: 'WhatsApp Server API',
    status: 'Running',
    database: isConnected ? 'Connected' : 'Disconnected',
    timestamp: new Date().toISOString()
  });
});

// Health Check
app.get('/api/health', async (req, res) => {
  try {
    const db = await connectDB();
    res.json({ 
      status: 'OK', 
      database: db ? 'Connected' : 'Disconnected',
      server: 'Running',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ error: 'Health check failed' });
  }
});

// File Upload
app.post('/api/upload', upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    console.log('📁 File uploaded:', req.file.filename);
    
    res.json({ 
      url: fileUrl,
      filename: req.file.filename,
      size: req.file.size
    });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'File upload failed' });
  }
});

// Signup (Fixed body parsing)
app.post('/api/sign_up', async (req, res) => {
  try {
    // Log request body for debugging
    console.log('📝 Signup request body:', req.body);
    
    const { email, username, password } = req.body;
    
    if (!email || !username || !password) {
      return res.status(400).json({ 
        error: 'All fields required',
        received: { email: !!email, username: !!username, password: !!password }
      });
    }

    const db = await connectDB();
    if (!db) {
      return res.status(503).json({ error: 'Database unavailable' });
    }

    const users = db.collection('users');

    // Check if email already exists
    const existingUser = await users.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    // Hash password
    const password_hash = await bcrypt.hash(password, 10);
    
    const result = await users.insertOne({
      email,
      username,
      password_hash,
      token: null,
      status: "offline",
      createdAt: new Date().toISOString()
    });

    console.log('👤 New user registered:', username);
    
    res.json({ 
      message: 'User created successfully. Please login.',
      userId: result.insertedId
    });
  } catch (err) {
    console.error('❌ Signup error:', err);
    res.status(500).json({ error: 'Internal server error during signup' });
  }
});

// Login (Fixed body parsing)
app.post('/api/login', async (req, res) => {
  try {
    console.log('🔑 Login request body:', req.body);
    
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        error: 'Email and password required',
        received: { email: !!email, password: !!password }
      });
    }

    const db = await connectDB();
    if (!db) {
      return res.status(503).json({ error: 'Database unavailable' });
    }

    const users = db.collection('users');
    const user = await users.findOne({ email });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check password - handle both hashed and plain text
    let isPasswordValid = false;
    
    if (user.password_hash) {
      isPasswordValid = await bcrypt.compare(password, user.password_hash);
    } else if (user.password_ba81d) {
      // For existing users with plain text passwords
      isPasswordValid = (password === user.password_ba81d);
    }

    if (!isPasswordValid) {
      return res.status(400).json({ error: 'Incorrect password' });
    }

    const token = generateToken();
    await users.updateOne({ email }, { 
      $set: { 
        token, 
        status: "online", 
        lastLogin: new Date().toISOString() 
      } 
    });

    console.log('✅ User logged in:', user.username);
    
    res.json({ 
      user: { 
        email: user.email, 
        username: user.username, 
        token 
      },
      message: 'Login successful'
    });
  } catch (err) {
    console.error('❌ Login error:', err);
    res.status(500).json({ error: 'Internal server error during login' });
  }
});

// Get Users
app.get('/api/users', async (req, res) => {
  try {
    const db = await connectDB();
    if (!db) {
      return res.status(503).json({ error: 'Database unavailable' });
    }

    const users = await db.collection('users')
      .find({})
      .project({ password_hash: 0, password_ba81d: 0, token: 0 })
      .sort({ username: 1 })
      .toArray();
    
    res.json(users);
  } catch (err) {
    console.error('❌ Get users error:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Get Messages
app.get('/api/messages/:room', async (req, res) => {
  try {
    const token = req.headers.authorization;
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const db = await connectDB();
    if (!db) {
      return res.status(503).json({ error: 'Database unavailable' });
    }

    const users = db.collection('users');
    const messagesCollection = db.collection('messages');

    const user = await users.findOne({ token });
    if (!user) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    const roomMessages = await messagesCollection
      .find({ room: req.params.room })
      .sort({ timestamp: 1 })
      .toArray();

    res.json(roomMessages);
  } catch (err) {
    console.error('❌ Get messages error:', err);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Send Message (New endpoint)
app.post('/api/messages', async (req, res) => {
  try {
    const token = req.headers.authorization;
    const { content, room } = req.body;
    
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    if (!content) {
      return res.status(400).json({ error: 'Message content required' });
    }

    const db = await connectDB();
    if (!db) {
      return res.status(503).json({ error: 'Database unavailable' });
    }

    const users = db.collection('users');
    const messagesCollection = db.collection('messages');

    const user = await users.findOne({ token });
    if (!user) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    const newMessage = {
      id: uuid.v4(),
      sender: user.username,
      content: content,
      room: room || 'general',
      timestamp: new Date().toISOString()
    };

    await messagesCollection.insertOne(newMessage);
    
    res.json({ 
      message: 'Message sent successfully',
      data: newMessage
    });
  } catch (err) {
    console.error('❌ Send message error:', err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// ================== WebSocket ==================
wss.on('connection', (ws) => {
  console.log('🔌 New WebSocket connection');
  ws.user = null;

  ws.on('message', async (data) => {
    try {
      const message = JSON.parse(data);

      // Authentication
      if (message.type === 'auth') {
        const db = await connectDB();
        if (db) {
          const users = db.collection('users');
          const user = await users.findOne({ token: message.token });
          if (user) {
            ws.user = user;
            ws.send(JSON.stringify({ 
              type: 'authSuccess', 
              user: { username: user.username } 
            }));
            console.log('✅ WebSocket authenticated:', user.username);
          }
        }
      }

      // Send message
      if (message.type === 'message' && ws.user) {
        const db = await connectDB();
        if (db) {
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

          // Broadcast to all clients
          wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
              client.send(JSON.stringify({ 
                type: 'message', 
                data: newMessage 
              }));
            }
          });
          
          console.log(`💬 Message from ${ws.user.username} in ${newMessage.room}`);
        }
      }
    } catch (err) {
      console.error('❌ WebSocket error:', err);
    }
  });

  ws.on('close', () => {
    console.log('🔌 WebSocket connection closed');
  });
});

// ================== Error Handling ==================
app.use((err, req, res, next) => {
  console.error('❌ Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// ================== Start Server ==================
const PORT = process.env.PORT || 5000;

async function startServer() {
  try {
    console.log('🚀 Starting WhatsApp Server...');
    
    // Test database connection (but don't block server start)
    connectDB().then(db => {
      if (db) {
        console.log('🎉 MongoDB connected successfully');
      } else {
        console.log('⚠️  Running without database connection');
      }
    });

    server.listen(PORT, '0.0.0.0', () => {
      console.log('='.repeat(50));
      console.log(`✅ Server running on port ${PORT}`);
      console.log(`✅ Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`✅ Health: http://localhost:${PORT}/api/health`);
      console.log('='.repeat(50));
    });
  } catch (err) {
    console.error('❌ Failed to start server:', err);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🔄 Shutting down gracefully...');
  try {
    await client.close();
    console.log('✅ MongoDB connection closed');
    process.exit(0);
  } catch (err) {
    console.error('❌ Error during shutdown:', err);
    process.exit(1);
  }
});

// Start the server
startServer();