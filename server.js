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

// ================== Environment Variables ==================
console.log('🔍 Environment Check:');
console.log('PORT:', process.env.PORT || '10000');
console.log('NODE_ENV:', process.env.NODE_ENV || 'development');

// MongoDB credentials - directly defined (no SSL issues)
const MONGODB_CONFIG = {
  user: 'mohdmustakimkazi_db_user',
  password: 'HugPu2kIqGxOdhNF',
  cluster: 'whatsapp.dzac4go.mongodb.net',
  dbName: 'whatsapp'
};

// ================== Database Connection (Simple Approach) ==================
let db = null;
let isConnected = false;

// Simple in-memory storage if MongoDB fails
const memoryStorage = {
  users: [
    {
      _id: '1',
      username: 'mustskim',
      email: 'mustskim@gmail.com',
      password_hash: '$2a$10$examplehashedpassword',
      token: null,
      status: 'offline',
      createdAt: new Date().toISOString()
    }
  ],
  messages: [],
  rooms: ['general', 'random', 'help']
};

async function connectDB() {
  if (db && isConnected) return db;
  
  try {
    // Try to use native MongoDB driver with simpler connection
    const { MongoClient } = require('mongodb');
    
    const uri = `mongodb+srv://${MONGODB_CONFIG.user}:${MONGODB_CONFIG.password}@${MONGODB_CONFIG.cluster}/${MONGODB_CONFIG.dbName}?retryWrites=true&w=majority`;
    
    console.log('🔄 Attempting MongoDB connection...');
    
    const client = new MongoClient(uri, {
      serverSelectionTimeoutMS: 5000,
      connectTimeoutMS: 10000,
      // Remove SSL options that cause issues
    });
    
    await client.connect();
    db = client.db(MONGODB_CONFIG.dbName);
    isConnected = true;
    
    console.log('✅ MongoDB Connected Successfully!');
    return db;
    
  } catch (err) {
    console.log('❌ MongoDB failed, using memory storage');
    console.log('💡 Error:', err.message);
    
    // Return memory storage instead
    return {
      collection: (name) => ({
        find: (query = {}) => ({
          toArray: () => Promise.resolve(memoryStorage[name].filter(item => {
            for (let key in query) {
              if (item[key] !== query[key]) return false;
            }
            return true;
          }))
        }),
        findOne: (query = {}) => Promise.resolve(
          memoryStorage[name].find(item => {
            for (let key in query) {
              if (item[key] !== query[key]) return false;
            }
            return true;
          })
        ),
        insertOne: (doc) => {
          doc._id = Date.now().toString();
          memoryStorage[name].push(doc);
          return Promise.resolve({ insertedId: doc._id });
        },
        updateOne: (query, update) => {
          const index = memoryStorage[name].findIndex(item => {
            for (let key in query) {
              if (item[key] !== query[key]) return false;
            }
            return true;
          });
          if (index !== -1) {
            memoryStorage[name][index] = { ...memoryStorage[name][index], ...update.$set };
          }
          return Promise.resolve({ modifiedCount: index !== -1 ? 1 : 0 });
        },
        countDocuments: () => Promise.resolve(memoryStorage[name].length)
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
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});

const upload = multer({ 
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }
});

app.use('/uploads', express.static(UPLOAD_DIR));

// ================== Utility Functions ==================
function generateToken() {
  return uuid.v4();
}

// ================== API Routes ==================

// Root route
app.get('/', (req, res) => {
  res.json({ 
    message: 'WhatsApp Server API is Running! 🚀',
    status: 'Active',
    database: isConnected ? 'MongoDB' : 'Memory Storage',
    timestamp: new Date().toISOString(),
    endpoints: [
      'GET  /api/health',
      'POST /api/sign_up',
      'POST /api/login', 
      'GET  /api/users',
      'GET  /api/messages/:room',
      'POST /api/messages',
      'POST /api/upload'
    ]
  });
});

// Health Check
app.get('/api/health', async (req, res) => {
  try {
    const db = await connectDB();
    res.json({ 
      status: '✅ Server is Healthy',
      database: isConnected ? '✅ MongoDB Connected' : '🔄 Using Memory Storage',
      timestamp: new Date().toISOString(),
      uptime: process.uptime()
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
    
    res.json({ 
      success: true,
      url: fileUrl,
      filename: req.file.filename,
      message: 'File uploaded successfully'
    });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'File upload failed' });
  }
});

// Sign Up
app.post('/api/sign_up', async (req, res) => {
  try {
    console.log('📝 Signup request received');
    
    const { email, username, password } = req.body;
    
    // Validation
    if (!email || !username || !password) {
      return res.status(400).json({ 
        error: 'All fields are required',
        details: 'Please provide email, username and password'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: 'Password too short',
        details: 'Password must be at least 6 characters'
      });
    }

    const db = await connectDB();
    const users = db.collection('users');

    // Check if user exists
    const existingUser = await users.findOne({ 
      $or: [{ email }, { username }] 
    });

    if (existingUser) {
      return res.status(400).json({
        error: 'User already exists',
        details: 'Email or username is already taken'
      });
    }

    // Hash password
    const password_hash = await bcrypt.hash(password, 10);
    
    // Create user
    const result = await users.insertOne({
      email,
      username,
      password_hash,
      token: null,
      status: "offline",
      createdAt: new Date().toISOString(),
      lastLogin: null
    });

    console.log('✅ New user registered:', username);

    res.json({
      success: true,
      message: 'Account created successfully! Please login.',
      user: {
        username,
        email
      }
    });

  } catch (err) {
    console.error('❌ Signup error:', err);
    res.status(500).json({
      error: 'Registration failed',
      details: 'Please try again later'
    });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    console.log('🔑 Login request received');
    
    const { email, password } = req.body;
    
    // Validation
    if (!email || !password) {
      return res.status(400).json({
        error: 'Missing credentials',
        details: 'Please provide both email and password'
      });
    }

    const db = await connectDB();
    const users = db.collection('users');

    // Find user
    const user = await users.findOne({ email });
    
    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        details: 'No account found with this email'
      });
    }

    // Check password
    let passwordValid = false;
    
    if (user.password_hash) {
      passwordValid = await bcrypt.compare(password, user.password_hash);
    }

    if (!passwordValid) {
      return res.status(401).json({
        error: 'Invalid password',
        details: 'Please check your password and try again'
      });
    }

    // Generate token
    const token = generateToken();
    
    // Update user
    await users.updateOne(
      { email }, 
      { 
        $set: { 
          token, 
          status: "online",
          lastLogin: new Date().toISOString() 
        } 
      }
    );

    console.log('✅ User logged in:', user.username);

    res.json({
      success: true,
      message: `Welcome back, ${user.username}!`,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        token: token
      }
    });

  } catch (err) {
    console.error('❌ Login error:', err);
    res.status(500).json({
      error: 'Login failed',
      details: 'Please try again later'
    });
  }
});

// Get All Users
app.get('/api/users', async (req, res) => {
  try {
    const db = await connectDB();
    const users = await db.collection('users')
      .find({})
      .project({ password_hash: 0, token: 0 })
      .toArray();

    res.json({
      success: true,
      users: users,
      count: users.length
    });

  } catch (err) {
    console.error('❌ Get users error:', err);
    res.status(500).json({
      error: 'Failed to fetch users'
    });
  }
});

// Get Messages for Room
app.get('/api/messages/:room', async (req, res) => {
  try {
    const token = req.headers.authorization;
    const room = req.params.room;

    if (!token) {
      return res.status(401).json({
        error: 'Authentication required'
      });
    }

    const db = await connectDB();
    const users = db.collection('users');
    const messagesCollection = db.collection('messages');

    // Verify user
    const user = await users.findOne({ token });
    if (!user) {
      return res.status(401).json({
        error: 'Invalid token'
      });
    }

    // Get messages
    const messages = await messagesCollection
      .find({ room })
      .sort({ timestamp: 1 })
      .toArray();

    res.json({
      success: true,
      room: room,
      messages: messages,
      count: messages.length
    });

  } catch (err) {
    console.error('❌ Get messages error:', err);
    res.status(500).json({
      error: 'Failed to fetch messages'
    });
  }
});

// Send Message
app.post('/api/messages', async (req, res) => {
  try {
    const token = req.headers.authorization;
    const { content, room = 'general' } = req.body;

    if (!token) {
      return res.status(401).json({
        error: 'Authentication required'
      });
    }

    if (!content || content.trim() === '') {
      return res.status(400).json({
        error: 'Message cannot be empty'
      });
    }

    const db = await connectDB();
    const users = db.collection('users');
    const messagesCollection = db.collection('messages');

    // Verify user
    const user = await users.findOne({ token });
    if (!user) {
      return res.status(401).json({
        error: 'Invalid token'
      });
    }

    // Create message
    const newMessage = {
      id: uuid.v4(),
      sender: user.username,
      content: content.trim(),
      room: room,
      timestamp: new Date().toISOString(),
      isFile: false
    };

    await messagesCollection.insertOne(newMessage);

    res.json({
      success: true,
      message: 'Message sent successfully',
      data: newMessage
    });

  } catch (err) {
    console.error('❌ Send message error:', err);
    res.status(500).json({
      error: 'Failed to send message'
    });
  }
});

// Get Rooms
app.get('/api/rooms', async (req, res) => {
  try {
    const token = req.headers.authorization;
    
    if (!token) {
      return res.status(401).json({
        error: 'Authentication required'
      });
    }

    const db = await connectDB();
    const users = db.collection('users');

    // Verify user
    const user = await users.findOne({ token });
    if (!user) {
      return res.status(401).json({
        error: 'Invalid token'
      });
    }

    const rooms = ['general', 'random', 'help', 'tech', 'games'];
    
    res.json({
      success: true,
      rooms: rooms
    });

  } catch (err) {
    console.error('❌ Get rooms error:', err);
    res.status(500).json({
      error: 'Failed to fetch rooms'
    });
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
        const users = db.collection('users');
        const user = await users.findOne({ token: message.token });
        
        if (user) {
          ws.user = user;
          ws.send(JSON.stringify({ 
            type: 'authSuccess', 
            user: { 
              username: user.username,
              email: user.email
            } 
          }));
          console.log('✅ WebSocket authenticated:', user.username);
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

    } catch (err) {
      console.error('❌ WebSocket error:', err);
    }
  });

  ws.on('close', () => {
    if (ws.user) {
      console.log('🔌 User disconnected:', ws.user.username);
    }
  });
});

// ================== Error Handling ==================
app.use((err, req, res, next) => {
  console.error('❌ Server error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: 'Something went wrong on our end'
  });
});

// 404 Handler
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Endpoint not found',
    message: 'The requested API endpoint does not exist'
  });
});

// ================== Start Server ==================
const PORT = process.env.PORT || 10000;

server.listen(PORT, '0.0.0.0', () => {
  console.log('='.repeat(60));
  console.log(`🚀 WhatsApp Server Started Successfully!`);
  console.log(`📍 Port: ${PORT}`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`💾 Database: ${isConnected ? 'MongoDB' : 'Memory Storage'}`);
  console.log(`🔗 Health Check: http://localhost:${PORT}/api/health`);
  console.log(`📚 API Docs: http://localhost:${PORT}/`);
  console.log('='.repeat(60));
  
  // Test connection
  connectDB().then(db => {
    if (isConnected) {
      console.log('✅ MongoDB: Connected and Ready');
    } else {
      console.log('🔄 MongoDB: Using Memory Storage (Fallback)');
    }
  });
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🔄 Shutting down server gracefully...');
  process.exit(0);
});