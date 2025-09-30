require('dotenv').config();
const express = require('express');
const cors = require('cors');
const http = require('http');
const WebSocket = require('ws');
const uuid = require('uuid');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// ================== Environment Setup ==================
console.log('🚀 Starting WhatsApp Server...');
console.log('🔍 Environment Check:');
console.log('PORT:', process.env.PORT || '10000');
console.log('NODE_ENV:', process.env.NODE_ENV || 'development');

// ================== Static Users Configuration ==================
const STATIC_USERS = {
  mustakim: {
    id: '1',
    username: 'mustakim',
    email: 'mustakim@gmail.com',
    password: '123456',
    displayName: 'Mustakim',
    avatar: '👨‍💻',
    status: 'online',
    isStatic: true
  },
  taniya: {
    id: '2',
    username: 'taniya',
    email: 'taniya@gmail.com',
    password: '123456',
    displayName: 'Taniya',
    avatar: '😎',
    status: 'online',
    isStatic: true
  },
  aliya: {
    id: '3', 
    username: 'aliya',
    email: 'aliya@gmail.com',
    password: '123456',
    displayName: 'Aliya',
    avatar: '👩‍💼',
    status: 'online',
    isStatic: true
  },
  saniya: {
    id: '4',
    username: 'saniya',
    email: 'saniya@gmail.com',
    password: '123456',
    displayName: 'Saniya',
    avatar: '👑',
    status: 'online',
    isStatic: true
  }
};

// ================== Memory Storage ==================
const memoryStorage = {
  users: Object.values(STATIC_USERS).map(user => ({
    _id: user.id,
    username: user.username,
    email: user.email,
    password_hash: bcrypt.hashSync(user.password, 10),
    displayName: user.displayName,
    avatar: user.avatar,
    token: null,
    status: 'offline',
    isStatic: true,
    createdAt: new Date().toISOString()
  })),
  messages: [
    {
      id: '1',
      sender: 'mustakim',
      senderName: 'Mustakim',
      content: 'Hello everyone! 👋 Welcome to our WhatsApp Clone!',
      room: 'general',
      timestamp: new Date(Date.now() - 3600000).toISOString(),
      isFile: false,
      avatar: '👨‍💻'
    },
    {
      id: '2', 
      sender: 'taniya',
      senderName: 'Taniya',
      content: 'Hey Mustakim! This app looks amazing! 🚀',
      room: 'general',
      timestamp: new Date(Date.now() - 1800000).toISOString(),
      isFile: false,
      avatar: '😎'
    },
    {
      id: '3',
      sender: 'aliya',
      senderName: 'Aliya',
      content: 'I love the design! Great work everyone! 💫',
      room: 'general',
      timestamp: new Date(Date.now() - 900000).toISOString(),
      isFile: false,
      avatar: '👩‍💼'
    },
    {
      id: '4',
      sender: 'saniya',
      senderName: 'Saniya',
      content: 'Ready to chat with all of you! ✅',
      room: 'general', 
      timestamp: new Date().toISOString(),
      isFile: false,
      avatar: '👑'
    }
  ],
  rooms: ['general', 'random', 'help', 'tech', 'games', 'social'],
  // Track active WebSocket connections
  activeConnections: new Map()
};

// Enhanced Database service with delete functionality
class DatabaseService {
  constructor() {
    this.db = this.getMemoryDB();
  }

  async connect() {
    console.log('💾 Using Memory Storage Database');
    return this.db;
  }

  getMemoryDB() {
    return {
      collection: (name) => this.getMemoryCollection(name),
      command: (cmd) => Promise.resolve({ ok: 1 })
    };
  }

  getMemoryCollection(name) {
    const collection = memoryStorage[name] || [];
    
    return {
      find: (query = {}) => ({
        toArray: () => {
          let results = [...collection];
          if (Object.keys(query).length > 0) {
            results = results.filter(item => {
              for (let key in query) {
                if (key === '$or') {
                  return query[key].some(condition => {
                    for (let orKey in condition) {
                      if (item[orKey] === condition[orKey]) return true;
                    }
                    return false;
                  });
                } else if (item[key] !== query[key]) {
                  return false;
                }
              }
              return true;
            });
          }
          return Promise.resolve(results);
        },
        sort: (sortCriteria) => ({
          toArray: () => {
            let results = [...collection];
            for (let key in sortCriteria) {
              results.sort((a, b) => {
                if (sortCriteria[key] === 1) {
                  return a[key] > b[key] ? 1 : -1;
                } else {
                  return a[key] < b[key] ? 1 : -1;
                }
              });
            }
            return Promise.resolve(results);
          }
        })
      }),

      findOne: (query = {}) => {
        const result = collection.find(item => {
          for (let key in query) {
            if (key === '$or') {
              return query[key].some(condition => {
                for (let orKey in condition) {
                  if (item[orKey] === condition[orKey]) return true;
                }
                return false;
              });
            } else if (item[key] !== query[key]) {
              return false;
            }
          }
          return true;
        });
        return Promise.resolve(result || null);
      },

      insertOne: (document) => {
        if (!memoryStorage[name]) memoryStorage[name] = [];
        document._id = document._id || uuid.v4();
        document.createdAt = new Date().toISOString();
        memoryStorage[name].push(document);
        return Promise.resolve({ 
          insertedId: document._id, 
          acknowledged: true 
        });
      },

      updateOne: (query, update) => {
        const index = collection.findIndex(item => {
          for (let key in query) {
            if (item[key] !== query[key]) return false;
          }
          return true;
        });

        if (index !== -1 && update.$set) {
          memoryStorage[name][index] = {
            ...memoryStorage[name][index],
            ...update.$set,
            updatedAt: new Date().toISOString()
          };
          return Promise.resolve({ 
            modifiedCount: 1, 
            acknowledged: true 
          });
        }
        return Promise.resolve({ 
          modifiedCount: 0, 
          acknowledged: true 
        });
      },

      deleteMany: (query = {}) => {
        const initialLength = collection.length;
        
        if (Object.keys(query).length === 0) {
          // Delete all documents
          memoryStorage[name] = [];
          return Promise.resolve({ 
            deletedCount: initialLength,
            acknowledged: true 
          });
        } else {
          // Delete documents matching query
          const remaining = collection.filter(item => {
            for (let key in query) {
              if (item[key] !== query[key]) {
                return true; // Keep this item
              }
            }
            return false; // Remove this item
          });
          
          const deletedCount = collection.length - remaining.length;
          memoryStorage[name] = remaining;
          
          return Promise.resolve({ 
            deletedCount: deletedCount,
            acknowledged: true 
          });
        }
      },

      countDocuments: (query = {}) => {
        let results = collection;
        if (Object.keys(query).length > 0) {
          results = results.filter(item => {
            for (let key in query) {
              if (item[key] !== query[key]) return false;
            }
            return true;
          });
        }
        return Promise.resolve(results.length);
      },

      distinct: (field) => {
        const values = [...new Set(collection.map(item => item[field]).filter(Boolean))];
        return Promise.resolve(values);
      }
    };
  }

  async close() {
    console.log('🔌 Database service closed');
  }
}

// Initialize database service
const database = new DatabaseService();

// ================== Express App Setup ==================
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ 
  server,
  // Add WebSocket server configuration
  perMessageDeflate: false,
  clientTracking: true
});

// ================== Middleware ==================
app.use(cors({
  origin: [
    'http://localhost:5173',
    'http://localhost:3000',
    'https://whatsapp-n8xf.vercel.app',
    'https://whatsapp-60un.onrender.com',
    'http://localhost:10000'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));

app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

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
  limits: { fileSize: 10 * 1024 * 1024 }
});

app.use('/uploads', express.static(UPLOAD_DIR));

// ================== Utility Functions ==================
function generateToken() {
  return uuid.v4();
}

function broadcastToAllClients(wss, data) {
  const message = JSON.stringify(data);
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN && client.isAuthenticated) {
      try {
        client.send(message);
      } catch (error) {
        console.error('Error broadcasting to client:', error);
      }
    }
  });
}

function broadcastToRoom(wss, room, data) {
  const message = JSON.stringify(data);
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN && client.isAuthenticated) {
      try {
        client.send(message);
      } catch (error) {
        console.error('Error broadcasting to client in room:', error);
      }
    }
  });
}

// ================== API Routes ==================

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'WhatsApp Clone API Server 🚀',
    version: '2.0.0',
    database: 'Memory Storage',
    staticUsers: Object.keys(STATIC_USERS),
    status: 'Running',
    timestamp: new Date().toISOString(),
    activeConnections: wss.clients.size
  });
});

// Health check with WebSocket status
app.get('/api/health', async (req, res) => {
  const db = await database.connect();
  
  res.json({
    success: true,
    status: 'Server is healthy 🟢',
    database: 'Memory Storage 🟢',
    staticUsers: Object.keys(STATIC_USERS).length,
    totalMessages: memoryStorage.messages.length,
    totalUsers: memoryStorage.users.length,
    activeConnections: wss.clients.size,
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()) + ' seconds'
  });
});

// Get Static Users Info
app.get('/api/static-users', (req, res) => {
  const usersInfo = Object.values(STATIC_USERS).map(user => ({
    username: user.username,
    displayName: user.displayName,
    avatar: user.avatar,
    email: user.email,
    password: user.password
  }));

  res.json({
    success: true,
    users: usersInfo,
    message: 'Use these credentials for instant login'
  });
});

// Quick Login - Direct login without password for static users
app.post('/api/quick-login', async (req, res) => {
  try {
    const { username } = req.body;

    if (!username) {
      return res.status(400).json({
        success: false,
        error: 'Username is required',
        availableUsers: Object.keys(STATIC_USERS)
      });
    }

    const staticUser = STATIC_USERS[username.toLowerCase()];
    if (!staticUser) {
      return res.status(400).json({
        success: false,
        error: `User '${username}' not found. Available users: ${Object.keys(STATIC_USERS).join(', ')}`
      });
    }

    const db = await database.connect();
    const users = db.collection('users');

    // Find the user
    let user = await users.findOne({ username: staticUser.username });

    // If user doesn't exist, create from static data
    if (!user) {
      user = {
        _id: staticUser.id,
        username: staticUser.username,
        email: staticUser.email,
        password_hash: bcrypt.hashSync(staticUser.password, 10),
        displayName: staticUser.displayName,
        avatar: staticUser.avatar,
        token: null,
        status: 'offline',
        isStatic: true,
        createdAt: new Date().toISOString()
      };
      await users.insertOne(user);
    }

    // Generate token
    const token = generateToken();

    // Update user status
    await users.updateOne(
      { username: staticUser.username },
      { 
        $set: { 
          token, 
          status: 'online',
          lastLogin: new Date().toISOString()
        } 
      }
    );

    console.log(`✅ Quick login: ${staticUser.displayName}`);

    res.json({
      success: true,
      message: `Welcome ${staticUser.displayName}! ${staticUser.avatar}`,
      user: {
        id: user._id,
        username: user.username,
        displayName: user.displayName,
        email: user.email,
        avatar: user.avatar,
        token: token,
        isStatic: true
      }
    });

  } catch (error) {
    console.error('Quick login error:', error);
    res.status(500).json({
      success: false,
      error: 'Quick login failed'
    });
  }
});

// File upload
app.post('/api/upload', upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'No file uploaded'
      });
    }

    const fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;

    res.json({
      success: true,
      message: 'File uploaded successfully',
      url: fileUrl,
      filename: req.file.filename
    });

  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({
      success: false,
      error: 'File upload failed'
    });
  }
});

// Regular Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password required'
      });
    }

    const db = await database.connect();
    const users = db.collection('users');

    // Find user by email or username
    const user = await users.findOne({ 
      $or: [{ email }, { username: email }] 
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // Check password
    const validPassword = await bcrypt.compare(password, user.password_hash);

    if (!validPassword) {
      return res.status(401).json({
        success: false,
        error: 'Invalid password'
      });
    }

    // Generate token
    const token = generateToken();

    // Update user
    await users.updateOne(
      { _id: user._id },
      { 
        $set: { 
          token, 
          status: 'online',
          lastLogin: new Date().toISOString()
        } 
      }
    );

    console.log('✅ User logged in:', user.displayName || user.username);

    res.json({
      success: true,
      message: `Welcome back, ${user.displayName || user.username}! ${user.avatar || '👋'}`,
      user: {
        id: user._id,
        username: user.username,
        displayName: user.displayName,
        email: user.email,
        avatar: user.avatar,
        token: token,
        isStatic: user.isStatic || false
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      error: 'Login failed'
    });
  }
});

// Get All Users
app.get('/api/users', async (req, res) => {
  try {
    const db = await database.connect();
    const users = await db.collection('users')
      .find({})
      .project({ password_hash: 0, token: 0 })
      .sort({ username: 1 })
      .toArray();

    res.json({
      success: true,
      users: users,
      count: users.length
    });

  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch users'
    });
  }
});

// Get Messages for Room
app.get('/api/messages/:room', async (req, res) => {
  try {
    const { room } = req.params;
    const db = await database.connect();
    const messages = await db.collection('messages')
      .find({ room })
      .sort({ timestamp: 1 })
      .toArray();

    res.json({
      success: true,
      room: room,
      messages: messages,
      count: messages.length
    });

  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch messages'
    });
  }
});

// Send Message
app.post('/api/messages', async (req, res) => {
  try {
    const { content, room = 'general' } = req.body;
    const token = req.headers.authorization;

    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required'
      });
    }

    if (!content || content.trim().length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Message content cannot be empty'
      });
    }

    const db = await database.connect();
    const users = db.collection('users');
    const messages = db.collection('messages');

    // Verify user
    const user = await users.findOne({ token });
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Invalid token'
      });
    }

    const messageData = {
      id: uuid.v4(),
      sender: user.username,
      senderName: user.displayName || user.username,
      content: content.trim(),
      room: room,
      timestamp: new Date().toISOString(),
      avatar: user.avatar,
      isFile: false
    };

    await messages.insertOne(messageData);

    res.json({
      success: true,
      message: 'Message sent successfully',
      data: messageData
    });

  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to send message'
    });
  }
});

// Clear all messages in a room
app.delete('/api/messages/:room', async (req, res) => {
  try {
    const { room } = req.params;
    const token = req.headers.authorization;

    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required'
      });
    }

    const db = await database.connect();
    const users = db.collection('users');
    const messages = db.collection('messages');

    // Verify user
    const user = await users.findOne({ token });
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Invalid token'
      });
    }

    // Delete all messages from the room
    const result = await messages.deleteMany({ room });

    console.log(`🗑️ API: Cleared ${result.deletedCount} messages from room: ${room} by user: ${user.username}`);

    // Broadcast clear event to all clients
    broadcastToAllClients(wss, {
      type: 'clear',
      room: room,
      clearedBy: user.username,
      clearedByName: user.displayName || user.username,
      timestamp: new Date().toISOString(),
      message: `Chat cleared by ${user.displayName || user.username}`
    });

    res.json({
      success: true,
      message: `Chat cleared successfully in room ${room}`,
      room: room,
      deletedCount: result.deletedCount,
      clearedBy: user.username,
      clearedByName: user.displayName || user.username,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Clear messages error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to clear messages'
    });
  }
});

// Clear all messages (admin only - optional)
app.delete('/api/messages', async (req, res) => {
  try {
    const token = req.headers.authorization;

    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required'
      });
    }

    const db = await database.connect();
    const users = db.collection('users');
    const messages = db.collection('messages');

    // Verify user
    const user = await users.findOne({ token });
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Invalid token'
      });
    }

    // Delete all messages
    const result = await messages.deleteMany({});

    console.log(`🗑️ API: Cleared ALL messages (${result.deletedCount}) by user: ${user.username}`);

    res.json({
      success: true,
      message: 'All messages cleared successfully',
      deletedCount: result.deletedCount,
      clearedBy: user.username,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Clear all messages error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to clear all messages'
    });
  }
});

// Get Rooms
app.get('/api/rooms', async (req, res) => {
  try {
    const rooms = ['general', 'random', 'help', 'tech', 'games', 'social'];
    res.json({
      success: true,
      rooms: rooms
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to fetch rooms'
    });
  }
});

// ================== WebSocket Handling ==================
wss.on('connection', (ws, req) => {
  console.log('🔌 New WebSocket connection');
  console.log(`📊 Total connections: ${wss.clients.size}`);
  
  ws.user = null;
  ws.isAuthenticated = false;
  ws.connectionId = uuid.v4();
  ws.lastPing = Date.now();

  // Set up ping-pong to keep connection alive
  const pingInterval = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) {
      try {
        ws.ping();
        ws.lastPing = Date.now();
      } catch (error) {
        console.error('Error sending ping:', error);
        clearInterval(pingInterval);
      }
    } else {
      clearInterval(pingInterval);
    }
  }, 30000); // Ping every 30 seconds

  ws.on('pong', () => {
    ws.lastPing = Date.now();
  });

  ws.on('message', async (data) => {
    try {
      const message = JSON.parse(data.toString());

      // Authentication
      if (message.type === 'auth') {
        const db = await database.connect();
        const users = db.collection('users');
        const user = await users.findOne({ token: message.token });
        
        if (user) {
          ws.user = user;
          ws.isAuthenticated = true;
          
          // Update user status to online
          await users.updateOne(
            { _id: user._id },
            { $set: { status: 'online' } }
          );

          // Get online users
          const onlineUsers = await users.find({ status: 'online' })
            .project({ username: 1, displayName: 1, avatar: 1 })
            .toArray();

          ws.send(JSON.stringify({
            type: 'authSuccess',
            user: {
              username: user.username,
              displayName: user.displayName,
              email: user.email,
              avatar: user.avatar
            },
            rooms: ['general', 'random', 'help', 'tech', 'games', 'social'],
            users: onlineUsers
          }));

          console.log('✅ WebSocket authenticated:', user.displayName || user.username);

          // Notify other users about new user online
          broadcastToAllClients(wss, {
            type: 'users',
            data: onlineUsers
          });
        } else {
          ws.send(JSON.stringify({
            type: 'authError',
            error: 'Authentication failed'
          }));
        }
      }

      // Send message
      if (message.type === 'message' && ws.isAuthenticated && ws.user) {
        const db = await database.connect();
        const messages = db.collection('messages');

        const messageData = {
          id: uuid.v4(),
          sender: ws.user.username,
          senderName: ws.user.displayName || ws.user.username,
          content: message.content,
          room: message.room || 'general',
          timestamp: new Date().toISOString(),
          avatar: ws.user.avatar,
          isFile: message.isFile || false,
          fileType: message.fileType || ''
        };

        await messages.insertOne(messageData);

        // Broadcast to all connected clients
        broadcastToAllClients(wss, {
          type: 'message',
          data: messageData
        });

        console.log(`💬 Message from ${ws.user.displayName} in ${messageData.room}`);
      }

      // Clear chat messages for a room
      if (message.type === 'clear' && ws.isAuthenticated && ws.user) {
        const db = await database.connect();
        const messages = db.collection('messages');
        const room = message.room || 'general';

        console.log(`🗑️ Clearing chat for room: ${room} by user: ${ws.user.username}`);

        // Delete all messages from the specified room
        const result = await messages.deleteMany({ room: room });

        // Broadcast clear event to all connected clients
        broadcastToAllClients(wss, {
          type: 'clear',
          room: room,
          clearedBy: ws.user.username,
          clearedByName: ws.user.displayName || ws.user.username,
          timestamp: new Date().toISOString(),
          message: `Chat cleared by ${ws.user.displayName || ws.user.username}`,
          deletedCount: result.deletedCount
        });

        console.log(`✅ Chat cleared for room ${room}. Removed ${result.deletedCount} messages`);
      }

      // Typing indicator
      if (message.type === 'typing' && ws.isAuthenticated) {
        const broadcastData = {
          type: 'typing',
          username: ws.user.username,
          displayName: ws.user.displayName || ws.user.username,
          typing: message.typing,
          room: message.room
        };

        broadcastToRoom(wss, message.room, broadcastData);
      }

      // Connection check
      if (message.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
      }

    } catch (error) {
      console.error('WebSocket message error:', error);
      try {
        ws.send(JSON.stringify({
          type: 'error',
          error: 'Invalid message format'
        }));
      } catch (sendError) {
        console.error('Error sending error message:', sendError);
      }
    }
  });

  ws.on('close', async (code, reason) => {
    console.log(`🔌 WebSocket disconnected: ${code} - ${reason}`);
    console.log(`📊 Remaining connections: ${wss.clients.size}`);
    
    clearInterval(pingInterval);

    if (ws.user) {
      console.log('👤 User disconnected:', ws.user.displayName || ws.user.username);
      
      // Update user status to offline after a delay
      setTimeout(async () => {
        const db = await database.connect();
        const users = db.collection('users');
        
        // Check if user has reconnected
        const currentUser = await users.findOne({ _id: ws.user._id });
        if (currentUser && currentUser.status === 'online') {
          // User might have reconnected, don't set to offline
          return;
        }
        
        await users.updateOne(
          { _id: ws.user._id },
          { $set: { status: 'offline' } }
        );

        // Get updated online users list
        const onlineUsers = await users.find({ status: 'online' })
          .project({ username: 1, displayName: 1, avatar: 1 })
          .toArray();

        // Broadcast updated users list
        broadcastToAllClients(wss, {
          type: 'users',
          data: onlineUsers
        });
      }, 5000); // 5 second delay
    }
  });

  ws.on('error', (error) => {
    console.error('❌ WebSocket error:', error);
  });

  // Send welcome message
  ws.send(JSON.stringify({
    type: 'connection',
    status: 'connected',
    message: 'WebSocket connected successfully',
    connectionId: ws.connectionId
  }));
});

// ================== Error Handling ==================
app.use((error, req, res, next) => {
  console.error('🚨 Server error:', error);
  res.status(500).json({
    success: false,
    error: 'Internal server error'
  });
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found: ' + req.originalUrl
  });
});

// ================== Start Server ==================
const PORT = process.env.PORT || 10000;

server.listen(PORT, '0.0.0.0', () => {
  console.log('='.repeat(70));
  console.log(`🚀 WhatsApp Server Running on Port ${PORT}`);
  console.log(`🌐 URL: http://localhost:${PORT}`);
  console.log(`💾 Database: Memory Storage 🟢`);
  console.log(`👥 Static Users: ${Object.keys(STATIC_USERS).join(', ')}`);
  console.log(`🎯 Quick Login: POST /api/quick-login`);
  console.log(`🗑️ Clear Chat: DELETE /api/messages/:room`);
  console.log(`✅ Health: http://localhost:${PORT}/api/health`);
  console.log('='.repeat(70));
  
  // Display static users info
  console.log('\n📋 Available Static Users (Password: 123456):');
  Object.values(STATIC_USERS).forEach(user => {
    console.log(`   ${user.avatar} ${user.displayName} (${user.username}) - ${user.email}`);
  });
  console.log('\n💡 Usage:');
  console.log('   Quick Login: POST /api/quick-login with {"username": "mustakim"}');
  console.log('   Regular Login: POST /api/login with {"email": "mustakim@gmail.com", "password": "123456"}');
  console.log('   Clear Chat: DELETE /api/messages/general or WebSocket "clear" message');
  console.log('='.repeat(70));
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🔄 Shutting down server gracefully...');
  
  // Close all WebSocket connections
  wss.clients.forEach(client => {
    client.close(1001, 'Server shutting down');
  });
  
  await database.close();
  process.exit(0);
});