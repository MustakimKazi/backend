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

// ================== Static Users Configuration ==================
const STATIC_USERS = {
  mustakim: {
    id: '1',
    username: 'mustakim',
    email: 'mustakim@gmail.com',
    password: '123456',
    displayName: 'Mustakim',
    avatar: '👨‍💻',
    status: 'offline',
    lastSeen: new Date().toISOString(),
    isStatic: true
  },
  taniya: {
    id: '2',
    username: 'taniya',
    email: 'taniya@gmail.com',
    password: '123456',
    displayName: 'Taniya',
    avatar: '😎',
    status: 'offline',
    lastSeen: new Date().toISOString(),
    isStatic: true
  },
  aliya: {
    id: '3', 
    username: 'aliya',
    email: 'aliya@gmail.com',
    password: '123456',
    displayName: 'Aliya',
    avatar: '👩‍💼',
    status: 'offline',
    lastSeen: new Date().toISOString(),
    isStatic: true
  },
  saniya: {
    id: '4',
    username: 'saniya',
    email: 'saniya@gmail.com',
    password: '123456',
    displayName: 'Saniya',
    avatar: '👑',
    status: 'offline',
    lastSeen: new Date().toISOString(),
    isStatic: true
  }
};

// ================== Memory Storage ==================
const memoryStorage = {
  users: [],
  messages: [
    {
      id: '1',
      sender: 'mustakim',
      senderName: 'Mustakim',
      content: 'Hello everyone! 👋 Welcome to our WhatsApp Clone!',
      room: 'general',
      timestamp: new Date(Date.now() - 3600000).toISOString(),
      isFile: false,
      avatar: '👨‍💻',
      seenBy: ['mustakim', 'taniya', 'aliya']
    },
    {
      id: '2', 
      sender: 'taniya',
      senderName: 'Taniya',
      content: 'Hey Mustakim! This app looks amazing! 🚀',
      room: 'general',
      timestamp: new Date(Date.now() - 1800000).toISOString(),
      isFile: false,
      avatar: '😎',
      seenBy: ['mustakim', 'taniya']
    },
    {
      id: '3',
      sender: 'aliya',
      senderName: 'Aliya',
      content: 'I love the design! Great work everyone! 💫',
      room: 'general',
      timestamp: new Date(Date.now() - 900000).toISOString(),
      isFile: false,
      avatar: '👩‍💼',
      seenBy: ['mustakim']
    },
    {
      id: '4',
      sender: 'saniya',
      senderName: 'Saniya',
      content: 'Ready to chat with all of you! ✅',
      room: 'general', 
      timestamp: new Date().toISOString(),
      isFile: false,
      avatar: '👑',
      seenBy: []
    }
  ],
  rooms: ['general', 'random', 'help', 'tech', 'games', 'social'],
  activeConnections: new Map(),
  typingUsers: new Map(),
  messageSeenStatus: new Map() // Track seen status for messages
};

// Initialize static users
function initializeStaticUsers() {
  console.log('📝 Initializing static users...');
  memoryStorage.users = Object.values(STATIC_USERS).map(user => ({
    _id: user.id,
    username: user.username,
    email: user.email,
    password_hash: bcrypt.hashSync(user.password, 10),
    displayName: user.displayName,
    avatar: user.avatar,
    token: null,
    status: 'offline',
    lastSeen: new Date().toISOString(),
    isStatic: true,
    createdAt: new Date().toISOString(),
    lastLogin: null,
    lastLogout: null
  }));
  console.log(`✅ Initialized ${memoryStorage.users.length} static users`);
}

// Call initialization
initializeStaticUsers();

// Enhanced Database service
class DatabaseService {
  constructor() {
    this.db = this.getMemoryDB();
  }

  async connect() {
    console.log('💾 Using Memory Storage Database');
    console.log(`📊 Total users in memory: ${memoryStorage.users.length}`);
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

      updateMany: (query, update) => {
        let modifiedCount = 0;
        collection.forEach((item, index) => {
          let shouldUpdate = true;
          for (let key in query) {
            if (item[key] !== query[key]) {
              shouldUpdate = false;
              break;
            }
          }
          if (shouldUpdate && update.$set) {
            memoryStorage[name][index] = {
              ...memoryStorage[name][index],
              ...update.$set,
              updatedAt: new Date().toISOString()
            };
            modifiedCount++;
          }
        });
        return Promise.resolve({ 
          modifiedCount: modifiedCount, 
          acknowledged: true 
        });
      },

      deleteMany: (query = {}) => {
        const initialLength = collection.length;
        if (Object.keys(query).length === 0) {
          memoryStorage[name] = [];
          return Promise.resolve({ 
            deletedCount: initialLength,
            acknowledged: true 
          });
        } else {
          const remaining = collection.filter(item => {
            for (let key in query) {
              if (item[key] !== query[key]) {
                return true;
              }
            }
            return false;
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

function broadcastToRoom(wss, room, data, excludeUser = null) {
  const message = JSON.stringify(data);
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN && 
        client.isAuthenticated && 
        (!excludeUser || client.user.username !== excludeUser)) {
      try {
        client.send(message);
      } catch (error) {
        console.error('Error broadcasting to client in room:', error);
      }
    }
  });
}

// Enhanced user status management
async function updateUserStatus(username, status, db) {
  try {
    const users = db.collection('users');
    const updateData = { 
      status: status,
      ...(status === 'offline' ? { 
        lastSeen: new Date().toISOString(),
        lastLogout: new Date().toISOString()
      } : {
        lastLogin: new Date().toISOString()
      })
    };
    
    await users.updateOne(
      { username: username },
      { $set: updateData }
    );
    
    console.log(`👤 ${username} is now ${status}`);
    
    // Get all users for broadcasting
    const allUsers = await users.find({})
      .project({ password_hash: 0, token: 0 })
      .toArray();

    const onlineUsers = allUsers.filter(u => u.status === 'online');
    
    // Broadcast user status update to all clients
    broadcastToAllClients(wss, {
      type: 'userStatusUpdate',
      users: allUsers,
      onlineCount: onlineUsers.length,
      totalUsers: allUsers.length,
      timestamp: new Date().toISOString()
    });
    
    return true;
  } catch (error) {
    console.error('Error updating user status:', error);
    return false;
  }
}

// Get online users count
async function getOnlineUsersCount(db) {
  const users = db.collection('users');
  const onlineUsers = await users.find({ status: 'online' }).toArray();
  return onlineUsers.length;
}

// Handle typing indicators
function handleTypingUpdate(username, room, isTyping) {
  if (isTyping) {
    // Add user to typing list for this room
    if (!memoryStorage.typingUsers.has(room)) {
      memoryStorage.typingUsers.set(room, new Set());
    }
    memoryStorage.typingUsers.get(room).add(username);
  } else {
    // Remove user from typing list for this room
    if (memoryStorage.typingUsers.has(room)) {
      memoryStorage.typingUsers.get(room).delete(username);
    }
  }
  
  // Get current typing users for this room
  const typingUsers = memoryStorage.typingUsers.has(room) 
    ? Array.from(memoryStorage.typingUsers.get(room)) 
    : [];
  
  // Broadcast typing update to all clients in the room (except the typing user)
  broadcastToRoom(wss, room, {
    type: 'typingUpdate',
    room: room,
    typingUsers: typingUsers,
    isTyping: isTyping,
    username: username,
    timestamp: new Date().toISOString()
  }, username);
  
  console.log(`⌨️ ${username} ${isTyping ? 'started' : 'stopped'} typing in ${room}. Currently typing: ${typingUsers.join(', ')}`);
}

// Handle message seen status
function handleMessageSeen(username, room, messageId) {
  try {
    const db = database.connect();
    const messages = db.collection('messages');
    
    // Find the message
    const message = memoryStorage.messages.find(m => m.id === messageId);
    if (message) {
      // Add user to seenBy array if not already there
      if (!message.seenBy) {
        message.seenBy = [];
      }
      if (!message.seenBy.includes(username)) {
        message.seenBy.push(username);
        
        // Broadcast seen update to all clients in the room
        broadcastToRoom(wss, room, {
          type: 'messageSeen',
          room: room,
          messageId: messageId,
          seenBy: message.seenBy,
          seenByUser: username,
          timestamp: new Date().toISOString()
        });
        
        console.log(`👀 ${username} saw message ${messageId}`);
      }
    }
  } catch (error) {
    console.error('Error updating message seen status:', error);
  }
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
    totalUsers: memoryStorage.users.length,
    status: 'Running',
    timestamp: new Date().toISOString(),
    activeConnections: wss.clients.size
  });
});

// Health check with WebSocket status
app.get('/api/health', async (req, res) => {
  const db = await database.connect();
  const users = db.collection('users');
  const allUsers = await users.find({}).toArray();
  const onlineCount = allUsers.filter(u => u.status === 'online').length;
  
  res.json({
    success: true,
    status: 'Server is healthy 🟢',
    database: 'Memory Storage 🟢',
    staticUsers: Object.keys(STATIC_USERS).length,
    totalMessages: memoryStorage.messages.length,
    totalUsers: allUsers.length,
    onlineUsers: onlineCount,
    activeConnections: wss.clients.size,
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()) + ' seconds'
  });
});

// Get ALL users with enhanced information
app.get('/api/users', async (req, res) => {
  try {
    const db = await database.connect();
    const users = await db.collection('users')
      .find({})
      .project({ password_hash: 0, token: 0 })
      .sort({ username: 1 })
      .toArray();

    console.log(`📊 Sending ${users.length} users to client`);

    const onlineCount = users.filter(u => u.status === 'online').length;

    res.json({
      success: true,
      users: users,
      count: users.length,
      onlineCount: onlineCount,
      offlineCount: users.length - onlineCount,
      message: `Found ${users.length} users (${onlineCount} online)`
    });

  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch users'
    });
  }
});

// Get online users specifically
app.get('/api/online-users', async (req, res) => {
  try {
    const db = await database.connect();
    const users = db.collection('users');
    
    const onlineUsers = await users.find({ status: 'online' })
      .project({ password_hash: 0, token: 0 })
      .toArray();
      
    const offlineUsers = await users.find({ status: 'offline' })
      .project({ password_hash: 0, token: 0 })
      .toArray();

    console.log(`📊 Online users: ${onlineUsers.length}, Offline users: ${offlineUsers.length}`);

    res.json({
      success: true,
      onlineCount: onlineUsers.length,
      offlineCount: offlineUsers.length,
      totalCount: memoryStorage.users.length,
      onlineUsers: onlineUsers,
      offlineUsers: offlineUsers,
      activeConnections: wss.clients.size,
      message: `${onlineUsers.length} users online, ${offlineUsers.length} offline`
    });

  } catch (error) {
    console.error('Get online users error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch online users'
    });
  }
});

// Get Static Users Info
app.get('/api/static-users', (req, res) => {
  const usersInfo = Object.values(STATIC_USERS).map(user => ({
    username: user.username,
    displayName: user.displayName,
    avatar: user.avatar,
    email: user.email,
    password: user.password,
    status: user.status,
    lastSeen: user.lastSeen
  }));

  res.json({
    success: true,
    users: usersInfo,
    count: usersInfo.length,
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
        lastSeen: new Date().toISOString(),
        isStatic: true,
        createdAt: new Date().toISOString()
      };
      await users.insertOne(user);
      console.log(`✅ Created static user: ${staticUser.username}`);
    }

    // Generate token
    const token = generateToken();

    // Update user status to online
    await updateUserStatus(staticUser.username, 'online', db);
    
    // Update token
    await users.updateOne(
      { username: staticUser.username },
      { 
        $set: { 
          token,
          lastLogin: new Date().toISOString()
        } 
      }
    );

    console.log(`✅ Quick login: ${staticUser.displayName}`);

    // Get updated user data
    const updatedUser = await users.findOne({ username: staticUser.username });

    res.json({
      success: true,
      message: `Welcome ${staticUser.displayName}! ${staticUser.avatar}`,
      user: {
        id: updatedUser._id,
        username: updatedUser.username,
        displayName: updatedUser.displayName,
        email: updatedUser.email,
        avatar: updatedUser.avatar,
        token: updatedUser.token,
        status: updatedUser.status,
        lastSeen: updatedUser.lastSeen,
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

// Regular login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password are required'
      });
    }

    const db = await database.connect();
    const users = db.collection('users');

    const user = await users.findOne({ email: email.toLowerCase() });

    if (!user) {
      return res.status(400).json({
        success: false,
        error: 'Invalid email or password'
      });
    }

    const isValidPassword = bcrypt.compareSync(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(400).json({
        success: false,
        error: 'Invalid email or password'
      });
    }

    const token = generateToken();

    await updateUserStatus(user.username, 'online', db);

    await users.updateOne(
      { email: email.toLowerCase() },
      { 
        $set: { 
          token,
          lastLogin: new Date().toISOString()
        } 
      }
    );

    console.log(`✅ Login: ${user.displayName || user.username}`);

    res.json({
      success: true,
      message: `Welcome back ${user.displayName || user.username}!`,
      user: {
        id: user._id,
        username: user.username,
        displayName: user.displayName,
        email: user.email,
        avatar: user.avatar,
        token: token,
        status: 'online',
        lastSeen: user.lastSeen,
        isStatic: user.isStatic
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

// Logout
app.post('/api/logout', async (req, res) => {
  try {
    const token = req.headers.authorization;
    
    if (!token) {
      return res.status(400).json({
        success: false,
        error: 'Token is required'
      });
    }

    const db = await database.connect();
    const users = db.collection('users');

    const user = await users.findOne({ token: token });

    if (user) {
      await updateUserStatus(user.username, 'offline', db);
      
      await users.updateOne(
        { token: token },
        { 
          $set: { 
            token: null,
            lastLogout: new Date().toISOString()
          } 
        }
      );

      console.log(`✅ Logout: ${user.displayName || user.username}`);
    }

    res.json({
      success: true,
      message: 'Logged out successfully'
    });

  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      error: 'Logout failed'
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
      url: fileUrl,
      filename: req.file.filename,
      originalname: req.file.originalname,
      size: req.file.size
    });

  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({
      success: false,
      error: 'File upload failed'
    });
  }
});

// Get messages for a room
app.get('/api/messages/:room', async (req, res) => {
  try {
    const { room } = req.params;
    const db = await database.connect();
    const messages = db.collection('messages');

    const roomMessages = await messages.find({ room: room })
      .sort({ timestamp: 1 })
      .toArray();

    console.log(`📨 Loaded ${roomMessages.length} messages for room: ${room}`);

    res.json({
      success: true,
      messages: roomMessages,
      count: roomMessages.length,
      room: room
    });

  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch messages'
    });
  }
});

// Get all rooms
app.get('/api/rooms', async (req, res) => {
  try {
    const db = await database.connect();
    const rooms = db.collection('rooms');

    const allRooms = await rooms.find({}).toArray();
    const roomNames = allRooms.length > 0 ? allRooms.map(r => r.name) : ['general'];

    res.json({
      success: true,
      rooms: roomNames,
      count: roomNames.length
    });

  } catch (error) {
    console.error('Get rooms error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch rooms'
    });
  }
});

// Clear messages in a room
app.delete('/api/messages/:room', async (req, res) => {
  try {
    const { room } = req.params;
    const db = await database.connect();
    const messages = db.collection('messages');

    const result = await messages.deleteMany({ room: room });

    console.log(`🗑️ Cleared ${result.deletedCount} messages from room: ${room}`);

    // Broadcast clear event to all clients
    broadcastToAllClients(wss, {
      type: 'clear',
      room: room,
      clearedBy: 'system',
      timestamp: new Date().toISOString()
    });

    res.json({
      success: true,
      message: `Cleared ${result.deletedCount} messages from ${room}`,
      clearedCount: result.deletedCount
    });

  } catch (error) {
    console.error('Clear messages error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to clear messages'
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
  }, 30000);

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
          await updateUserStatus(user.username, 'online', db);

          // Get ALL users for the client
          const allUsers = await users.find({})
            .project({ password_hash: 0, token: 0 })
            .toArray();

          const onlineUsers = allUsers.filter(u => u.status === 'online');
          
          // Store connection in active connections
          memoryStorage.activeConnections.set(user.username, {
            ws: ws,
            user: user,
            connectedAt: new Date().toISOString()
          });

          ws.send(JSON.stringify({
            type: 'authSuccess',
            user: {
              username: user.username,
              displayName: user.displayName,
              email: user.email,
              avatar: user.avatar,
              status: user.status,
              lastSeen: user.lastSeen,
              isStatic: user.isStatic
            },
            rooms: ['general', 'random', 'help', 'tech', 'games', 'social'],
            users: allUsers,
            onlineCount: onlineUsers.length,
            totalUsers: allUsers.length,
            message: `Connected successfully. ${onlineUsers.length} users online.`
          }));

          console.log(`✅ WebSocket authenticated: ${user.displayName || user.username}`);
          console.log(`📊 Sent ${allUsers.length} users to client (${onlineUsers.length} online)`);

        } else {
          ws.send(JSON.stringify({
            type: 'authError',
            error: 'Authentication failed'
          }));
        }
        return;
      }

      // Enhanced typing indicator
      if (message.type === 'typing') {
        if (ws.isAuthenticated && ws.user) {
          handleTypingUpdate(ws.user.username, message.room, message.typing);
        }
        return;
      }

      // Message seen status
      if (message.type === 'messageSeen') {
        if (ws.isAuthenticated && ws.user) {
          handleMessageSeen(ws.user.username, message.room, message.messageId);
        }
        return;
      }

      // User status update
      if (message.type === 'statusUpdate') {
        if (ws.isAuthenticated && ws.user) {
          await updateUserStatus(ws.user.username, message.status, db);
        }
        return;
      }

      // Handle new message
      if (message.type === 'message') {
        if (!ws.isAuthenticated || !ws.user) {
          ws.send(JSON.stringify({
            type: 'error',
            error: 'Not authenticated'
          }));
          return;
        }

        const db = await database.connect();
        const messages = db.collection('messages');

        const newMessage = {
          id: uuid.v4(),
          sender: ws.user.username,
          senderName: ws.user.displayName || ws.user.username,
          content: message.content,
          room: message.room || 'general',
          timestamp: new Date().toISOString(),
          isFile: message.isFile || false,
          fileType: message.fileType || null,
          avatar: ws.user.avatar,
          seenBy: [ws.user.username] // Sender automatically sees their own message
        };

        // Save to database
        await messages.insertOne(newMessage);

        // Broadcast to all clients in the room
        broadcastToRoom(wss, message.room || 'general', {
          type: 'message',
          data: newMessage
        });

        console.log(`📨 ${ws.user.username} sent message to ${message.room || 'general'}: ${message.content.substring(0, 50)}${message.content.length > 50 ? '...' : ''}`);

        // Stop typing indicator when message is sent
        handleTypingUpdate(ws.user.username, message.room || 'general', false);
        return;
      }

      // Handle clear chat
      if (message.type === 'clear') {
        if (!ws.isAuthenticated || !ws.user) {
          ws.send(JSON.stringify({
            type: 'error', 
            error: 'Not authenticated'
          }));
          return;
        }

        const db = await database.connect();
        const messages = db.collection('messages');

        const result = await messages.deleteMany({ room: message.room });

        // Broadcast clear event to all clients
        broadcastToAllClients(wss, {
          type: 'clear',
          room: message.room,
          clearedBy: ws.user.username,
          timestamp: new Date().toISOString()
        });

        console.log(`🗑️ ${ws.user.username} cleared ${result.deletedCount} messages from ${message.room}`);
        return;
      }

      // Handle ping
      if (message.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong' }));
        return;
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
      
      // Remove from active connections
      memoryStorage.activeConnections.delete(ws.user.username);
      
      // Remove from all typing lists
      memoryStorage.typingUsers.forEach((typingSet, room) => {
        if (typingSet.has(ws.user.username)) {
          typingSet.delete(ws.user.username);
          // Broadcast typing stop
          broadcastToRoom(wss, room, {
            type: 'typingUpdate',
            room: room,
            typingUsers: Array.from(typingSet),
            isTyping: false,
            username: ws.user.username,
            timestamp: new Date().toISOString()
          });
        }
      });
      
      // Update user status to offline after a short delay
      setTimeout(async () => {
        const db = await database.connect();
        
        // Check if user has reconnected
        const currentConnections = Array.from(memoryStorage.activeConnections.entries())
          .filter(([username, conn]) => username === ws.user.username);
        
        if (currentConnections.length === 0) {
          // User hasn't reconnected, set to offline
          await updateUserStatus(ws.user.username, 'offline', db);
          console.log(`👤 ${ws.user.username} set to offline`);
        } else {
          console.log(`👤 ${ws.user.username} reconnected, keeping online status`);
        }
      }, 5000);
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
    connectionId: ws.connectionId,
    totalUsers: memoryStorage.users.length
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
  console.log(`📊 Total Users in System: ${memoryStorage.users.length}`);
  console.log(`🎯 Quick Login: POST /api/quick-login`);
  console.log(`👤 All Users: GET /api/users`);
  console.log(`📈 Online Users: GET /api/online-users`);
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
  console.log('   All Users: GET /api/users');
  console.log('   Online Users: GET /api/online-users');
  console.log('='.repeat(70));
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🔄 Shutting down server gracefully...');
  
  // Set all online users to offline
  try {
    const db = await database.connect();
    const users = db.collection('users');
    
    await users.updateMany(
      { status: 'online' },
      { 
        $set: { 
          status: 'offline',
          lastSeen: new Date().toISOString()
        } 
      }
    );
    
    console.log('✅ All users set to offline');
  } catch (error) {
    console.error('Error setting users offline:', error);
  }
  
  // Close all WebSocket connections
  wss.clients.forEach(client => {
    client.close(1001, 'Server shutting down');
  });
  
  await database.close();
  process.exit(0);
});
