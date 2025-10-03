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
const { MongoClient } = require('mongodb');

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
  users: [], // ✅ ADDED BACK users array for compatibility
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
  messageSeenStatus: new Map(),
  userPresence: new Map()
};

// ================== MongoDB Database Service ==================
class DatabaseService {
  constructor() {
    this.client = null;
    this.db = null;
    this.connectionString = "mongodb+srv://mohdmustakimkazi_db_user:HugPu2kIqGxOdhNF@whatsapp.dzac4go.mongodb.net/?retryWrites=true&w=majority&appName=whatsapp";
  }

  async connect() {
    if (this.db) {
      return this.db;
    }

    try {
      console.log('🔗 Attempting MongoDB connection...');
      
      this.client = new MongoClient(this.connectionString, {
        serverSelectionTimeoutMS: 5000,
        connectTimeoutMS: 10000,
      });

      await this.client.connect();
      this.db = this.client.db('whatsapp');
      
      console.log('✅ Connected to MongoDB Atlas');
      console.log(`📊 Database: ${this.db.databaseName}`);
      
      await this.db.command({ ping: 1 });
      console.log('✅ MongoDB ping successful');
      
      return this.db;
    } catch (error) {
      console.error('❌ MongoDB connection error:', error.message);
      throw error;
    }
  }

  getCollection(name) {
    if (!this.db) {
      throw new Error('Database not connected. Call connect() first.');
    }
    return this.db.collection(name);
  }

  async close() {
    if (this.client) {
      await this.client.close();
      console.log('🔌 MongoDB connection closed');
    }
  }
}

// Initialize database service
const database = new DatabaseService();

// Initialize static users in MongoDB
async function initializeStaticUsers() {
  try {
    const db = await database.connect();
    const users = database.getCollection('users');

    for (const staticUser of Object.values(STATIC_USERS)) {
      const existingUser = await users.findOne({ username: staticUser.username });
      
      if (!existingUser) {
        const newUser = {
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
          createdAt: new Date().toISOString(),
          lastLogin: null,
          lastLogout: null
        };

        await users.insertOne(newUser);
        console.log(`✅ Created static user in MongoDB: ${staticUser.username}`);
      } else {
        console.log(`✅ Static user already exists: ${staticUser.username}`);
      }
    }

    const totalUsers = await users.countDocuments();
    console.log(`📊 Total users in MongoDB: ${totalUsers}`);
    
  } catch (error) {
    console.error('Error initializing static users in MongoDB:', error);
  }
}

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
async function updateUserStatus(username, status) {
  try {
    const users = database.getCollection('users'); // ✅ FIXED: use getCollection
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
async function getOnlineUsersCount() {
  const users = database.getCollection('users'); // ✅ FIXED: use getCollection
  const onlineUsers = await users.find({ status: 'online' }).toArray();
  return onlineUsers.length;
}

// Handle typing indicators
function handleTypingUpdate(username, room, isTyping) {
  if (isTyping) {
    if (!memoryStorage.typingUsers.has(room)) {
      memoryStorage.typingUsers.set(room, new Set());
    }
    memoryStorage.typingUsers.get(room).add(username);
  } else {
    if (memoryStorage.typingUsers.has(room)) {
      memoryStorage.typingUsers.get(room).delete(username);
    }
  }
  
  const typingUsers = memoryStorage.typingUsers.has(room) 
    ? Array.from(memoryStorage.typingUsers.get(room)) 
    : [];
  
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
    const messages = database.getCollection('messages'); // ✅ FIXED: use getCollection
    
    const message = memoryStorage.messages.find(m => m.id === messageId);
    if (message) {
      if (!message.seenBy) {
        message.seenBy = [];
      }
      if (!message.seenBy.includes(username)) {
        message.seenBy.push(username);
        
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
    database: 'MongoDB Atlas',
    staticUsers: Object.keys(STATIC_USERS),
    status: 'Running',
    timestamp: new Date().toISOString(),
    activeConnections: wss.clients.size
  });
});

// Health check with WebSocket status
app.get('/api/health', async (req, res) => {
  try {
    await database.connect();
    const users = database.getCollection('users'); // ✅ FIXED: use getCollection
    const allUsers = await users.find({}).toArray();
    const onlineCount = allUsers.filter(u => u.status === 'online').length;
    
    res.json({
      success: true,
      status: 'Server is healthy 🟢',
      database: 'MongoDB Atlas 🟢',
      staticUsers: Object.keys(STATIC_USERS).length,
      totalMessages: memoryStorage.messages.length,
      totalUsers: allUsers.length,
      onlineUsers: onlineCount,
      activeConnections: wss.clients.size,
      timestamp: new Date().toISOString(),
      uptime: Math.floor(process.uptime()) + ' seconds'
    });
  } catch (error) {
    res.json({
      success: true,
      status: 'Server is healthy 🟢',
      database: 'Memory Storage (MongoDB failed)',
      staticUsers: Object.keys(STATIC_USERS).length,
      totalMessages: memoryStorage.messages.length,
      activeConnections: wss.clients.size,
      timestamp: new Date().toISOString(),
      uptime: Math.floor(process.uptime()) + ' seconds'
    });
  }
});

// Get ALL users with enhanced information
app.get('/api/users', async (req, res) => {
  try {
    await database.connect();
    const users = database.getCollection('users'); // ✅ FIXED: use getCollection
    const allUsers = await users.find({})
      .project({ password_hash: 0, token: 0 })
      .sort({ username: 1 })
      .toArray();

    console.log(`📊 Sending ${allUsers.length} users to client`);

    const onlineCount = allUsers.filter(u => u.status === 'online').length;

    res.json({
      success: true,
      users: allUsers,
      count: allUsers.length,
      onlineCount: onlineCount,
      offlineCount: allUsers.length - onlineCount,
      message: `Found ${allUsers.length} users (${onlineCount} online)`
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
    await database.connect();
    const users = database.getCollection('users'); // ✅ FIXED: use getCollection
    
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

    await database.connect();
    const users = database.getCollection('users'); // ✅ FIXED: use getCollection

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
        createdAt: new Date().toISOString(),
        lastLogin: null,
        lastLogout: null
      };
      await users.insertOne(user);
      console.log(`✅ Created static user: ${staticUser.username}`);
    }

    // Generate token
    const token = generateToken();

    // Update user status to online
    await updateUserStatus(staticUser.username, 'online');
    
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

// ✅ REGULAR LOGIN ENDPOINT - FIXED
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password are required'
      });
    }

    await database.connect();
    const users = database.getCollection('users'); // ✅ FIXED: use getCollection

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

    await updateUserStatus(user.username, 'online');

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

    await database.connect();
    const users = database.getCollection('users'); // ✅ FIXED: use getCollection

    const user = await users.findOne({ token: token });

    if (user) {
      await updateUserStatus(user.username, 'offline');
      
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

// ✅ SIGNUP ENDPOINT - FIXED
app.post('/api/signup', async (req, res) => {
  try {
    const { username, email, password, displayName, avatar = '👤' } = req.body;

    console.log('📝 Signup attempt:', { username, email, displayName });

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Username, email and password are required'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        error: 'Password must be at least 6 characters long'
      });
    }

    if (!/\S+@\S+\.\S+/.test(email)) {
      return res.status(400).json({
        success: false,
        error: 'Please enter a valid email address'
      });
    }

    await database.connect();
    const users = database.getCollection('users'); // ✅ FIXED: use getCollection

    // Check if user already exists
    const existingUser = await users.findOne({
      $or: [
        { username: username.toLowerCase() },
        { email: email.toLowerCase() }
      ]
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: 'User with this username or email already exists'
      });
    }

    // Create new user
    const newUser = {
      _id: uuid.v4(),
      username: username.toLowerCase(),
      email: email.toLowerCase(),
      password_hash: bcrypt.hashSync(password, 10),
      displayName: displayName || username,
      avatar: avatar,
      token: null,
      status: 'offline',
      lastSeen: new Date().toISOString(),
      isStatic: false,
      createdAt: new Date().toISOString(),
      lastLogin: null,
      lastLogout: null
    };

    await users.insertOne(newUser);

    console.log(`✅ New user registered: ${newUser.displayName}`);

    // Auto login after signup
    const token = generateToken();
    
    await updateUserStatus(newUser.username, 'online');
    
    await users.updateOne(
      { username: newUser.username },
      { 
        $set: { 
          token: token,
          lastLogin: new Date().toISOString()
        } 
      }
    );

    // Get updated user data
    const updatedUser = await users.findOne({ username: newUser.username });

    res.status(201).json({
      success: true,
      message: `Welcome ${newUser.displayName}! Account created successfully.`,
      user: {
        id: updatedUser._id,
        username: updatedUser.username,
        displayName: updatedUser.displayName,
        email: updatedUser.email,
        avatar: updatedUser.avatar,
        token: token,
        status: 'online',
        lastSeen: updatedUser.lastSeen,
        isStatic: false
      }
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({
      success: false,
      error: 'Registration failed. Please try again.'
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
    await database.connect();
    const messages = database.getCollection('messages'); // ✅ FIXED: use getCollection

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
    await database.connect();
    const rooms = database.getCollection('rooms'); // ✅ FIXED: use getCollection

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
    await database.connect();
    const messages = database.getCollection('messages'); // ✅ FIXED: use getCollection

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
  ws.isActive = true;

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
        await database.connect();
        const users = database.getCollection('users'); // ✅ FIXED: use getCollection
        const user = await users.findOne({ token: message.token });
        
        if (user) {
          ws.user = user;
          ws.isAuthenticated = true;
          ws.isActive = true;
          
          // Update user status to online
          await updateUserStatus(user.username, 'online');

          // Get ALL users for the client
          const allUsers = await users.find({})
            .project({ password_hash: 0, token: 0 })
            .toArray();

          const onlineUsers = allUsers.filter(u => u.status === 'online');
          
          // Store connection in active connections
          memoryStorage.activeConnections.set(user.username, {
            ws: ws,
            user: user,
            connectedAt: new Date().toISOString(),
            isActive: true
          });

          // Store user presence
          memoryStorage.userPresence.set(user.username, {
            status: 'online',
            lastActive: new Date().toISOString(),
            isActive: true
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

      // ... rest of WebSocket message handling remains the same
      // (User activity, typing, message seen, etc.)

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
      
      // Update user presence to away
      if (memoryStorage.userPresence.has(ws.user.username)) {
        memoryStorage.userPresence.set(ws.user.username, {
          ...memoryStorage.userPresence.get(ws.user.username),
          isActive: false,
          lastActive: new Date().toISOString()
        });
      }
      
      // Update user status to offline after a short delay
      setTimeout(async () => {
        const currentConnections = Array.from(memoryStorage.activeConnections.entries())
          .filter(([username, conn]) => username === ws.user.username);
        
        if (currentConnections.length === 0) {
          await updateUserStatus(ws.user.username, 'offline');
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
    features: {
      pushNotifications: true,
      typingIndicators: true,
      autoReconnect: true,
      userPresence: true
    }
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

server.listen(PORT, '0.0.0.0', async () => {
  console.log('='.repeat(70));
  console.log(`🚀 WhatsApp Server Running on Port ${PORT}`);
  console.log(`🌐 URL: http://localhost:${PORT}`);
  
  try {
    await database.connect();
    await initializeStaticUsers();
    
    console.log(`💾 Database: MongoDB Atlas 🟢`);
    console.log(`👥 Static Users: ${Object.keys(STATIC_USERS).join(', ')}`);
    
    const usersCollection = database.getCollection('users');
    const totalUsers = await usersCollection.countDocuments();
    console.log(`📊 Total Users in Database: ${totalUsers}`);
    
  } catch (error) {
    console.error('❌ Failed to initialize database:', error);
    console.log(`💾 Database: Memory Storage (MongoDB failed)`);
  }

  console.log(`🎯 Quick Login: POST /api/quick-login`);
  console.log(`🔐 Regular Login: POST /api/login`);
  console.log(`📝 Sign Up: POST /api/signup`);
  console.log(`👤 All Users: GET /api/users`);
  console.log(`📈 Online Users: GET /api/online-users`);
  console.log(`✅ Health: http://localhost:${PORT}/api/health`);
  console.log('='.repeat(70));
  
  console.log('\n📋 Available Static Users (Password: 123456):');
  Object.values(STATIC_USERS).forEach(user => {
    console.log(`   ${user.avatar} ${user.displayName} (${user.username}) - ${user.email}`);
  });
  console.log('='.repeat(70));
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🔄 Shutting down server gracefully...');
  
  try {
    const users = database.getCollection('users');
    await users.updateMany(
      { status: 'online' },
      { 
        $set: { 
          status: 'offline',
          lastSeen: new Date().toISOString()
        } 
      }
    );
    console.log('✅ All users set to offline in MongoDB');
  } catch (error) {
    console.error('Error setting users offline in MongoDB:', error);
  }
  
  wss.clients.forEach(client => {
    client.close(1001, 'Server shutting down');
  });
  
  await database.close();
  process.exit(0);
});