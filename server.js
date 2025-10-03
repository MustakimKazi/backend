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
  users: Object.values(STATIC_USERS).map(user => ({
    ...user,
    password_hash: bcrypt.hashSync(user.password, 10),
    token: null,
    createdAt: new Date().toISOString(),
    lastLogin: null,
    lastLogout: null
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

// ================== Database Service with Fallback ==================
class DatabaseService {
  constructor() {
    this.client = null;
    this.db = null;
    this.isConnected = false;
    this.connectionString = "mongodb+srv://mohdmustakimkazi_db_user:HugPu2kIqGxOdhNF@whatsapp.dzac4go.mongodb.net/?retryWrites=true&w=majority&appName=whatsapp";
  }

  async connect() {
    if (this.isConnected && this.db) {
      return this.db;
    }

    try {
      console.log('🔗 Attempting MongoDB connection...');
      
      // Updated MongoDB connection with better SSL handling
      this.client = new MongoClient(this.connectionString, {
        serverSelectionTimeoutMS: 8000,
        connectTimeoutMS: 10000,
        socketTimeoutMS: 45000,
        maxPoolSize: 10,
        minPoolSize: 1,
        maxIdleTimeMS: 30000,
        retryWrites: true,
        retryReads: true,
        // Remove SSL validation for problematic environments
        tlsAllowInvalidCertificates: true,
        tlsAllowInvalidHostnames: true,
        // Alternative connection string without SSL
        useNewUrlParser: true,
        useUnifiedTopology: true
      });

      await this.client.connect();
      this.db = this.client.db('whatsapp');
      this.isConnected = true;
      
      console.log('✅ Connected to MongoDB Atlas');
      console.log(`📊 Database: ${this.db.databaseName}`);
      
      // Test the connection
      await this.db.command({ ping: 1 });
      console.log('✅ MongoDB ping successful');
      
      return this.db;
    } catch (error) {
      console.error('❌ MongoDB connection failed, using memory storage:', error.message);
      this.isConnected = false;
      this.db = null;
      // Don't throw error, fallback to memory storage
      return null;
    }
  }

  getCollection(name) {
    if (!this.isConnected || !this.db) {
      throw new Error('Database not connected. Using memory storage.');
    }
    return this.db.collection(name);
  }

  async close() {
    if (this.client && this.isConnected) {
      await this.client.close();
      this.isConnected = false;
      console.log('🔌 MongoDB connection closed');
    }
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

// Enhanced user status management with fallback
async function updateUserStatus(username, status) {
  try {
    // Try MongoDB first
    if (database.isConnected) {
      const users = database.getCollection('users');
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
    }
    
    // Always update memory storage
    const userIndex = memoryStorage.users.findIndex(u => u.username === username);
    if (userIndex !== -1) {
      memoryStorage.users[userIndex].status = status;
      if (status === 'offline') {
        memoryStorage.users[userIndex].lastSeen = new Date().toISOString();
        memoryStorage.users[userIndex].lastLogout = new Date().toISOString();
      } else {
        memoryStorage.users[userIndex].lastLogin = new Date().toISOString();
      }
    }
    
    console.log(`👤 ${username} is now ${status}`);
    
    // Get all users for broadcasting
    const allUsers = memoryStorage.users.map(user => ({
      ...user,
      password_hash: undefined // Remove sensitive data
    }));

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

// ================== API Routes ==================

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'WhatsApp Clone API Server 🚀',
    version: '2.0.0',
    database: database.isConnected ? 'MongoDB Atlas' : 'Memory Storage',
    staticUsers: Object.keys(STATIC_USERS),
    status: 'Running',
    timestamp: new Date().toISOString(),
    activeConnections: wss.clients.size
  });
});

// Health check with WebSocket status
app.get('/api/health', async (req, res) => {
  const dbStatus = database.isConnected ? 'MongoDB Atlas 🟢' : 'Memory Storage 🟡';
  
  res.json({
    success: true,
    status: 'Server is healthy 🟢',
    database: dbStatus,
    staticUsers: Object.keys(STATIC_USERS).length,
    totalMessages: memoryStorage.messages.length,
    totalUsers: memoryStorage.users.length,
    onlineUsers: memoryStorage.users.filter(u => u.status === 'online').length,
    activeConnections: wss.clients.size,
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()) + ' seconds'
  });
});

// Get ALL users with enhanced information
app.get('/api/users', async (req, res) => {
  try {
    const allUsers = memoryStorage.users.map(user => ({
      id: user.id,
      username: user.username,
      displayName: user.displayName,
      email: user.email,
      avatar: user.avatar,
      status: user.status,
      lastSeen: user.lastSeen,
      isStatic: user.isStatic,
      createdAt: user.createdAt
    }));

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

// ✅ FIXED LOGIN ENDPOINT - Works with memory storage
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password are required'
      });
    }

    // Find user in memory storage
    const user = memoryStorage.users.find(u => u.email === email.toLowerCase());

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

    // Update user status and token in memory storage
    user.token = token;
    user.status = 'online';
    user.lastLogin = new Date().toISOString();

    console.log(`✅ Login: ${user.displayName || user.username}`);

    res.json({
      success: true,
      message: `Welcome back ${user.displayName || user.username}!`,
      user: {
        id: user.id,
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
      error: 'Login failed. Please try again.'
    });
  }
});

// ✅ FIXED QUICK LOGIN ENDPOINT
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

    // Find user in memory storage
    let user = memoryStorage.users.find(u => u.username === staticUser.username);

    // Generate token
    const token = generateToken();

    // Update user status to online
    user.token = token;
    user.status = 'online';
    user.lastLogin = new Date().toISOString();

    console.log(`✅ Quick login: ${staticUser.displayName}`);

    res.json({
      success: true,
      message: `Welcome ${staticUser.displayName}! ${staticUser.avatar}`,
      user: {
        id: user.id,
        username: user.username,
        displayName: user.displayName,
        email: user.email,
        avatar: user.avatar,
        token: user.token,
        status: 'online',
        lastSeen: user.lastSeen,
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

// ✅ FIXED SIGNUP ENDPOINT
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

    // Check if user already exists in memory storage
    const existingUser = memoryStorage.users.find(u => 
      u.username === username.toLowerCase() || u.email === email.toLowerCase()
    );

    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: 'User with this username or email already exists'
      });
    }

    // Create new user in memory storage
    const newUser = {
      id: uuid.v4(),
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

    memoryStorage.users.push(newUser);

    console.log(`✅ New user registered: ${newUser.displayName}`);

    // Auto login after signup
    const token = generateToken();
    newUser.token = token;
    newUser.status = 'online';
    newUser.lastLogin = new Date().toISOString();

    res.status(201).json({
      success: true,
      message: `Welcome ${newUser.displayName}! Account created successfully.`,
      user: {
        id: newUser.id,
        username: newUser.username,
        displayName: newUser.displayName,
        email: newUser.email,
        avatar: newUser.avatar,
        token: token,
        status: 'online',
        lastSeen: newUser.lastSeen,
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

// Logout endpoint
app.post('/api/logout', async (req, res) => {
  try {
    const token = req.headers.authorization;
    
    if (!token) {
      return res.status(400).json({
        success: false,
        error: 'Token is required'
      });
    }

    // Find user in memory storage and logout
    const user = memoryStorage.users.find(u => u.token === token);
    if (user) {
      user.status = 'offline';
      user.lastSeen = new Date().toISOString();
      user.lastLogout = new Date().toISOString();
      user.token = null;

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

// Get messages for a room
app.get('/api/messages/:room', async (req, res) => {
  try {
    const { room } = req.params;
    const roomMessages = memoryStorage.messages.filter(m => m.room === room)
      .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

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
    res.json({
      success: true,
      rooms: memoryStorage.rooms,
      count: memoryStorage.rooms.length
    });

  } catch (error) {
    console.error('Get rooms error:', error);
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
        const user = memoryStorage.users.find(u => u.token === message.token);
        
        if (user) {
          ws.user = user;
          ws.isAuthenticated = true;
          ws.isActive = true;
          
          // Update user status to online
          user.status = 'online';
          user.lastLogin = new Date().toISOString();

          // Get ALL users for the client (remove sensitive data)
          const allUsers = memoryStorage.users.map(u => ({
            id: u.id,
            username: u.username,
            displayName: u.displayName,
            email: u.email,
            avatar: u.avatar,
            status: u.status,
            lastSeen: u.lastSeen,
            isStatic: u.isStatic
          }));

          const onlineUsers = allUsers.filter(u => u.status === 'online');
          
          // Store connection in active connections
          memoryStorage.activeConnections.set(user.username, {
            ws: ws,
            user: user,
            connectedAt: new Date().toISOString(),
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
            rooms: memoryStorage.rooms,
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

      // Handle other message types...

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
      
      // Update user status to offline after delay
      setTimeout(() => {
        const currentConnections = Array.from(memoryStorage.activeConnections.entries())
          .filter(([username, conn]) => username === ws.user.username);
        
        if (currentConnections.length === 0) {
          const user = memoryStorage.users.find(u => u.username === ws.user.username);
          if (user) {
            user.status = 'offline';
            user.lastSeen = new Date().toISOString();
            console.log(`👤 ${ws.user.username} set to offline`);
          }
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
  
  // Try to connect to MongoDB but don't fail if it doesn't work
  try {
    await database.connect();
    console.log(`💾 Database: MongoDB Atlas 🟢`);
  } catch (error) {
    console.log(`💾 Database: Memory Storage 🟡 (MongoDB not available)`);
  }
  
  console.log(`👥 Static Users: ${Object.keys(STATIC_USERS).join(', ')}`);
  console.log(`📊 Total Users: ${memoryStorage.users.length}`);
  console.log(`🎯 Quick Login: POST /api/quick-login`);
  console.log(`🔐 Regular Login: POST /api/login`);
  console.log(`📝 Sign Up: POST /api/signup`);
  console.log(`👤 All Users: GET /api/users`);
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
  
  // Set all users to offline in memory storage
  memoryStorage.users.forEach(user => {
    user.status = 'offline';
    user.lastSeen = new Date().toISOString();
  });
  
  wss.clients.forEach(client => {
    client.close(1001, 'Server shutting down');
  });
  
  await database.close();
  process.exit(0);
});