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
const { MongoClient, ObjectId } = require('mongodb');

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
    this.isConnected = false;
    this.connectionString = "mongodb+srv://mohdmustakimkazi_db_user:HugPu2kIqGxOdhNF@whatsapp.dzac4go.mongodb.net/?retryWrites=true&w=majority&appName=whatsapp";
  }

  async connect() {
    if (this.isConnected && this.db) {
      return this.db;
    }

    try {
      console.log('🔗 Attempting MongoDB connection...');
      
      this.client = new MongoClient(this.connectionString, {
        serverSelectionTimeoutMS: 8000,
        connectTimeoutMS: 10000,
        socketTimeoutMS: 45000,
        maxPoolSize: 10,
        retryWrites: true,
        retryReads: true
      });

      await this.client.connect();
      this.db = this.client.db('whatsapp');
      this.isConnected = true;
      
      console.log('✅ Connected to MongoDB Atlas');
      console.log(`📊 Database: ${this.db.databaseName}`);
      
      // Test the connection
      await this.db.command({ ping: 1 });
      console.log('✅ MongoDB ping successful');
      
      // Initialize collections
      await this.initializeCollections();
      
      return this.db;
    } catch (error) {
      console.error('❌ MongoDB connection failed:', error.message);
      this.isConnected = false;
      this.db = null;
      throw error;
    }
  }

  async initializeCollections() {
    try {
      // Create users collection and indexes
      const users = this.db.collection('users');
      await users.createIndex({ username: 1 }, { unique: true });
      await users.createIndex({ email: 1 }, { unique: true });
      await users.createIndex({ token: 1 });
      
      // Create messages collection and indexes
      const messages = this.db.collection('messages');
      await messages.createIndex({ room: 1 });
      await messages.createIndex({ timestamp: 1 });
      
      // Create rooms collection
      const rooms = this.db.collection('rooms');
      
      console.log('✅ Database collections initialized');
      
      // Initialize static users
      await this.initializeStaticUsers();
      
    } catch (error) {
      console.error('Error initializing collections:', error);
    }
  }

  async initializeStaticUsers() {
    try {
      const users = this.db.collection('users');
      
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
          console.log(`✅ Created static user: ${staticUser.username}`);
        }
      }

      // Initialize default rooms
      const rooms = this.db.collection('rooms');
      const defaultRooms = ['general', 'random', 'help', 'tech', 'games', 'social'];
      
      for (const roomName of defaultRooms) {
        const existingRoom = await rooms.findOne({ name: roomName });
        if (!existingRoom) {
          await rooms.insertOne({ 
            name: roomName, 
            createdAt: new Date().toISOString(),
            createdBy: 'system'
          });
        }
      }
      
      console.log('✅ Static users and rooms initialized');
      
    } catch (error) {
      console.error('Error initializing static users:', error);
    }
  }

  getCollection(name) {
    if (!this.isConnected || !this.db) {
      throw new Error('Database not connected');
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

function broadcastToAllClients(data) {
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

function broadcastToRoom(room, data, excludeUser = null) {
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

async function updateUserStatus(username, status) {
  try {
    const db = await database.connect();
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
    broadcastToAllClients({
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
  
  broadcastToRoom(room, {
    type: 'typingUpdate',
    room: room,
    typingUsers: typingUsers,
    isTyping: isTyping,
    username: username,
    timestamp: new Date().toISOString()
  }, username);
  
  console.log(`⌨️ ${username} ${isTyping ? 'started' : 'stopped'} typing in ${room}`);
}

// ================== API Routes ==================

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'WhatsApp Clone API Server 🚀',
    version: '2.0.0',
    database: database.isConnected ? 'MongoDB Atlas' : 'Disconnected',
    staticUsers: Object.keys(STATIC_USERS),
    status: 'Running',
    timestamp: new Date().toISOString(),
    activeConnections: wss.clients.size
  });
});

// Health check
app.get('/api/health', async (req, res) => {
  try {
    const db = await database.connect();
    const users = db.collection('users');
    const messages = db.collection('messages');
    
    const totalUsers = await users.countDocuments();
    const onlineUsers = await users.countDocuments({ status: 'online' });
    const totalMessages = await messages.countDocuments();
    
    res.json({
      success: true,
      status: 'Server is healthy 🟢',
      database: database.isConnected ? 'MongoDB Atlas 🟢' : 'Disconnected 🔴',
      staticUsers: Object.keys(STATIC_USERS).length,
      totalMessages: totalMessages,
      totalUsers: totalUsers,
      onlineUsers: onlineUsers,
      activeConnections: wss.clients.size,
      timestamp: new Date().toISOString(),
      uptime: Math.floor(process.uptime()) + ' seconds'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Database connection failed',
      details: error.message
    });
  }
});

// Get ALL users
app.get('/api/users', async (req, res) => {
  try {
    const db = await database.connect();
    const users = await db.collection('users')
      .find({})
      .project({ password_hash: 0, token: 0 })
      .sort({ username: 1 })
      .toArray();

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
          token: token,
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
      error: 'Quick login failed: ' + error.message
    });
  }
});

// ✅ FIXED REGULAR LOGIN
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

    await updateUserStatus(user.username, 'online');

    await users.updateOne(
      { email: email.toLowerCase() },
      { 
        $set: { 
          token: token,
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
        isStatic: user.isStatic || false
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      error: 'Login failed: ' + error.message
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

    const db = await database.connect();
    const users = db.collection('users');

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
      error: 'Registration failed: ' + error.message
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

    const db = await database.connect();
    const users = db.collection('users');

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
      error: 'Logout failed: ' + error.message
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
        const db = await database.connect();
        const users = db.collection('users');
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

          // Get rooms
          const roomsCollection = db.collection('rooms');
          const allRooms = await roomsCollection.find({}).toArray();
          const roomNames = allRooms.length > 0 ? allRooms.map(r => r.name) : ['general'];

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
            rooms: roomNames,
            users: allUsers,
            onlineCount: onlineUsers.length,
            totalUsers: allUsers.length,
            message: `Connected successfully. ${onlineUsers.length} users online.`
          }));

          console.log(`✅ WebSocket authenticated: ${user.displayName || user.username}`);

        } else {
          ws.send(JSON.stringify({
            type: 'authError',
            error: 'Authentication failed'
          }));
        }
        return;
      }

      // Typing indicator
      if (message.type === 'typing') {
        if (ws.isAuthenticated && ws.user) {
          handleTypingUpdate(ws.user.username, message.room, message.typing);
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
          seenBy: [ws.user.username]
        };

        // Save to database
        await messages.insertOne(newMessage);

        // Broadcast to all clients in the room
        broadcastToRoom(message.room || 'general', {
          type: 'message',
          data: newMessage
        });

        console.log(`📨 ${ws.user.username} sent message to ${message.room || 'general'}`);

        // Stop typing indicator when message is sent
        handleTypingUpdate(ws.user.username, message.room || 'general', false);
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
        }
      });
      
      // Update user status to offline after a short delay
      setTimeout(async () => {
        const currentConnections = Array.from(memoryStorage.activeConnections.entries())
          .filter(([username, conn]) => username === ws.user.username);
        
        if (currentConnections.length === 0) {
          await updateUserStatus(ws.user.username, 'offline');
          console.log(`👤 ${ws.user.username} set to offline`);
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

server.listen(PORT, '0.0.0.0', async () => {
  console.log('='.repeat(70));
  console.log(`🚀 WhatsApp Server Running on Port ${PORT}`);
  console.log(`🌐 URL: http://localhost:${PORT}`);
  
  try {
    await database.connect();
    console.log(`💾 Database: MongoDB Atlas 🟢`);
  } catch (error) {
    console.log(`💾 Database: Connection Failed 🔴`);
    console.log(`❌ Error: ${error.message}`);
  }

  console.log(`👥 Static Users: ${Object.keys(STATIC_USERS).join(', ')}`);
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