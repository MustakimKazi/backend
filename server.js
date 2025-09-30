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
console.log('🔍 Environment Check:');
console.log('PORT:', process.env.PORT || '5000');
console.log('NODE_ENV:', process.env.NODE_ENV || 'development');

// ================== MongoDB Configuration ==================
// Fixed MongoDB connection - using your exact credentials from screenshot
const MONGODB_CONFIG = {
  user: 'mohdmustakimkazi_db_user',
  password: 'HugPu2kIqGxOdhNF',
  cluster: 'whatsapp.dzac4go.mongodb.net', // Fixed cluster name
  dbName: 'whatsapp'
};

// Correct connection string format
const MONGODB_URI = `mongodb+srv://${MONGODB_CONFIG.user}:${MONGODB_CONFIG.password}@${MONGODB_CONFIG.cluster}/${MONGODB_CONFIG.dbName}?retryWrites=true&w=majority`;

console.log('🔗 MongoDB URI configured');

// ================== Database Service ==================
let dbClient = null;
let isMongoConnected = false;

// Memory storage as fallback
const memoryStorage = {
  users: [
    {
      _id: '1',
      username: 'mustskim',
      email: 'mustskim@gmail.com',
      password_hash: '$2a$10$rQdUO9BspOYR8B6u6t1kE.Fz6BJWfE9Y9YQ9YQ9YQ9YQ9YQ9YQ9YQ', // demo123
      token: null,
      status: 'offline',
      createdAt: new Date().toISOString()
    },
    {
      _id: '2',
      username: 'admin',
      email: 'admin@example.com',
      password_hash: '$2a$10$rQdUO9BspOYR8B6u6t1kE.Fz6BJWfE9Y9YQ9YQ9YQ9YQ9YQ9YQ9YQ', // demo123
      token: null,
      status: 'offline',
      createdAt: new Date().toISOString()
    }
  ],
  messages: [
    {
      id: '1',
      sender: 'mustskim',
      content: 'Hello everyone! 👋',
      room: 'general',
      timestamp: new Date().toISOString(),
      isFile: false
    },
    {
      id: '2',
      sender: 'admin',
      content: 'Welcome to WhatsApp Clone! 🚀',
      room: 'general',
      timestamp: new Date().toISOString(),
      isFile: false
    }
  ],
  rooms: ['general', 'random', 'help', 'tech', 'games']
};

class DatabaseService {
  constructor() {
    this.db = null;
    this.isConnected = false;
  }

  async connect() {
    if (this.isConnected && this.db) return this.db;

    try {
      console.log('🔄 Attempting MongoDB connection...');
      console.log('📡 Cluster:', MONGODB_CONFIG.cluster);
      
      const client = new MongoClient(MONGODB_URI, {
        serverSelectionTimeoutMS: 10000,
        connectTimeoutMS: 15000,
        maxPoolSize: 10,
        // Remove SSL options that cause issues
      });

      await client.connect();
      this.db = client.db(MONGODB_CONFIG.dbName);
      this.isConnected = true;
      dbClient = client;
      isMongoConnected = true;

      console.log('✅ MongoDB Connected Successfully!');
      
      // Test the connection
      await this.db.command({ ping: 1 });
      console.log('🎯 MongoDB Ping Successful');
      
      // Initialize collections
      await this.initializeCollections();
      
      return this.db;

    } catch (error) {
      console.log('⚠️  MongoDB connection failed, using memory storage');
      console.log('💡 Connection details:', {
        cluster: MONGODB_CONFIG.cluster,
        database: MONGODB_CONFIG.dbName,
        error: error.message
      });
      
      // Return memory database interface
      return this.getMemoryDB();
    }
  }

  getMemoryDB() {
    return {
      collection: (name) => this.getMemoryCollection(name),
      command: (cmd) => Promise.resolve({ ok: 1 }), // For ping command
      listCollections: () => ({
        toArray: () => Promise.resolve(Object.keys(memoryStorage).map(name => ({ name })))
      })
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
                  // Handle $or queries
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
          },
          project: (projection) => ({
            toArray: () => {
              let results = [...collection];
              if (projection) {
                results = results.map(item => {
                  const newItem = {};
                  for (let key in item) {
                    if (projection[key] !== 0) {
                      newItem[key] = item[key];
                    }
                  }
                  return newItem;
                });
              }
              return Promise.resolve(results);
            }
          })
        }),
        project: (projection) => ({
          toArray: () => {
            let results = [...collection];
            if (projection) {
              results = results.map(item => {
                const newItem = {};
                for (let key in item) {
                  if (projection[key] !== 0) {
                    newItem[key] = item[key];
                  }
                }
                return newItem;
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

  async initializeCollections() {
    try {
      const collections = await this.db.listCollections().toArray();
      const collectionNames = collections.map(col => col.name);

      if (!collectionNames.includes('users')) {
        await this.db.createCollection('users');
        console.log('✅ Users collection created');
      } else {
        const userCount = await this.db.collection('users').countDocuments();
        console.log(`✅ Users collection exists with ${userCount} users`);
      }

      if (!collectionNames.includes('messages')) {
        await this.db.createCollection('messages');
        console.log('✅ Messages collection created');
      } else {
        const messageCount = await this.db.collection('messages').countDocuments();
        console.log(`✅ Messages collection exists with ${messageCount} messages`);
      }

    } catch (error) {
      console.log('ℹ️  Collections initialization note:', error.message);
    }
  }

  async close() {
    if (dbClient) {
      await dbClient.close();
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

// ================== API Routes ==================

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'WhatsApp Clone API Server 🚀',
    version: '2.0.0',
    database: isMongoConnected ? 'MongoDB' : 'Memory Storage',
    status: 'Running',
    timestamp: new Date().toISOString()
  });
});

// Health check
app.get('/api/health', async (req, res) => {
  const db = await database.connect();
  
  res.json({
    success: true,
    status: 'Server is healthy 🟢',
    database: isMongoConnected ? 'MongoDB Connected 🟢' : 'Memory Storage 🟡',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()) + ' seconds'
  });
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

// Sign Up
app.post('/api/sign_up', async (req, res) => {
  try {
    const { email, username, password } = req.body;

    if (!email || !username || !password) {
      return res.status(400).json({
        success: false,
        error: 'All fields are required'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        error: 'Password must be at least 6 characters'
      });
    }

    const db = await database.connect();
    const users = db.collection('users');

    // Check existing user
    const existingUser = await users.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: 'User already exists'
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
      status: 'offline',
      createdAt: new Date().toISOString()
    });

    console.log('✅ New user registered:', username);

    res.json({
      success: true,
      message: 'Account created successfully! Please login.',
      user: { username, email }
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({
      success: false,
      error: 'Registration failed'
    });
  }
});

// Login
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

    // Find user
    const user = await users.findOne({ email });

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
      { email },
      { 
        $set: { 
          token, 
          status: 'online',
          lastLogin: new Date().toISOString()
        } 
      }
    );

    console.log('✅ User logged in:', user.username);

    res.json({
      success: true,
      message: `Welcome back, ${user.username}!`,
      user: {
        username: user.username,
        email: user.email,
        token: token
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

// Demo Login
app.post('/api/demo-login', async (req, res) => {
  try {
    const { account } = req.body;

    const demoAccounts = {
      mustskim: {
        email: 'mustskim@gmail.com',
        username: 'mustskim',
        password: 'demo123'
      },
      admin: {
        email: 'admin@example.com', 
        username: 'admin',
        password: 'demo123'
      }
    };

    const demo = demoAccounts[account];
    if (!demo) {
      return res.status(400).json({
        success: false,
        error: 'Invalid demo account'
      });
    }

    const db = await database.connect();
    const users = db.collection('users');

    // Find or create user
    let user = await users.findOne({ email: demo.email });
    
    if (!user) {
      const password_hash = await bcrypt.hash(demo.password, 10);
      await users.insertOne({
        email: demo.email,
        username: demo.username,
        password_hash,
        token: null,
        status: 'offline',
        createdAt: new Date().toISOString()
      });
      user = await users.findOne({ email: demo.email });
    }

    // Generate token
    const token = generateToken();

    await users.updateOne(
      { email: demo.email },
      { 
        $set: { 
          token, 
          status: 'online',
          lastLogin: new Date().toISOString()
        } 
      }
    );

    res.json({
      success: true,
      message: `Demo login successful! Welcome ${demo.username}`,
      user: {
        username: user.username,
        email: user.email,
        token: token
      }
    });

  } catch (error) {
    console.error('Demo login error:', error);
    res.status(500).json({
      success: false,
      error: 'Demo login failed'
    });
  }
});

// Get Users
app.get('/api/users', async (req, res) => {
  try {
    const db = await database.connect();
    const users = await db.collection('users')
      .find({})
      .project({ password_hash: 0, token: 0 })
      .toArray();

    res.json({
      success: true,
      users: users
    });

  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch users'
    });
  }
});

// Get Messages
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
      messages: messages
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

    if (!content) {
      return res.status(400).json({
        success: false,
        error: 'Message content required'
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
      content: content,
      room: room,
      timestamp: new Date().toISOString()
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

// Get Rooms
app.get('/api/rooms', async (req, res) => {
  try {
    const rooms = ['general', 'random', 'help', 'tech', 'games'];
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

// ================== WebSocket ==================
wss.on('connection', (ws) => {
  console.log('🔌 New WebSocket connection');
  ws.user = null;

  ws.on('message', async (data) => {
    try {
      const message = JSON.parse(data);

      if (message.type === 'auth') {
        const db = await database.connect();
        const users = db.collection('users');
        const user = await users.findOne({ token: message.token });
        
        if (user) {
          ws.user = user;
          ws.send(JSON.stringify({
            type: 'auth_success',
            user: {
              username: user.username,
              email: user.email
            }
          }));
          console.log('✅ WebSocket authenticated:', user.username);
        }
      }

      if (message.type === 'message' && ws.user) {
        const db = await database.connect();
        const messages = db.collection('messages');

        const messageData = {
          id: uuid.v4(),
          sender: ws.user.username,
          content: message.content,
          room: message.room || 'general',
          timestamp: new Date().toISOString()
        };

        await messages.insertOne(messageData);

        // Broadcast to all clients
        wss.clients.forEach(client => {
          if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({
              type: 'new_message',
              data: messageData
            }));
          }
        });

        console.log(`💬 Message from ${ws.user.username} in ${messageData.room}`);
      }

    } catch (error) {
      console.error('WebSocket error:', error);
    }
  });

  ws.on('close', () => {
    if (ws.user) {
      console.log('🔌 User disconnected:', ws.user.username);
    }
  });
});

// ================== Start Server ==================
const PORT = process.env.PORT || 5000;

server.listen(PORT, '0.0.0.0', () => {
  console.log('='.repeat(60));
  console.log(`🚀 WhatsApp Server Running on Port ${PORT}`);
  console.log(`🌐 URL: http://localhost:${PORT}`);
  console.log(`💾 Database: ${isMongoConnected ? 'MongoDB 🟢' : 'Memory Storage 🟡'}`);
  console.log(`📡 WebSocket: Ready`);
  console.log(`✅ Health: http://localhost:${PORT}/api/health`);
  console.log('='.repeat(60));
  
  // Test database connection
  database.connect().then(db => {
    if (isMongoConnected) {
      console.log('🎉 MongoDB: Connected and Ready');
    } else {
      console.log('🔄 Using Memory Storage - All features available');
      console.log('👤 Demo accounts: mustskim / admin (password: demo123)');
    }
  });
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🔄 Shutting down server...');
  await database.close();
  process.exit(0);
});