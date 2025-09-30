require('dotenv').config();
const { MongoClient } = require('mongodb');

const user = encodeURIComponent(process.env.MONGO_USER);
const pass = encodeURIComponent(process.env.MONGO_PASS);
const cluster = process.env.MONGO_CLUSTER;
const dbName = process.env.MONGO_DB || 'whatsapp';

const uri = `mongodb+srv://${user}:${pass}@${cluster}/?retryWrites=true&w=majority&appName=whatsapp`;

const client = new MongoClient(uri);

let db;
async function connectDB() {
  if (db) return db;
  try {
    await client.connect();
    db = client.db(dbName);
    console.log('✅ Connected to MongoDB Atlas - WhatsApp Database');
    
    // Verify connection by listing collections
    const collections = await db.listCollections().toArray();
    console.log('📁 Available collections:', collections.map(c => c.name));
    
    return db;
  } catch (err) {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  }
}

module.exports = connectDB;