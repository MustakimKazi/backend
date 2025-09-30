const connectDB = require('./db');

async function testConnection() {
  try {
    const db = await connectDB();
    
    // Test users collection
    const users = db.collection('users');
    const userCount = await users.countDocuments();
    console.log(`👥 Total users in database: ${userCount}`);
    
    // List all users
    const allUsers = await users.find({}).toArray();
    console.log('📋 Users:', allUsers);
    
  } catch (error) {
    console.error('Test failed:', error);
  }
}

testConnection();