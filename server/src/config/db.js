const mongoose = require('mongoose');
const env = require('./env');

async function connectDB() {
  mongoose.set('strictQuery', true);
  // Fail fast (10 s) when MongoDB is unreachable instead of the 30 s default.
  await mongoose.connect(env.mongoUri, { serverSelectionTimeoutMS: 10_000 });
  console.log(`[db] connected: ${mongoose.connection.name}`);
  return mongoose.connection;
}

module.exports = { connectDB };
