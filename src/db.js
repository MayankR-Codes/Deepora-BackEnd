'use strict';

const path = require('node:path');
const fs = require('node:fs');

// Attempt to load .env from multiple candidate paths (root or current working dir)
try {
  const dotenv = require('dotenv');
  dotenv.config(); // CWD
  dotenv.config({ path: path.resolve(__dirname, '..', '.env') });
  dotenv.config({ path: path.resolve(__dirname, '.env') });
} catch {}

const dns = require('node:dns');
try {
  // Ensure Node on Windows can resolve MongoDB Atlas SRV records
  if (process.platform === 'win32') {
    dns.setServers(['8.8.8.8', '1.1.1.1']);
  }
} catch {}

const { MongoClient } = require('mongodb');

let client = null;
let db = null;
let isConnecting = false;
let indexesInitialized = false;

function getMongoConfig() {
  return {
    uri: process.env.MONGODB_URI,
    dbName: process.env.MONGODB_DB_NAME || 'deepora',
  };
}

async function connectToMongo() {
  if (db) {
    try {
      if (client?.topology?.s?.state === 'closed') {
        db = null;
        client = null;
      } else {
        return db;
      }
    } catch {
      db = null;
      client = null;
    }
  }
  if (isConnecting) {
    while (isConnecting) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    return getDb();
  }

  const { uri, dbName } = getMongoConfig();
  if (!uri) throw new Error('MONGODB_URI must be configured before starting the backend.');
  isConnecting = true;
  try {
    client = new MongoClient(uri, {
      serverSelectionTimeoutMS: 8000,
      connectTimeoutMS: 12000,
      maxPoolSize: 10,
      minPoolSize: 0,
    });

    await client.connect();
    // Use configured dbName or database from URI
    db = client.db(dbName);
    console.log(`[MongoDB] Successfully connected to database: "${db.databaseName}"`);

    if (!indexesInitialized) {
      indexesInitialized = true;
      initCollectionsAndIndexes().catch(err => {
        console.error(`[MongoDB] Background index error: ${err.message}`);
      });
    }
    return db;
  } catch (error) {
    console.error(`[MongoDB] Connection failed: ${error.message}`);
    if (client) await client.close().catch(() => {});
    client = null;
    db = null;
    throw error;
  } finally {
    isConnecting = false;
  }
}

function getDb() {
  if (!db) throw new Error('MongoDB is not connected.');
  return db;
}

function isConnected() {
  return Boolean(db);
}

async function initCollectionsAndIndexes() {
  const database = getDb();
  const indexes = [
    ['users', { id: 1 }, { unique: true }],
    ['users', { phone: 1 }, { unique: true, sparse: true }],
    // Keep email lookups indexed. Uniqueness is also checked by the signup flow,
    // while a non-unique index safely handles older records with blank emails.
    ['users', { email: 1 }, { name: 'users_by_email' }],
    ['orders', { reference: 1 }, { unique: true }],
    ['orders', { userId: 1, createdAt: -1 }, { name: 'orders_by_user_recent' }],
    ['feedback', { orderReference: 1, userId: 1 }, { unique: true, name: 'feedback_by_order_user' }],
    ['products', { id: 1 }, { unique: true }],
    ['products', { category: 1 }, {}],
    ['sessions', { token: 1 }, { unique: true }],
    ['sessions', { expiresAt: 1 }, { expireAfterSeconds: 0 }],
    ['email_challenges', { email: 1 }, { unique: true }],
    ['email_challenges', { expiresAt: 1 }, { expireAfterSeconds: 0 }],
  ];
  let failures = 0;
  for (const [collection, keys, options] of indexes) {
    try {
      await database.collection(collection).createIndex(keys, options);
    } catch (error) {
      failures++;
      console.error(`[MongoDB] Could not initialize ${collection} index ${JSON.stringify(keys)}: ${error.message}`);
    }
  }
  if (!failures) console.log('[MongoDB] Collections and indexes initialized successfully.');
}

// ======================== User Operations ========================
async function findUserById(id) {
  return getDb().collection('users').findOne({ id }, { projection: { _id: 0 } });
}

async function findUserByIdentifier(identifier, { phone, email } = {}) {
  const database = getDb();
  const queries = [];
  if (phone) queries.push({ phone });
  if (email) queries.push({ email });
  if (identifier && !phone && !email) {
    queries.push({ phone: identifier }, { email: identifier });
  }
  if (!queries.length) return null;
  return database.collection('users').findOne({ $or: queries }, { projection: { _id: 0 } });
}

async function createUser(user) {
  const database = getDb();
  const doc = {
    ...user,
    createdAt: user.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  await database.collection('users').insertOne(doc);
  const { _id, ...clean } = doc;
  return clean;
}

async function updateUser(id, updates) {
  const database = getDb();
  const updateDoc = {
    ...updates,
    updatedAt: new Date().toISOString(),
  };
  delete updateDoc.id;
  delete updateDoc._id;
  const res = await database.collection('users').findOneAndUpdate(
    { id },
    { $set: updateDoc },
    { returnDocument: 'after', projection: { _id: 0 } }
  );
  return res?.value || res;
}

// ======================== Session Operations ========================
async function createSession(userId, token, expiresAt) {
  const database = getDb();
  const doc = {
    userId,
    token,
    expiresAt: new Date(expiresAt),
    createdAt: new Date(),
  };
  await database.collection('sessions').insertOne(doc);
  return doc;
}

async function findSession(token) {
  const database = getDb();
  const session = await database.collection('sessions').findOne({ token });
  if (!session) return null;
  if (session.expiresAt && new Date(session.expiresAt) <= new Date()) {
    await database.collection('sessions').deleteOne({ token });
    return null;
  }
  return session;
}

async function deleteSession(token) {
  await getDb().collection('sessions').deleteOne({ token });
}

// ======================== Order Operations ========================
async function createOrder(order) {
  const database = getDb();
  const doc = {
    ...order,
    createdAt: order.createdAt || new Date().toISOString(),
  };
  await database.collection('orders').insertOne(doc);
  const { _id, ...clean } = doc;
  return clean;
}

async function findOrdersByUserId(userId) {
  return getDb().collection('orders')
    .find({ userId }, { projection: { _id: 0 } })
    .sort({ createdAt: -1 })
    .toArray();
}

async function findOrderByReference(reference) {
  return getDb().collection('orders').findOne({ reference }, { projection: { _id: 0 } });
}

async function getAllOrders(limit = 100) {
  return getDb().collection('orders')
    .find({}, { projection: { _id: 0 } })
    .sort({ createdAt: -1 })
    .limit(limit)
    .toArray();
}

async function saveFeedback(feedback) {
  const { orderReference, userId, ...values } = feedback;
  await getDb().collection('feedback').updateOne(
    { orderReference, userId },
    { $set: { ...values, orderReference, userId, updatedAt: new Date().toISOString() }, $setOnInsert: { createdAt: new Date().toISOString() } },
    { upsert: true },
  );
  return { orderReference, userId, ...values };
}

// ======================== Product Operations ========================
async function getAllProducts() {
  return getDb().collection('products')
    .find({}, { projection: { _id: 0 } })
    .sort({ createdAt: 1 })
    .toArray();
}

async function getProductById(id) {
  return getDb().collection('products').findOne({ id }, { projection: { _id: 0 } });
}

async function upsertProduct(product) {
  const database = getDb();
  const now = new Date().toISOString();
  const updateDoc = {
    ...product,
    updatedAt: now,
  };
  delete updateDoc._id;
  await database.collection('products').updateOne(
    { id: product.id },
    {
      $set: updateDoc,
      $setOnInsert: { createdAt: now },
    },
    { upsert: true }
  );
  return getProductById(product.id);
}

async function updateProduct(id, updates) {
  const database = getDb();
  const updateDoc = {
    ...updates,
    updatedAt: new Date().toISOString(),
  };
  delete updateDoc.id;
  delete updateDoc._id;
  delete updateDoc.createdAt;
  await database.collection('products').updateOne(
    { id },
    { $set: updateDoc }
  );
  return getProductById(id);
}

async function deleteProduct(id) {
  const res = await getDb().collection('products').deleteOne({ id });
  return res.deletedCount > 0;
}

// ======================== Email Challenges ========================
async function saveEmailChallenge(email, { codeHash, expiresAt, sentAt, attempts }) {
  const database = getDb();
  await database.collection('email_challenges').updateOne(
    { email },
    {
      $set: {
        email,
        codeHash,
        expiresAt: new Date(expiresAt),
        sentAt,
        attempts: attempts || 0,
        updatedAt: new Date(),
      },
    },
    { upsert: true }
  );
}

async function getEmailChallenge(email) {
  const database = getDb();
  const doc = await database.collection('email_challenges').findOne({ email });
  if (!doc) return null;
  return {
    ...doc,
    expiresAt: doc.expiresAt instanceof Date ? doc.expiresAt.getTime() : doc.expiresAt,
  };
}

async function deleteEmailChallenge(email) {
  await getDb().collection('email_challenges').deleteOne({ email });
}

async function incrementEmailChallengeAttempts(email) {
  const database = getDb();
  const res = await database.collection('email_challenges').findOneAndUpdate(
    { email },
    { $inc: { attempts: 1 } },
    { returnDocument: 'after' }
  );
  return res?.value || res;
}

async function closeConnection() {
  if (client) {
    await client.close();
    client = null;
    db = null;
    console.log('[MongoDB] Connection closed.');
  }
}

module.exports = {
  connectToMongo,
  getDb,
  isConnected,
  closeConnection,
  initCollectionsAndIndexes,
  // User
  findUserById,
  findUserByIdentifier,
  createUser,
  updateUser,
  // Session
  createSession,
  findSession,
  deleteSession,
  // Order
  createOrder,
  findOrdersByUserId,
  findOrderByReference,
  getAllOrders,
  saveFeedback,
  // Product
  getAllProducts,
  getProductById,
  upsertProduct,
  updateProduct,
  deleteProduct,
  // Email Challenge
  saveEmailChallenge,
  getEmailChallenge,
  deleteEmailChallenge,
  incrementEmailChallengeAttempts,
};
