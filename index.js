const express = require('express');
const app = express();
const cors = require('cors');
require('dotenv').config();
const { MongoClient, ServerApiVersion } = require('mongodb');
const admin = require('firebase-admin');

const port = process.env.PORT || 3000;

//  CORS FIX (for credentials)
app.use(
  cors({
    origin: 'http://localhost:5176',
    credentials: true,
  })
);
app.use(express.json());

//  FIREBASE ADMIN INIT (ONLY ONCE)
try {
 /*  const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf-8');
  console.log(' Firebase key loaded');

  const serviceAccount = JSON.parse(decoded);

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  }); */
  const serviceAccount = require('./serviceAccountKey.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

} catch (err) {
  console.error(' Firebase Admin Init Failed:', err.message);
  process.exit(1);
}

//  JWT MIDDLEWARE
const verifyJWT = async (req, res, next) => {
  const authHeader = req?.headers?.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send({ message: 'Unauthorized Access!' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.tokenEmail = decoded.email;
    next();
  } catch (err) {
    return res.status(401).send({ message: 'Unauthorized Access!', err });
  }
};

// MONGODB CONNECTION
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.nma65uq.mongodb.net/?appName=Cluster0`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  await client.connect();

  const db = client.db('contestDB');
  const usersCollection = db.collection('user');

  // SAVE OR UPDATE USER
  app.post('/user', async (req, res) => {
    const userData = req.body;
    userData.created_at = new Date().toISOString();
    userData.last_loggedIn = new Date().toISOString();
    userData.role = userData.role || 'user';

    const query = { email: userData.email };
    const alreadyExist = await usersCollection.findOne(query);

    if (alreadyExist) {
      await usersCollection.updateOne(query, {
        $set: { last_loggedIn: new Date().toISOString() },
      });
      return res.send({ updated: true });
    }

    const result = await usersCollection.insertOne(userData);
    res.send(result);
  });

  //  GET USER ROLE
  app.get('/user/role/:email', async (req, res) => {
    const email = req.params.email;
    const result = await usersCollection.findOne({ email });

    res.send({ role: result?.role || 'user' });
  });

  console.log(' MongoDB connected');
}

run();

// ROOT TEST
app.get('/', (req, res) => {
  res.send('Rank-up is running well!');
});

// SERVER START
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
