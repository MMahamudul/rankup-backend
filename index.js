const express = require('express');
const app = express();
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const admin = require('firebase-admin');

const port = process.env.PORT || 3000;

//  CORS FIX (for credentials)
app.use(
  cors( {
    origin: [process.env.CLIENT_DOMAIN],
    credentials: true,
  } )
);
app.use(express.json());

//  FIREBASE ADMIN INIT (ONLY ONCE)
try {
  const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf-8');
  console.log(' Firebase key loaded');

  const serviceAccount = JSON.parse(decoded);

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
  const contestsCollection = db.collection('contest');
  const ordersCollection = db.collection('orders');

// SAVE CONTESTS POSTED BY CREATOR

app.post('/add-contest', async (req, res) => {
  const contestData = req.body;

  contestData.participant = 0;

  const result = await contestsCollection.insertOne(contestData);
  res.send(result);
});

// GET CONTEST IN ALL CONTEST PAGE 

app.get('/contests', async(req, res)=>{
  const result= await contestsCollection.find().toArray();
  res.send(result)
})

// CONTEST DETAILS PAGE

app.get('/contests/:id', async(req, res)=>{
  const id = req.params.id
  const result= await contestsCollection.findOne({_id: new ObjectId(id)});
  res.send(result)
})
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
// GET USER'S PARTICIPATED CONTESTS
app.get('/my-contests/:email', async(req, res)=>{
  const email = req.params.email;
  const result = await ordersCollection.find({customer: email}).toArray();
  res.send(result)

})
// GET CREATOR'S CREATED CONTEST
app.get('/handle-contests/:email', async(req, res)=>{
  const email = req.params.email;
  const result = await contestsCollection.find({'creator.email': email}).toArray();
  res.send(result)

})

// PAYMENT ENDPOINTS

app.post('/create-checkout-session', async (req, res) => {
  
  const paymentInfo = req.body;
  
  const session = await stripe.checkout.sessions.create({
    line_items: [
      {
        
        price_data: {
          currency: 'usd',
          product_data:{
            name: paymentInfo?.name,
            description: paymentInfo?.description,
            images:[paymentInfo.image]

          },
          unit_amount: paymentInfo?.price * 100,
        },
        quantity: paymentInfo?.quantity,
      },
    ],
    customer_email:paymentInfo?.customer?.email ,
    mode: 'payment',
    metadata: {
      contestId: paymentInfo?.contestId,
      customer: paymentInfo?.customer.email,
    },
    success_url: `${process.env.CLIENT_DOMAIN}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${process.env.CLIENT_DOMAIN}/contest/${paymentInfo?.contestId}`,
  })
  res.send({url:session.url})
}) 

// PAYMENT SUCCESS
app.post('/payment-success', async (req, res) => {
  try {
    const { session_id } = req.body;

    if (!session_id) {
      return res.status(400).send({ message: 'Missing session_id' });
    }

    // 1) Get session info from Stripe
    const session = await stripe.checkout.sessions.retrieve(session_id);

    // 2) Find the contest
    const contest = await contestsCollection.findOne({
      _id: new ObjectId(session.metadata.contestId),
    });

    if (!contest) {
      return res.status(404).send({ message: 'Contest not found' });
    }

    // 3) Check if order already exists (important for refresh / double-call)
    const existingOrder = await ordersCollection.findOne({
      transactionId: session.payment_intent,
    });

    // 4) Only proceed if payment is paid
    if (session.payment_status !== 'paid') {
      return res.status(400).send({
        success: false,
        message: 'Payment not completed',
        payment_status: session.payment_status,
      });
    }

    let orderId;

    // 5) If no order yet -> create one & increment participant
    if (!existingOrder) {
      const orderInfo = {
        contestId: session.metadata.contestId,
        transactionId: session.payment_intent,
        customer: session.metadata.customer,
        status: 'pending',
        creator: contest.creator,
        name: contest.name,
        image:contest?.image,
        deadline:contest?.deadline,
        category: contest.category,
        participant: 1,
        price: session.amount_total / 100,
        createdAt: new Date().toISOString(),
      };

      const result = await ordersCollection.insertOne(orderInfo);

      // 6) Increment contest participant
      await contestsCollection.updateOne(
        { _id: new ObjectId(session.metadata.contestId) },
        { $inc: { participant: 1 } }  
      );

      orderId = result.insertedId;
    } else {
      // If order already exists, just reuse its ID
      orderId = existingOrder._id;
    }

    // 7) Always return success for a valid, paid session
    return res.send({
      success: true,
      transactionId: session.payment_intent,
      orderId,
    });
  } catch (err) {
    console.error('Payment success error:', err);
    return res.status(500).send({
      message: 'Internal Server Error while verifying payment',
      error: err.message,
    });
  }
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
