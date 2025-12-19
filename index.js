const express = require('express');
const app = express();
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const admin = require('firebase-admin');

const port = process.env.PORT || 3000;

//  CORS (for credentials)
app.use(
  cors( {
    origin: [process.env.CLIENT_DOMAIN],
    credentials: true,
  } )
);
app.use(express.json());

//  FIREBASE ADMIN INIT 
try {
  const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf-8');
  // console.log(' Firebase key loaded');

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
  // await client.connect();

  const db = client.db('contestDB');
  const usersCollection = db.collection('user');
  const contestsCollection = db.collection('contest');
  const ordersCollection = db.collection('orders');
  const submissionsCollection = db.collection('submissions');


// SAVE CONTESTS POSTED BY CREATOR

app.post('/add-contest', verifyJWT, async (req, res) => {
  const email = req.tokenEmail;
  const user = await usersCollection.findOne({ email });

  if (!user || (user.role !== "creator" && user.role !== "admin")) {
    return res.status(403).send({ message: "Forbidden: not a creator" });
  }

  const contestData = req.body;
  contestData.participant = 0;
  contestData.status = "pending"; 

  const result = await contestsCollection.insertOne(contestData);
  res.send(result);
});
//BANNER  SEARCH CONTESTS (by category or name)

app.get("/contests/search", async (req, res) => {
  try {
    const q = (req.query.q || "").trim();

    if (!q) return res.send([]);

    const result = await contestsCollection
      .find({
        status: "approved",
        $or: [
          { category: { $regex: q, $options: "i" } },
          { name: { $regex: q, $options: "i" } },
        ],
      })
      .toArray();

    res.send(result);
  } catch (err) {
    console.error("Search error:", err);
    res.status(500).send({ message: "Search failed", error: err.message });
  }
});

// CONTEST DETAILS PAGE

app.get("/contests/:id", async (req, res) => {
  try {
    const contest = await contestsCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!contest) return res.status(404).send({ message: "Contest not found" });
    res.send(contest);
  } catch (err) {
    res.status(500).send({ message: "Failed to load contest" });
  }
});

// UPDATE CONTESTS BEFORE APPROVAL
app.patch("/contests/:id", verifyJWT, async (req, res) => {
  const id = req.params.id;
  const updatedData = req.body;

  const contest = await contestsCollection.findOne({ _id: new ObjectId(id) });
  if (!contest) return res.status(404).send({ message: "Contest not found" });

  if (contest.creator.email !== req.tokenEmail) {
    return res.status(403).send({ message: "Forbidden" });
  }

  const result = await contestsCollection.updateOne(
    { _id: new ObjectId(id) },
    { $set: updatedData }
  );

  res.send(result);
});

// DELETE CONTESTS BEFORE APPROVAL
app.delete("/contests/:id", verifyJWT, async (req, res) => {
  const id = req.params.id;

  const contest = await contestsCollection.findOne({ _id: new ObjectId(id) });
  if (!contest) return res.status(404).send({ message: "Contest not found" });

  if (contest.creator.email !== req.tokenEmail) {
    return res.status(403).send({ message: "Forbidden" });
  }

  const result = await contestsCollection.deleteOne({
    _id: new ObjectId(id),
  });

  res.send(result);
});

// GET ALL APPROVED CONTESTS TO ALL CONTEST PAGE
app.get('/all-contests', async(req, res)=>{
  const result= await contestsCollection.find({ status: "approved" }).toArray();
  res.send(result)
})
// GET ALL USERS FOR ADMIN APPROVAL
// GET ALL USERS (ADMIN) WITH PAGINATION
app.get("/users", verifyJWT, async (req, res) => {
  try {
    const adminEmail = req.tokenEmail;

    const page = Math.max(parseInt(req.query.page || "1"), 1);
    const limit = Math.max(parseInt(req.query.limit || "10"), 1);
    const skip = (page - 1) * limit;

    const filter = { email: { $ne: adminEmail } };

    const total = await usersCollection.countDocuments(filter);

    const users = await usersCollection
      .find(filter)
      .sort({ created_at: -1 })
      .skip(skip)
      .limit(limit)
      .toArray();

    res.send({
      users,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    });
  } catch (err) {
    res.status(500).send({
      message: "Failed to load users",
      error: err.message,
    });
  }
});

// GET CONTEST FOR ADMIN APPROVAL

app.get('/manage-contest',verifyJWT, async(req, res)=>{
  const result= await contestsCollection.find({ status: "pending" }).toArray();
  res.send(result)
})



// APPROVE CONTESTS BY ADMIN
app.patch('/approve-contests/:id', verifyJWT, async (req, res)=>{
  const id = req.params.id;
  const result = await contestsCollection.updateOne(
    {_id: new ObjectId(id)},
    {$set: {status: 'approved'}}
  )
  res.send(result)

})
// CHANGE USER ROLE BY ADMIN
app.patch('/update-role', verifyJWT, async (req, res)=>{
  const {email, role} = req.body;
  const result = await usersCollection.updateOne(
    {email},
    {$set: {role}}
  )
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
app.get('/user/role', verifyJWT, async (req, res) => {
  const result = await usersCollection.findOne({ email: req.tokenEmail });
  res.send({ role: result?.role || 'user' });
});

  // GET USER'S PARTICIPATED CONTESTS
app.get("/my-joined-contests", verifyJWT, async (req, res) => {
  try {
    const email = req.tokenEmail; 
    const orders = await ordersCollection.find({ customer: email }).toArray();
    res.send(orders);
  } catch (err) {
    res.status(500).send({ message: "Failed to load joined contests" });
  }
});


// GET CREATOR'S CREATED CONTEST

app.get('/handle-contests/:email', verifyJWT, async (req, res) => {
  const email = req.params.email;

  if (req.tokenEmail !== email) {
    return res.status(403).send({ message: "Forbidden" });
  }

  const result = await contestsCollection.find({ 'creator.email': email }).toArray();
  res.send(result);
});

// POST REQUEST FOR SUBMISSION OF THE TASK

app.post("/submissions", verifyJWT, async (req, res) => {
  try {
    const email = req.tokenEmail; // correct
    const { contestId, text, link } = req.body;

    if (!contestId) return res.status(400).send({ message: "Missing contestId" });

    // ensure paid
    const paid = await ordersCollection.findOne({
      contestId: String(contestId),
      customer: email,
      status: "Paid",
    });

    if (!paid) return res.status(403).send({ message: "You must register/pay before submitting." });

    const payload = {
      contestId: String(contestId),
      userEmail: email,
      text: (text || "").trim(),
      link: (link || "").trim(),
      updatedAt: new Date().toISOString(),
    };

    const existing = await submissionsCollection.findOne({
      contestId: String(contestId),
      userEmail: email,
    });

    if (existing) {
      await submissionsCollection.updateOne({ _id: existing._id }, { $set: payload });
      return res.send({ success: true, message: "Submission updated" });
    }

    payload.createdAt = new Date().toISOString();
    await submissionsCollection.insertOne(payload);
    return res.send({ success: true, message: "Submission created" });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to submit" });
  }
});


// GET SUBMISSION FORM
app.get('/creator/submissions', verifyJWT, async (req, res) => {
  try {
    const { contestId } = req.query;
    if (!contestId) return res.status(400).send({ message: "contestId required" });

    const contest = await contestsCollection.findOne({ _id: new ObjectId(contestId) });
    if (!contest) return res.status(404).send({ message: "Contest not found" });

    const user = await usersCollection.findOne({ email: req.tokenEmail });
    const isAdmin = user?.role === "admin";
    const isCreator = contest?.creator?.email === req.tokenEmail;

    if (!isAdmin && !isCreator) return res.status(403).send({ message: "Forbidden" });

    const submissions = await submissionsCollection
      .find({ contestId: String(contestId) })
      .sort({ createdAt: -1 })
      .toArray();

    res.send(submissions);
  } catch (err) {
    res.status(500).send({ message: "Failed to load submissions", error: err.message });
  }
});
// HANDLE SUBMISSION
app.get("/submissions/me", verifyJWT, async (req, res) => {
  try {
    const email = req.tokenEmail;
    const { contestId } = req.query;

    if (!contestId) {
      return res.status(400).send({ message: "Missing contestId" });
    }

    const submission = await submissionsCollection.findOne({
      contestId: String(contestId),
      userEmail: email,
    });

    res.send(submission || null);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to load submission" });
  }
});

//DECLARE WINNER BY CREATOR FOR A CONTEST
app.patch('/contests/:id/declare-winner', verifyJWT, async (req, res) => {
  try {
    const id = req.params.id;
    const { name, image, email } = req.body;

    const contest = await contestsCollection.findOne({ _id: new ObjectId(id) });
    if (!contest) return res.status(404).send({ message: "Contest not found" });

    // block re-declare
    if (contest?.winnerDeclared) {
      return res.status(409).send({ message: "Winner already declared" });
    }

    // block declaring winner before deadline
    if (contest.deadline && new Date(contest.deadline) > new Date()) {
      return res.status(409).send({ message: "You can't declare winner before deadline." });
    }

    // only creator/admin can declare
    const user = await usersCollection.findOne({ email: req.tokenEmail });
    const isCreator = contest?.creator?.email === req.tokenEmail;
    const isAdmin = user?.role === "admin";

    if (!isCreator && !isAdmin) {
      return res.status(403).send({ message: "Forbidden" });
    }

    const result = await contestsCollection.updateOne(
      { _id: new ObjectId(id), winnerDeclared: { $ne: true } },
      {
        $set: {
          winnerDeclared: true,
          winner: { name, image, email, declaredAt: new Date().toISOString() },
        },
      }
    );

    if (result.modifiedCount === 0) {
      return res.status(409).send({ message: "Winner already declared" });
    }

    res.send(result);
  } catch (err) {
    res.status(500).send({ message: "Failed to declare winner", error: err.message });
  }
});

// WINNING CONTESTS BY USER
app.get("/my-winning-contests", verifyJWT, async (req, res) => {
  try {
    const email = req.tokenEmail;

    const result = await contestsCollection
      .find({ winnerDeclared: true, "winner.email": email })
      .sort({ "winner.declaredAt": -1 })
      .toArray();

    res.send(result);
  } catch (err) {
    res.status(500).send({ message: "Failed to load winning contests", error: err.message });
  }
});

//LEADERBOARD
app.get("/leaderboard", async (req, res) => {
  const leaderboard = await contestsCollection.aggregate([
    { $match: { winnerDeclared: true } },
    {
      $group: {
        _id: "$winner.email",
        name: { $first: "$winner.name" },
        image: { $first: "$winner.image" },
        wins: { $sum: 1 },
        totalPrize: { $sum: "$prize" },
      },
    },
    { $sort: { wins: -1 } },
    { $limit: 20 },
  ]).toArray();

  res.send(leaderboard);
});

//GET USER PROFILE FROM DB
app.get("/me", verifyJWT, async (req, res) => {
  const email = req.tokenEmail;
  const me = await usersCollection.findOne({ email });
  if (!me) return res.status(404).send({ message: "User not found" });
  res.send(me);
});
 // UPDATE PROFILE
 app.patch("/me", verifyJWT, async (req, res) => {
  const email = req.tokenEmail;
  const { name, image, bio, address } = req.body;

  const updateDoc = {
    ...(name !== undefined && { name }),
    ...(image !== undefined && { image }),
    ...(bio !== undefined && { bio }),
    ...(address !== undefined && { address }),
    updatedAt: new Date().toISOString(),
  };

  const result = await usersCollection.updateOne(
    { email },
    { $set: updateDoc }
  );

  res.send(result);
});
// GET USER WIN STAT 
app.get("/me/stats", verifyJWT, async (req, res) => {
  const email = req.tokenEmail;

  const participated = await ordersCollection.countDocuments({
    customer: email,
    status: "Paid",
  });

  const won = await contestsCollection.countDocuments({
    winnerDeclared: true,
    "winner.email": email,
  });

  const winPercentage = participated > 0 ? Math.round((won / participated) * 100) : 0;

  res.send({ participated, won, winPercentage });
});
// WINNER ADVERTISEMENT (HOME SECTION)

app.get("/winners/highlights", async (req, res) => {
  try {
    // recent winners
    const recentWinners = await contestsCollection
      .find({ winnerDeclared: true })
      .sort({ "winner.declaredAt": -1 })
      .limit(6)
      .project({
        name: 1,
        prize: 1,
        image: 1,
        "winner.name": 1,
        "winner.image": 1,
        "winner.declaredAt": 1,
      })
      .toArray();

    // stats
    const totalWinners = await contestsCollection.countDocuments({
      winnerDeclared: true,
    });

    const prizeAgg = await contestsCollection.aggregate([
      { $match: { winnerDeclared: true } },
      { $group: { _id: null, totalPrize: { $sum: "$prize" } } },
    ]).toArray();

    res.send({
      recentWinners,
      stats: {
        totalWinners,
        totalPrize: prizeAgg[0]?.totalPrize || 0,
      },
    });
  } catch (err) {
    res.status(500).send({ message: "Failed to load winners" });
  }
});

// PAYMENT ENDPOINTS

app.post('/create-checkout-session', async (req, res) => {
  try {
    const paymentInfo = req.body;

    const session = await stripe.checkout.sessions.create({
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: {
              name: paymentInfo?.name,
              description: paymentInfo?.description,
              images: paymentInfo?.image ? [paymentInfo.image] : [],
            },
            unit_amount: Math.round(Number(paymentInfo?.price || 0) * 100),
          },
          quantity: Number(paymentInfo?.quantity || 1),
        },
      ],
      customer_email: paymentInfo?.customer?.email,
      mode: 'payment',
      metadata: {
        contestId: String(paymentInfo?.contestId),
        customer: String(paymentInfo?.customer?.email),
      },
      success_url: `${process.env.CLIENT_DOMAIN}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.CLIENT_DOMAIN}/contest/${paymentInfo?.contestId}`,
    });

    res.send({ url: session.url });
  } catch (err) {
    console.error("create-checkout-session error:", err);
    res.status(500).send({ message: "Failed to create checkout session" });
  }
});
 

// PAYMENT SUCCESS
app.post('/payment-success', async (req, res) => {
  try {
    const { session_id } = req.body;

    if (!session_id) {
      return res.status(400).send({ success: false, message: 'Missing session_id' });
    }

    // 1) Retrieve session from Stripe
    const session = await stripe.checkout.sessions.retrieve(session_id);

    const contestId = session?.metadata?.contestId;
    const customerEmail = session?.metadata?.customer;

    if (!contestId) {
      return res.status(400).send({ success: false, message: "Missing contestId in session metadata" });
    }

    // 2) Ensure payment completed
    if (session.payment_status !== 'paid') {
      return res.status(400).send({
        success: false,
        message: 'Payment not completed',
        payment_status: session.payment_status,
      });
    }

    // 3) Find contest
    const contest = await contestsCollection.findOne({
      _id: new ObjectId(contestId),
    });

    if (!contest) {
      return res.status(404).send({ success: false, message: 'Contest not found' });
    }

    // 4) Idempotency: if user refreshes page, don’t create duplicate
    const existingOrder = await ordersCollection.findOne({
      transactionId: session.payment_intent,
    });

    let orderId;

    if (!existingOrder) {
      const orderInfo = {
        contestId, // keep as string
        transactionId: session.payment_intent,
        customer: customerEmail,
        status: 'Paid',
        creator: contest.creator,
        name: contest.name,
        image: contest?.image,
        deadline: contest?.deadline,
        category: contest.category,
        participant: 1,
        price: session.amount_total / 100,
        createdAt: new Date().toISOString(),
      };

      const result = await ordersCollection.insertOne(orderInfo);
      orderId = result.insertedId;

      // increment participant
      await contestsCollection.updateOne(
        { _id: new ObjectId(contestId) },
        { $inc: { participant: 1 } }
      );
    } else {
      orderId = existingOrder._id;
    }

    //  return contestId for frontend redirect
    return res.send({
      success: true,
      contestId,
      transactionId: session.payment_intent,
      orderId,
    });
  } catch (err) {
    console.error('Payment success error:', err);
    return res.status(500).send({
      success: false,
      message: 'Internal Server Error while verifying payment',
      error: err.message,
    });
  }
});


// POPULAR CONTESTS
app.get("/popular-contests", async (req, res) => {
  try {
    const result = await contestsCollection
      .find({ status: "approved" })
      .sort({ participant: -1 })
      .limit(5)
      .toArray();

    res.send(result);
  } catch (err) {
    res.status(500).send({ message: "Failed to load popular contests" });
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
