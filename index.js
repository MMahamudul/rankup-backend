const express = require('express')
const app = express()
const cors = require('cors');
require('dotenv').config();
const { MongoClient, ServerApiVersion } = require('mongodb');
const port = process.env.PORT || 3000

// middleware

app.use(express.json())
app.use(cors())

const uri =`mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.nma65uq.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
const db = client.db('contestDB');
const usersCollection = db.collection('user')


// save or update user info

app.post('/user', async(req, res)=>{
  const userData = req.body;
  userData.created_at = new Date().toISOString;
  userData.last_loggedIn = new Date().toISOString;
  const query = {
    email: userData.email
  }

  const alreadyExist = await usersCollection.findOne(query);
  if(alreadyExist){
    const result = await usersCollection.updateOne(query, {
      $set: {
        last_loggedIn : new Date().toISOString,
      }
    })
    return res.send(result)

  }

  const result = await usersCollection.insertOne(userData);
  res.send(result);
})

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get('/', (req, res) => {
  res.send('Rank-up is running well!')
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
