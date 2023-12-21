const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.24f3vqg.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    const userCollection = client.db("gubBossDB").collection("users");
    const foodMenuCollection = client.db("gubBossDB").collection("menu");
    const busCollection = client.db("gubBossDB").collection("bus");
    const cartCollection = client.db("gubBossDB").collection("carts");
    const paymentCollection = client.db("gubBossDB").collection("payments");
    const clubCollection = client.db("gubBossDB").collection("club");

    // jwt related api
    app.post("/jwt", async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "7d",
      });
      res.send({ token });
    });

    // middleware to verify jwt token
    const verifyToken = (req, res, next) => {
      if (!req.headers.authorization) {
        return res.status(401).send({ message: "Unauthorized access" });
      }
      const token = req.headers.authorization.split(" ")[1];
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
          return res.status(401).send({ message: "Unauthorized access" });
        }
        req.decoded = decoded;
        next();
      });
    };

    //  verify admin
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email: email };
      const user = await userCollection.findOne(query);
      const isAdmin = user?.role === "admin";
      if (!isAdmin) {
        return res.status(403).send({ message: "Forbidden access" });
      }
      next();
    };

    //  verify moderator
    const verifyModerator = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email: email };
      const user = await userCollection.findOne(query);
      const isModerator = user?.role === "moderator";
      if (!isModerator) {
        return res.status(403).send({ message: "Forbidden access" });
      }
      next();
    };

    // user related api
    app.get("/users", async (req, res) => {
      const result = await userCollection.find().toArray();
      res.send(result);
    });

    app.get("/users/:email", async (req, res) => {
      const email = req.params.email;
      const query = { email: email };
      const result = await userCollection.findOne(query);
      res.send(result);
    });

    app.get("/users/admin/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      if (email !== req.decoded.email) {
        return res.status(403).send({ message: "Forbidden access" });
      }
      const query = { email: email };
      const user = await userCollection.findOne(query);
      let admin = false;
      if (user) {
        admin = user?.role === "admin";
      }
      res.send({ admin });
    });

    app.get("/users/moderator/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      if (email !== req.decoded.email) {
        return res.status(403).send({ message: "Forbidden access" });
      }
      const query = { email: email };
      const user = await userCollection.findOne(query);
      let moderator = false;
      if (user) {
        moderator = user?.role === "moderator";
      }
      res.send({ moderator });
    });

    app.post("/users", async (req, res) => {
      const user = req.body;
      // insert email to check if user already exists
      const query = { email: user.email };
      const existingUser = await userCollection.findOne(query);
      if (existingUser) {
        return res.send({ message: "user already exists", insertedId: null });
      }
      const result = await userCollection.insertOne(user);
      res.send(result);
    });

    app.patch(
      "/users/admin/:id",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;
        const filter = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: {
            role: "admin",
          },
        };
        const result = await userCollection.updateOne(filter, updateDoc);
        res.send(result);
      }
    );

    app.patch(
      "/users/moderator/:id",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;
        const filter = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: {
            role: "moderator",
          },
        };
        const result = await userCollection.updateOne(filter, updateDoc);
        res.send(result);
      }
    );

    // menu related api
    app.get("/menu", async (req, res) => {
      const result = await foodMenuCollection.find().toArray();
      res.send(result);
    });

    app.post("/menu", verifyToken, verifyModerator, async (req, res) => {
      const newMenuItem = req.body;
      const result = await foodMenuCollection.insertOne(newMenuItem);
      res.json(result);
    });

    // club related api
    app.get("/club", async (req, res) => {
      const result = await clubCollection.find().toArray();
      res.send(result);
    });

    app.post("/club", verifyToken, verifyModerator, async (req, res) => {
      const newMenuItem = req.body;
      const result = await clubCollection.insertOne(newMenuItem);
      res.json(result);
    });

    // cart collection
    app.get("/carts", async (req, res) => {
      const email = req.query.email;
      const query = { email: email };
      const result = await cartCollection.find(query).toArray();
      res.send(result);
    });

    app.post("/carts", async (req, res) => {
      const cartItem = req.body;
      const result = await cartCollection.insertOne(cartItem);
      res.send(result);
    });

    app.delete("/carts/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await cartCollection.deleteOne(query);
      res.send(result);
    });

    // payment related api
    app.get("/payments/:email", verifyToken, async (req, res) => {
      const query = { email: req.params?.email };
      if (req.params.email !== req.decoded.email) {
        return res.status(403).send({ message: "Forbidden access" });
      }
      const result = await paymentCollection.find(query).toArray();
      res.send(result);
    });

    app.post("/payments", async (req, res) => {
      const payment = req.body;
      const paymentResult = await paymentCollection.insertOne(payment);
      // res.send(paymentResult);
      // carefully delete each item from the cart
      // console.log("payment Info", payment);
      const query = {
        _id: {
          $in: payment.cartIds.map((id) => new ObjectId(id)),
        },
      };
      const deleteResult = await cartCollection.deleteMany(query);
      res.send({ paymentResult, deleteResult });
    });

    // bus related api
    app.get("/buses", async (req, res) => {
      const result = await busCollection.find().toArray();
      res.send(result);
    });

    // for admin stats
    app.get("/admin-stats", verifyToken, verifyAdmin, async (req, res) => {
      const users = await userCollection.estimatedDocumentCount();
      const products = await foodMenuCollection.estimatedDocumentCount();
      const bus = await busCollection.estimatedDocumentCount();

      res.send([{ users: users }, { products: products }, { bus: bus }]);
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Gub eco system server is running");
});

app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});
