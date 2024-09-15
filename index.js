const express = require("express");
const app = express();
require("dotenv").config();
const cors = require("cors");
const nodemailer = require("nodemailer");
const cookieParser = require("cookie-parser");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const port = process.env.PORT || 8000;


// middleware
const corsOptions = {
  origin: [
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:5175",
  ],
  credentials: true,
  optionSuccessStatus: 200,
};
app.use(cors(corsOptions));

app.use(express.json());
app.use(cookieParser());



// Verify Token Middleware
const verifyToken = async (req, res, next) => {
  const token = req.cookies?.token;
  console.log(token);
  if (!token) {
    return res.status(401).send({ message: "unauthorized access" });
  }
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      console.log(err);
      return res.status(401).send({ message: "unauthorized access" });
    }
    req.user = decoded;
    next();
  });
};

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.nghfy93.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    const db = client.db("hostelhub");
    const mealsCollection = db.collection("meals");
    const upcomingMealsCollection = db.collection("upcomingMeals");
    const usersCollection = db.collection("users");
    const requestMealCollection = db.collection("request-meal");
    

    
    // verify admin middleware
    const verifyAdmin = async (req, res, next) => {
      console.log("hello");
      const user = req.user;
      const query = { email: user?.email };
      const result = await usersCollection.findOne(query);
      console.log(result?.role);
      if (!result || result?.role !== "admin")
        return res.status(401).send({ message: "unauthorized access!!" });

      next();
    };
  
    // auth related api
    app.post("/jwt", async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "365d",
      });
      res
        .cookie("token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        })
        .send({ success: true });
    });
    // Logout
    app.get("/logout", async (req, res) => {
      try {
        res
          .clearCookie("token", {
            maxAge: 0,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
          })
          .send({ success: true });
        console.log("Logout successful");
      } catch (err) {
        res.status(500).send(err);
      }
    });

    

    // save a user data in db
    app.put("/user", async (req, res) => {
      const user = req.body;

      const query = { email: user?.email };

      // check if user already exists in db
      const isExist = await usersCollection.findOne(query);
      if (isExist) {
        if (user.status === "Requested") {
          // if existing user try to change his role
          const result = await usersCollection.updateOne(query, {
            $set: { status: user?.status },
          });
          return res.send(result);
        } else {
          // if existing user login again
          return res.send(isExist);
        }
      }

      // save user for the first time
      const options = { upsert: true };
      const updateDoc = {
        $set: {
          ...user,

          timestamp: Date.now(),
        },
      };
      const result = await usersCollection.updateOne(query, updateDoc, options);
      // welcome new user
      sendEmail(user?.email, {
        subject: "Welcome to HostelHub!",
        message: `Hope you will find you destination`,
      });
      res.send(result);
    });

    // get a user info by email from db
    app.get("/user/:email", async (req, res) => {
      const email = req.params.email;
      const result = await usersCollection.findOne({ email });
      res.send(result);
    });

    // get all users data from db
    app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
      const result = await usersCollection.find().toArray();
      res.send(result);
    });

    //update a user role
    app.patch("/users/update/:email", verifyToken,verifyAdmin, async (req, res) => {
      const email = req.params.email;
      const user = req.body;
      const query = { email };
      const updateDoc = {
        $set: { ...user, timestamp: Date.now() },
      };
      const result = await usersCollection.updateOne(query, updateDoc);
      res.send(result);
    });

    // Get all meals from db
    app.get("/meals", async (req, res) => {
      const category = req.query.category;
      console.log(category);
      let query = {};
      if (category && category !== "null") query = { category };
      const result = await mealsCollection.find(query).toArray();
      res.send(result);
    });

    // Save a meal data in db
    app.post("/meals", async (req, res) => {
      const mealData = req.body;
      const result = await mealsCollection.insertOne(mealData);
      res.send(result);
    });

  
    

    app.get("/all-meals", async (req, res) => {
      const category = req.query.category;
      const priceRange = req.query.priceRange;
      const search = req.query.search;
      const sortBy = req.query.sortBy || "likes"; // Sorting by likes by default
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 5;

      let query = {};
      if (search) {
        query.title = { $regex: search, $options: "i" };
      }
      if (category) {
        query.category = category;
      }
      if (priceRange) {
        const priceParts = priceRange.split("-");
        if (priceParts.length === 2) {
          query.price = {
            $gte: parseFloat(priceParts[0]),
            $lte: parseFloat(priceParts[1]),
          };
        } else if (priceRange === "30") {
          query.price = { $gte: 30 };
        }
      }

      let sortQuery = {};
      if (sortBy === "likes") {
        sortQuery.likes = -1; // Sorting by likes in descending order
      } else if (sortBy === "reviews") {
        sortQuery.reviews = -1; // Sorting by reviews in descending order
      }

      try {
        const meals = await mealsCollection
          .find(query)
          .sort(sortQuery)
          .skip((page - 1) * limit)
          .limit(limit)
          .toArray();

        const totalMeals = await mealsCollection.countDocuments(query);

        res.send({ meals, totalMeals });
      } catch (error) {
        console.error("Error fetching meals:", error);
        res.status(500).send("Failed to retrieve meals data.");
      }
    });

    // Get all meals data count from db
    app.get("/meals-count", async (req, res) => {
      const filter = req.query.filter;
      const search = req.query.search;
      let query = {
        title: { $regex: search, $options: "i" },
      };
      if (filter) query.category = filter;
      const count = await mealsCollection.countDocuments(query);

      res.send({ count });
    });

    // get all rooms for host
    app.get("/all-meals/", async (req, res) => {
      const email = req.params.email;

      // let query = { "admin.email": email };
      const result = await mealsCollection.find(query).toArray();
      res.send(result);
    });

    app.delete("/meals/:id", verifyToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      try {
        const result = await mealsCollection.deleteOne(query);
        if (result.deletedCount === 1) {
          res.status(200).send({ message: "Meal deleted successfully" });
        } else {
          res.status(404).send({ message: "Meal not found" });
        }
      } catch (error) {
        res.status(500).send({ error: "Failed to delete meal" });
      }
    });

    // Get a single room data from db using _id
    app.get("/meals/:id", async (req, res) => {
      const id = req.params.id;

      const query = { _id: new ObjectId(id) };

      const result = await mealsCollection.findOne(query);
      res.send(result);
    });

    app.patch("/meals/:id", async (req, res) => {
      const id = req.params.id;
      const { email } = req.body; // Get the user email from the request
      const filter = { _id: new ObjectId(id) };

      // Ensure that the 'like' field is numeric
      const meal = await mealsCollection.findOne(filter);
      if (typeof meal.like !== "number") {
        await mealsCollection.updateOne(filter, {
          $set: { like: 0, likedUsers: [] },
        });
      }

      // Check if the user has already liked the meal
      if (meal.likedUsers && meal.likedUsers.includes(email)) {
        return res
          .status(400)
          .json({ message: "User has already liked this meal." });
      }

      // Increment the like count by 1 and add the user to the likedUsers list
      const updateDoc = {
        $inc: { like: 1 },
        $push: { likedUsers: email }, // Add the user's email to the likedUsers array
      };

      const result = await mealsCollection.updateOne(filter, updateDoc);
      res.send(result);
    });

    
    // update meal data
    app.put("/meals/update/:id", verifyToken, async (req, res) => {
      const id = req.params.id;
      const mealData = req.body;
      const query = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: mealData,
      };
      const result = await mealsCollection.updateOne(query, updateDoc);
      res.send(result);
    });


    

    // Save a request data in db
    app.post("/request-meal", verifyToken, async (req, res) => {
      const requestData = req.body;
      console.log("Request data received:", requestData); // Debug log
      try {
        const result = await requestMealCollection.insertOne(requestData);
        res.send(result);
      } catch (error) {
        console.error("Error saving meal request:", error);
        res.status(500).send({ error: "Unable to save meal request." });
      }
    });

    // Get all requests for a guest based on email
    app.get("/my-request/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const query = { email };

      try {
        const result = await requestMealCollection.find(query).toArray();

        // Send the filtered result
        res.send(result);
      } catch (error) {
        console.error("Error fetching requests for the guest:", error);
        res
          .status(500)
          .send({ error: "Unable to fetch requests for the specified guest." });
      }
    });

   

    
    // Get all meal requests for an admin based on their email
    app.get("/manage-serve-meal/:email", verifyToken,verifyAdmin, async (req, res) => {
      const email = req.params.email; // Extract the email from request params
      const query = { "admin.email": email }; // Filter by admin's email
     
      try {
        const result = await requestMealCollection.find().toArray(); // Apply query filter
        res.send(result); // Send the result back to the client
      } catch (error) {
        console.error("Error fetching serve meals for the admin:", error);
        res
          .status(500)
          .send({
            error: "Unable to fetch serve meals for the specified admin.",
          });
      }
    });

    app.patch("/request-meal/:mealId", async (req, res) => {
      // const mealId =  mongodb.ObjectId(req.params.mealId);
      console.log("Updating meal ID:", mealId);
      try {
        const result = await requestMealCollection.updateOne(
          { _id: mealId },
          { $set: { status: "Served" } }
        );
        console.log("Update result:", result);
        res.send(result);
      } catch (error) {
        console.error("Error updating meal status:", error);
        res.status(500).send({
          error: "Unable to update meal status.",
        });
      }
    });
    

    // delete a request
    app.delete("/request-meal/:id", verifyToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await requestMealCollection.deleteOne(query);
      res.send(result);
    });

    


    app.get("/upcoming-meals", async (req, res) => {
      const result = await upcomingMealsCollection.find().toArray();
      res.send(result);
    });

    app.post("/upcoming-meals/:mealId/like", async (req, res) => {
      const { mealId } = req.params;
      const { userId } = req.body;

      // Check if the user is premium
      const user = await usersCollection.findOne({ _id: userId });
      if (!["Silver", "Gold", "Platinum"].includes(user.subscription)) {
        return res.status(403).send("Only premium users can like meals");
      }

      // Check if the user has already liked the meal
      const meal = await upcomingMealsCollection.findOne({ _id: mealId });
      if (meal.likes.includes(userId)) {
        return res.status(400).send("User has already liked this meal");
      }

      // Add like to the meal
      const result = await upcomingMealsCollection.updateOne(
        { _id: mealId },
        { $push: { likes: userId } }
      );
      res.send(result);
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Hello from Hostel Management Server..");
});



app.listen(port, () => {
  console.log(`Hostel Management is running on port ${port}`);
});
