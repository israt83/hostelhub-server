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
    "hostel-management-system-ef2f8.web.app",
  ],
  methods: ["POST", "GET", "PUT", "PATCH", "DELETE"],
  credentials: true,
  optionSuccessStatus: 200,
};
app.use(cors(corsOptions));

app.use(express.json());
app.use(cookieParser());

// send email
const sendEmail = (emailAddress, emailData) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    host: 'smtp.gmail.com',
    port: 587,
    secure: false, // Use `true` for port 465, `false` for all other ports
    auth: {
      user: process.env.TRANSPORTER_EMAIL,
      pass: process.env.TRANSPORTER_PASS,
    },
  })

  // verify transporter
  // verify connection configuration
  transporter.verify(function (error, success) {
    if (error) {
      console.log(error)
    } else {
      console.log('Server is ready to take our messages')
    }
  })
  const mailBody = {
    from: `"HostelHub" <${process.env.TRANSPORTER_EMAIL}>`, // sender address
    to: emailAddress, // list of receivers
    subject: emailData.subject, // Subject line
    html: emailData.message, // html body
  }

  transporter.sendMail(mailBody, (error, info) => {
    if (error) {
      console.log(error)
    } else {
      console.log('Email Sent: ' + info.response)
    }
  })
}

// Verify Token Middleware
const verifyToken = async (req, res, next) => {
  const token = req.cookies?.token;
  if (!token) {
    return res.status(401).send({ message: "Unauthorized access" });
  }
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send({ message: "Unauthorized access" });
    }
    req.user = decoded; // Decoded user data from the token
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
  
    const paymentDataCollection = client
      .db("hostelhub")
      .collection("paymentData");
  

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
    app.patch(
      "/users/update/:email",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const email = req.params.email;
        const user = req.body;
        const query = { email };
        const updateDoc = {
          $set: { ...user, timestamp: Date.now() },
        };
        const result = await usersCollection.updateOne(query, updateDoc);
        res.send(result);
      }
    );

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

 
    app.post("/meals/:id/reviews", async (req, res) => {
      const { text, userName, userEmail, userImage } = req.body.review;
      const mealId = req.params.id;

      // Validate the mealId
      if (!ObjectId.isValid(mealId)) {
        return res.status(400).send({ message: "Invalid meal ID" });
      }

      const query = { _id: new ObjectId(mealId) };

      const reviewData = {
        user: {
          displayName: userName || "Anonymous",
          email: userEmail || "",
          photoURL: userImage || "",
        },
        text: text || "",
        createdAt: new Date(),
      };

      const update = {
        $push: {
          reviews: reviewData, // Save the review in the reviews array
        },
      };

      try {
        // Ensure the meal's reviews field is an array before pushing
        const meal = await mealsCollection.findOne(query);

        // If the 'reviews' field is not an array, initialize it as an array
        if (!Array.isArray(meal.reviews)) {
          await mealsCollection.updateOne(query, { $set: { reviews: [] } });
        }

        const result = await mealsCollection.updateOne(query, update);

        if (result.modifiedCount === 0) {
          return res
            .status(404)
            .send({ message: "Meal not found or no changes made" });
        }

        res.send({ message: "Review added successfully", result });
      } catch (error) {
        console.error("Error adding review:", error);
        res.status(500).send({ message: "Error adding review", error });
      }
    });

    // Fetch meals with only the logged-in user's reviews
    app.get("/meals/reviews", verifyToken, async (req, res) => {
      const userEmail = req.user.email; // Extract the email from the JWT token

      try {
        // Fetch meals where the logged-in user has submitted reviews
        const mealsWithUserReviews = await mealsCollection
          .find({ "reviews.user.email": userEmail })
          .toArray();

        res.send(mealsWithUserReviews);
      } catch (error) {
        res.status(500).send({ message: "Server error", error });
      }
    });

    // Update Review
    app.put("/meals/reviews", verifyToken, async (req, res) => {
      const userEmail = req.user.email; // Extract the user's email from the token
      const { mealId, reviewText } = req.body; // Extract mealId and review text from the request

      try {
        const updateResult = await mealsCollection.updateOne(
          { _id: new ObjectId(mealId), "reviews.user.email": userEmail },
          { $set: { "reviews.$.text": reviewText } } // Use the positional operator $ to update the correct review
        );

        if (updateResult.modifiedCount === 1) {
          res.send({ message: "Review updated successfully" });
        } else {
          res.status(404).send({ message: "Review not found" });
        }
      } catch (error) {
        res.status(500).send({ message: "Failed to update review", error });
      }
    });

    app.delete("/meals/reviews", verifyToken, async (req, res) => {
      const userEmail = req.user.email; // Extract the user's email from the token
      const { mealId, reviewId } = req.body; // Extract mealId and reviewId from the request body

      try {
        // Find the meal and check if the review exists for the user
        const meal = await mealsCollection.findOne({
          _id: new ObjectId(mealId),
        });

        if (!meal) {
          return res.status(404).send({ message: "Meal not found" });
        }

        const reviewIndex = meal.reviews.findIndex(
          (review) => review._id === reviewId && review.user.email === userEmail
        );

        if (reviewIndex === -1) {
          return res.status(404).send({ message: "Review not found" });
        }

        // Remove the review from the reviews array
        meal.reviews.splice(reviewIndex, 1);

        // Save the updated meal
        await mealsCollection.updateOne(
          { _id: new ObjectId(mealId) },
          { $set: { reviews: meal.reviews } }
        );

        res.status(200).send({ message: "Review deleted successfully" });
      } catch (error) {
        console.error("Error deleting review:", error);
        res.status(500).send({ error: "Failed to delete review" });
      }
    });


    app.get("/all-meals", async (req, res) => {
      const category = req.query.category;
      const priceRange = req.query.priceRange;
      const search = req.query.search;
      const sortBy = req.query.sortBy || "likes"; // Sorting by likes by default
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 5; // Limit meals per page

      let query = {};

      // Add search functionality
      if (search) {
        query.title = { $regex: search, $options: "i" }; // Search by title (case insensitive)
      }

      // Filter by category
      if (category) {
        query.category = category;
      }

      // Filter by price range
      if (priceRange) {
        const priceParts = priceRange.split("-");
        if (priceParts.length === 2) {
          query.price = {
            $gte: parseFloat(priceParts[0]), // Minimum price
            $lte: parseFloat(priceParts[1]), // Maximum price
          };
        } else if (priceRange === "30") {
          query.price = { $gte: 30 }; // Price greater than $30
        }
      }

      // Sorting meals
      let sortQuery = {};
      if (sortBy === "likes") {
        sortQuery.likes = -1; // Sort by likes in descending order
      } else if (sortBy === "reviews") {
        sortQuery.reviews = -1; // Sort by reviews in descending order
      }

      try {
        // Fetch meals with pagination
        const meals = await mealsCollection
          .find(query)
          .sort(sortQuery)
          .skip((page - 1) * limit) // Pagination logic
          .limit(limit)
          .toArray();

        // Get the total number of meals
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

    // // get all meals for host
    // app.get("/all-meals/", async (req, res) => {
    //   const email = req.params.email;

    //   // let query = { "admin.email": email };
    //   const result = await mealsCollection.find(query).toArray();
    //   res.send(result);
    // });

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

    // Get a single meal data from db using _id
    app.get("/meals/:id", async (req, res) => {
      const id = req.params.id;

      const query = { _id: new ObjectId(id) };

      const result = await mealsCollection.findOne(query);
      res.send(result);
    });

    app.patch("/meals/:id", async (req, res) => {
      const id = req.params.id;
      const { email } = req.body;
      const filter = { _id: new ObjectId(id) };

  
      const meal = await mealsCollection.findOne(filter);
      if (typeof meal.like !== "number") {
        await mealsCollection.updateOne(filter, {
          $set: { like: 0, likedUsers: [] },
        });
      }

      if (meal.likedUsers && meal.likedUsers.includes(email)) {
        return res
          .status(400)
          .json({ message: "User has already liked this meal." });
      }

      const updateDoc = {
        $inc: { like: 1 },
        $push: { likedUsers: email }, 
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

    // // Get all requests for a guest based on email
    // app.get("/my-request/:email", verifyToken, async (req, res) => {
    //   const email = req.params.email;
    //   const query = { email };

    //   try {
    //     const result = await requestMealCollection.find(query).toArray();

    //     // Send the filtered result
    //     res.send(result);
    //   } catch (error) {
    //     console.error("Error fetching requests for the guest:", error);
    //     res
    //       .status(500)
    //       .send({ error: "Unable to fetch requests for the specified guest." });
    //   }
    // });
    // Get all requests for a guest based on email
app.get("/my-request/:email", verifyToken, async (req, res) => {
  const email = req.params.email;
  const query = { email };

  try {
    const result = await requestMealCollection.find(query).toArray();
    res.send(result);
  } catch (error) {
    console.error("Error fetching requests for the guest:", error);
    res.status(500).send({ error: "Unable to fetch requests for the specified guest." });
  }
});


    // Get all meal requests for an admin based on their email
    app.get(
      "/manage-serve-meal/:email",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const email = req.params.email; // Extract the email from request params
        const query = { "admin.email": email }; // Filter by admin's email

        try {
          const result = await requestMealCollection.find().toArray(); // Apply query filter
          res.send(result); // Send the result back to the client
        } catch (error) {
          console.error("Error fetching serve meals for the admin:", error);
          res.status(500).send({
            error: "Unable to fetch serve meals for the specified admin.",
          });
        }
      }
    );

    // Update meal status
    app.patch("/request-meal/:id", async (req, res) => {
      const { id } = req.params;

      // Check if id is a valid ObjectId
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({ error: "Invalid meal ID format." });
      }

      try {
        const result = await requestMealCollection.updateOne(
          { _id: new ObjectId(id) }, // Convert mealId to ObjectId
          { $set: { status: "Served" } }
        );

        if (result.modifiedCount === 0) {
          return res.status(404).send({ error: "Meal request not found." });
        }

        res.send({ message: "Meal status updated successfully.", result });
      } catch (error) {
        console.error("Error updating meal status:", error);
        res.status(500).send({ error: "Unable to update meal status." });
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
      try {
          const meals = await upcomingMealsCollection.find().toArray();
          res.send(meals); // Check the output here
      } catch (error) {
          console.error("Error fetching meals:", error);
          res.status(500).send({ error: "Server error while fetching meals" });
      }
  });
  
    
  app.get("/upcoming-meals/:id", async (req, res) => {
    const id = req.params.id;

    if (!ObjectId.isValid(id)) {
        return res.status(400).send({ error: "Invalid meal ID" });
    }

    // Check if _id is stored as a string
    const query = { _id: id }; // Use this if IDs are stored as strings
    
    try {
        const result = await upcomingMealsCollection.findOne(query);

        if (!result) {
            return res.status(404).send({ error: "Meal not found" });
        }

        res.send(result);
    } catch (error) {
        console.error("Error fetching meal:", error);
        res.status(500).send({ error: "Server error while fetching meal" });
    }
});





app.patch("/upcoming-meals/:id", async (req, res) => {
  const id = req.params.id;
  const { email } = req.body; // Get the user email from the request

  // Ensure the ID is valid
  if (!ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid meal ID" });
  }

  const filter = { _id: new ObjectId(id) };

  try {
      // Find the meal
      const meal = await upcomingMealsCollection.findOne(filter);

      // Check if the meal exists
      if (!meal) {
          return res.status(404).json({ error: "Meal not found" });
      }

      // Ensure that the 'like' field is numeric; initialize if not
      if (typeof meal.like !== "number") {
          await upcomingMealsCollection.updateOne(filter, {
              $set: { like: 0, likedUsers: [] },
          });
      }

      // Check if the user has already liked the meal
      if (meal.likedUsers && meal.likedUsers.includes(email)) {
          return res.status(400).json({ message: "User has already liked this meal." });
      }

      // Increment the like count by 1 and add the user to the likedUsers list
      const updateDoc = {
          $inc: { like: 1 },
          $push: { likedUsers: email }, // Add the user's email to the likedUsers array
      };

      const result = await upcomingMealsCollection.updateOne(filter, updateDoc);
      res.send(result);
  } catch (error) {
      console.error("Error updating likes:", error);
      res.status(500).send({ error: "Server error while updating likes" });
  }
});

// Update meal data
app.put("/upcoming-meals/update/:id", async (req, res) => {
  const id = req.params.id;
  const mealData = req.body;

  // Ensure the ID is valid
  if (!ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid meal ID" });
  }

  const query = { _id: new ObjectId(id) };
  const updateDoc = {
      $set: mealData,
  };

  try {
      const result = await upcomingMealsCollection.updateOne(query, updateDoc);
      res.send(result);
  } catch (error) {
      console.error("Error updating meal:", error);
      res.status(500).send({ error: "Server error while updating meal" });
  }
});


app.post("/upcoming-meals/:id", async (req, res) => {
  const mealId = req.params.id;
  const { email } = req.body;

  if (!ObjectId.isValid(mealId)) {
    return res.status(400).send({ error: "Invalid meal ID" });
  }

  try {
    const meal = await upcomingMealsCollection.findOne({ _id: new ObjectId(mealId) });
    if (!meal) return res.status(404).send({ error: "Meal not found" });

    if (meal.likedUsers?.includes(email)) {
      return res.status(400).send("You have already liked this meal.");
    }

    await upcomingMealsCollection.updateOne(
      { _id: new ObjectId(mealId) },
      {
        $inc: { like: 1 },
        $push: { likedUsers: email }
      }
    );

    res.send({ message: "Like added successfully!" });
  } catch (error) {
    res.status(500).send("Error liking meal.");
  }
});

    // app.post("/upcoming-meals/:id", async (req, res) => {
    //   const id = req.params.id; // Correctly referencing meal ID
    //   const { email } = req.body;
    
    //   try {
    //     // Validate the ObjectId format
    //     if (!ObjectId.isValid(id)) {
    //       return res.status(400).send("Invalid meal ID.");
    //     }
    
    //     // Find the meal by ID
    //     const meal = await upcomingMealsCollection.findOne({ _id: new ObjectId(id) });
    
    //     if (!meal) {
    //       return res.status(404).send("Meal not found.");
    //     }
    
    //     // Check if the user has already liked the meal by email
    //     const alreadyLiked = meal.likedUsers.includes(email);
    //     if (alreadyLiked) {
    //       return res.status(400).send("You have already liked this meal.");
    //     }
    
    //     // Add the email to the meal's likes array and increment like count
    //     await upcomingMealsCollection.updateOne(
    //       { _id: new ObjectId(id) }, // Filter to update the correct meal
    //       {
    //         $inc: { like: 1 },
    //         $push: { likedUsers: email }
    //       }
    //     );
    
    //     res.send({ message: "Like added successfully!" });
    //   } catch (error) {
    //     console.error("Error liking meal:", error);
    //     res.status(500).send("Error liking meal.");
    //   }
    // });

 
    

    // Publish a meal (move from upcomingMealsCollection to mealsCollection)
    app.post("/publish-meal/:id", async (req, res) => {
      const id = req.params.id;
      const meal = await upcomingMealsCollection.findOne({
        _id: new ObjectId(id),
      });

      if (meal) {
        await mealsCollection.insertOne(meal); // Add to main meals collection
        await upcomingMealsCollection.deleteOne({ _id: new ObjectId(id) }); // Remove from upcoming meals
        res.send({ message: "Meal published successfully!" });
      } else {
        res.status(404).send({ message: "Meal not found" });
      }
    });

    // Add a new upcoming meal
    app.post("/upcoming-meals", async (req, res) => {
      const newMeal = req.body;
      const result = await upcomingMealsCollection.insertOne(newMeal);
      res.send(result);
    });

    // Create checkout session
    app.post("/create-checkout-session", async (req, res) => {
      const { package_name, price, email, badge_img } = req.body;
      const formattedPrice = parseInt(Number(price) * 100); // Convert price to cents

      try {
        // Check if the user already has an active subscription
        const existingSubscription = await paymentDataCollection.findOne({
          email,
          payment_status: "paid",
        });

        if (existingSubscription) {
          return res.status(400).json({
            error:
              "You already subscribed to a package. Only one package can be subscribed.",
          });
        }

        const session = await stripe.checkout.sessions.create({
          payment_method_types: ["card"],
          mode: "payment",
          line_items: [
            {
              price_data: {
                currency: "usd",
                product_data: {
                  name: `${package_name} Package`,
                },
                unit_amount: formattedPrice,
              },
              quantity: 1,
            },
          ],
          success_url: `${process.env.CLIENT_URL}complete?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${process.env.CLIENT_URL}`,
          metadata: {
            email,
            package_name,
            badge_img,
          },
        });

        res.json({ url: session.url });
      } catch (error) {
        console.error("Error creating Stripe session:", error.message);
        res.status(500).json({ error: error.message });
      }
    });

    // Route to get payment history of the logged-in user
app.get("/payment-history", async (req, res) => {
  const { email } = req.query;

  if (!email) {
    return res.status(400).json({ error: "Email is required." });
  }

  try {
    // Fetch payment history from the collection
    const payments = await paymentDataCollection.find({ email }).toArray();

    // If no payments found, return a relevant message
    if (payments.length === 0) {
      return res.status(404).json({ message: "No payment history found." });
    }

    res.json(payments);
  } catch (error) {
    console.error("Error fetching payment history:", error);
    res.status(500).json({ error: "Server error while fetching payment history." });
  }
});


   

    // Complete payment and save to database
    app.get("/complete", async (req, res) => {
      const sessionId = req.query.session_id;

      if (!sessionId) {
        return res.status(400).send({ error: "No session ID provided" });
      }

      try {
        const session = await stripe.checkout.sessions.retrieve(sessionId, {
          expand: ["payment_intent"],
        });

        const paymentData = {
          email: session.metadata.email,
          package_name: session.metadata.package_name,
          badge_img: session.metadata.badge_img,
          amount: session.amount_total / 100, // Convert cents to dollars
          currency: session.currency,
          payment_status: session.payment_status,
          session_id: session.id,
          payment_intent_id: session.payment_intent.id,
          payment_date: new Date(),
        };

        await paymentDataCollection.insertOne(paymentData);

        res.status(200).send({ package_name: session.metadata.package_name });
      } catch (error) {
        console.error("Error completing payment:", error);
        res.status(500).json({ error: error.message });
      }
    });

    // Get user subscriptions
    app.get("/user-subscriptions", async (req, res) => {
      const email = req.query.email;

      if (!email) {
        return res.status(400).send({ error: "Email is required" });
      }

      try {
        const userPayments = await paymentDataCollection
          .find({ email })
          .toArray();
        const subscribedPackages = userPayments.map((payment) => ({
          package_name: payment.package_name,
          badge_img: payment.badge_img,
        }));

        res.status(200).json({ subscribedPackages });
      } catch (error) {
        console.error("Error fetching user subscriptions:", error);
        res.status(500).json({ error: error.message });
      }
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
