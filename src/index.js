import express from "express";
import { connectDb } from "./config/dbConenction.js";
import cors from "cors"
// *********** All-Routes *************
import auth from "./routes/auth.routes.js";
import user from "./routes/user.routes.js";
// *********** All-Routes *************

import cookieParser from "cookie-parser";
const app = express();
// Use cors middleware
const allowedOrigins = [
  'http://localhost:3000', // Replace with your localhost port if different
  'https://learder-board-frontend.vercel.app/' // Replace with your actual Vercel domain
];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (e.g., server-to-server or tools like Postman)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE','PATCH'], // Specify allowed methods
}));


//middle wares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// *********** All-Routes *************

app.get("/", (req, res) => {
  res.json("I'm coming from backend");
});
app.use("/api/auth/v1", auth);
app.use("/api/user/v1", user);

// for wrong apis
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Route not found. Please check the URL and try again.",
  });
});

// Error handling middleware (optional, for other server errors)
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({
    success: false,
    message: "Internal server error.",
    error: err.message,
  });
});

app.listen(3000, async () => {
  console.log("Server is running on port 7000");
  await connectDb();
});
