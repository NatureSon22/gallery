import express from "express";
import { config } from "dotenv";
import router from "./router/index.js";
import db from "./helper/db.js";
import passport from "./helper/strategy.js";
import cors from "cors";
import cookieParser from "cookie-parser";
import errorHandler from "./middleware/errorHandler.js";

config();

const app = express();

// JSON parser
app.use(express.json());

// Attach DB
app.use((req, res, next) => {
  req.db = db;
  next();
});
app.use(cors());
app.use(json());
app.use(cookieParser());
app.use(urlencoded({ limit: "", extended: true }));
app.use(passport.initialize());

app.use("/api/v1", router);

// Error middleware
app.use(errorHandler);

// Start server
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => console.log(`Server is running on port: ${PORT}`));
