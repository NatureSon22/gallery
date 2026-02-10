import express, { json, urlencoded } from "express";
import { config } from "dotenv";
import helmet from "helmet";
import morgan from "morgan";
import { rateLimit } from "express-rate-limit"; // Requires: npm i express-rate-limit
import router from "./router/index.js";
import db from "./helper/db.js";
import cors from "cors";
import cookieParser from "cookie-parser";
import errorHandler from "./middleware/errorHandler.js";
import logger from "./helper/logger.js";
import passport from "./helper/strategy.js";
import path from "path";

config();

const app = express();

// Security Middleware
app.use(helmet()); // Secure HTTP headers
app.use(cors()); // Allow Cross-Origin requests

// serve uploads folder
app.use("/uploads", express.static(path.resolve(process.cwd(), "uploads")));

// Rate Limiting (Prevent Brute Force)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again later",
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// 2. Logging (Morgan piped to Winston)
app.use(morgan("combined", { stream: logger.stream }));

// 3. Parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 4. Authentication (Passport)
app.use(passport.initialize());

// 5. Attach DB to Request
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

// 7. Error Handling
app.use(errorHandler);

// Start Server
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
  logger.info(`Server is running on port: ${PORT}`);
});
