import express from "express";
import dotenv from "dotenv";
import helmet from "helmet";
import cors from "cors";
import logger from "./helper/logger.js";
import { rateLimit } from "express-rate-limit";
import db from "./helper/db.js";

// Load env
dotenv.config();

const app = express();

// Security Middleware
const isProd = process.env.NODE_ENV === "production";
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "http://localhost:5173";
app.use(
  helmet({
    crossOriginEmbedderPolicy: false,
    hsts: isProd
      ? { maxAge: 90 * 24 * 60 * 60, includeSubDomains: true, preload: false }
      : false,
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        // allow same-origin + uploaded files served under /uploads, data URIs and any https image host
        "img-src": ["'self'", "data:", "https:"],
        // allow connections to your API, identity providers, or frontend (adjust exact hosts as required)
        "connect-src": ["'self'", FRONTEND_ORIGIN, "https:"],
      },
    },
  }),
); // Secure HTTP headers
app.use(
  cors({
    origin: true,
    credentials: true,
  }),
); // Allow Cross-Origin requests

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

// Logging (Morgan piped to Winston)
app.use(morgan("combined", { stream: logger.stream }));

// Parsers
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Authentication (Passport)
app.use(passport.initialize());

// Attach DB to Request
app.use((req, res, next) => {
  req.db = db;
  next();
});
app.use(json());
app.use(cookieParser());
app.use(urlencoded({ limit: "", extended: true }));
app.use(passport.initialize());

app.use("/api/v1", router);

// Error Handling
app.use(errorHandler);

// Start Server
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log("SMTP READY: Server is ready to send emails");
});
