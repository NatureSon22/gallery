import "dotenv/config";
import express, { json, urlencoded } from "express";
import path from "path";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import cookieParser from "cookie-parser";
import { rateLimit } from "express-rate-limit";

// Local Imports
import db from "./helper/db.js";
import logger from "./helper/logger.js";
import passport from "./helper/strategy.js";
import router from "./router/index.js";
import errorHandler from "./middleware/errorHandler.js";

const app = express();
const PORT = process.env.PORT || 8000;
const isProd = process.env.NODE_ENV === "production";
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "http://localhost:5173";

// --- 1. Settings & Security ---
app.set("trust proxy", 1);

// Helmet (Uncommented and cleaned up)
// app.use(
//   helmet({
//     xPoweredBy: true,
//     crossOriginResourcePolicy: { policy: "cross-origin" },
//     crossOriginEmbedderPolicy: false,
//     contentSecurityPolicy: {
//       useDefaults: true,
//       directives: {
//         "img-src": ["'self'", "data:", "https:"],
//         "connect-src": ["'self'", FRONTEND_ORIGIN, "https:"],
//       },
//     },
//   })
// );

app.use(cookieParser());

app.use(
  cors({
    origin: FRONTEND_ORIGIN,
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests from this IP, please try again later",
});
app.use("/api/", limiter); // Apply specifically to API routes

// --- 2. Logging & Parsers ---
app.use(morgan("dev"));
app.use(json({ limit: "10mb" }));
app.use(urlencoded({ extended: true, limit: "10mb" }));

// --- 3. Static Files ---
app.use("/uploads", express.static("uploads"));
app.use("/public", express.static(path.resolve(process.cwd(), "public")));

// --- 4. Custom Context & Auth ---
// Attach DB to Request
app.use((req, res, next) => {
  req.db = db;
  next();
});

app.use(passport.initialize());

// --- 5. Routes ---
app.use("/api/v1", router);

// --- 6. Error Handling (Must be last) ---
app.use(errorHandler);

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
