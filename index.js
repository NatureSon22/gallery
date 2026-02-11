import express from "express";
import dotenv from "dotenv";
import helmet from "helmet";
import cors from "cors";
import morgan from "morgan";
import logger from "./helper/logger.js";
import authRouter from "./router/auth.js";
import db from "./helper/db.js";
import AppError from "./helper/AppError.js";

// Load env
dotenv.config();

const app = express();
const PORT = process.env.PORT || 8000;
app.use(morgan("combined", { stream: logger.stream }));

/* ---------------------------------------------------
 * SECURITY: HELMET
 * --------------------------------------------------- */
app.use(
  helmet({
    // Disable CSP for now (enable later when frontend is stable)
    contentSecurityPolicy: false,

    // Prevent clickjacking
    frameguard: { action: "deny" },

    // Hide X-Powered-By
    hidePoweredBy: true,

    // Force HTTPS (enable only in production with HTTPS)
    hsts: process.env.NODE_ENV === "production",
  })
);

/* ---------------------------------------------------
 * CORS (adjust origins later)
 * --------------------------------------------------- */
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

/* ---------------------------------------------------
 * BODY PARSERS
 * --------------------------------------------------- */
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

/* ---------------------------------------------------
 * DB CONNECTION PER REQUEST
 * --------------------------------------------------- */
app.use((req, res, next) => {
  req.db = db;
  next();
});

/* ---------------------------------------------------
 * ROUTES
 * --------------------------------------------------- */
app.use("/api/v1/auth", authRouter);

/* ---------------------------------------------------
 * 404 HANDLER
 * --------------------------------------------------- */
app.use((req, res, next) => {
  next(new AppError(`Cannot find ${req.originalUrl}`, 404));
});


/* ---------------------------------------------------
 * GLOBAL ERROR HANDLER
 * --------------------------------------------------- */
app.use((err, req, res, next) => {
  console.error("🔥 ERROR:", err);

  const statusCode = err.statusCode || 500;
  const status = err.status || "error";

  res.status(statusCode).json({
    status,
    message: err.message || "Internal Server Error",
    ...(process.env.NODE_ENV === "development" && { stack: err.stack }),
  });
});

/* ---------------------------------------------------
 * START SERVER
 * --------------------------------------------------- */
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log("SMTP READY: Server is ready to send emails");
});
