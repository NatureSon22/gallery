import "dotenv/config";
import express, { json, urlencoded } from "express";
import path from "path";
import cors from "cors";
import corsOptions from "./config/cors.js";
import helmet from "helmet";
import morgan from "morgan";
import cookieParser from "cookie-parser";
import { rateLimit } from "express-rate-limit";

import db from "./helper/db.js";
import passport from "./helper/strategy.js";
import router from "./router/router.js";
import errorHandler from "./middleware/errorHandler.js";
import helmetConfig from "./config/helmet.js";
import configureCron from "./helper/purgeUsers.js";

const app = express();
const PORT = process.env.PORT || 8000;

app.set("trust proxy", 1);

app.use(cookieParser());

// CORS Configuration
app.use(cors(corsOptions));

app.use(helmet(helmetConfig));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests, please try again later",
});
app.use("/api/", limiter);

app.use(morgan("dev"));
app.use(json({ limit: "10mb" }));
app.use(urlencoded({ extended: true, limit: "10mb" }));

app.use("/uploads", express.static("uploads"));
app.use("/public", express.static(path.resolve(process.cwd(), "public")));

app.use((req, res, next) => {
  req.db = db;
  next();
});


app.use(passport.initialize());

app.use("/api", router);

//configureCron(db);

app.use(errorHandler);

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
