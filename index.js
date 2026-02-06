import express, { json, urlencoded } from "express";
import { config } from "dotenv";
import router from "./router/index.js";
import db from "./helper/db.js";
import passport from "./helper/strategy.js";
import cors from "cors";
import cookieParser from "cookie-parser";

config();

const app = express();

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

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server is running on port: ${PORT}`);
});
