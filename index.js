import express from "express";
import { config } from "dotenv";
import router from "./router/index.js";
import db from "./helper/db.js";

config();

const app = express();

app.use((req, res, next) => {
  req.db = db;
  next();
});
app.use("/api/v1", router);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server is running on port: ${PORT}`);
});
