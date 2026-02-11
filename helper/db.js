import { config } from "dotenv";
import mysql from "mysql2/promise";
import fs from "fs";
import path from "path";

config();

const caPath = process.env.CA ? path.resolve(process.cwd(), process.env.CA) : null;
const ssl = caPath && fs.existsSync(caPath) ? { ca: fs.readFileSync(caPath) } : undefined;

const db = mysql.createPool({
  host: process.env.HOST,
  user: process.env.USER,
  database: process.env.DATABASE,
  password: process.env.PASSWORD,
  ...(ssl ? { ssl } : {}),
  waitForConnections: true,
  connectionLimit: 10,
  maxIdle: 10,
  idleTimeout: 60000,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0,
});

export default db;