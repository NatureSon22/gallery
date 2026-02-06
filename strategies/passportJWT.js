import { config } from "dotenv";
config(); // This MUST be before the import of Passport Strategy if possible

import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
import db from "../helper/db.js";

const options = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  // Use a fallback string temporarily to check if it stops the crash
  secretOrKey: process.env.JWT_SECRET, 
};

// Check if secret exists to give a better error message
if (!options.secretOrKey) {
  console.error("FATAL ERROR: JWT_SECRET is not defined in .env file");
}

const jwtStrategy = new JwtStrategy(options, async (req, jwtPayload, done) => {
  try {
    const [rows] = await db.query(
      "SELECT account_id, email FROM tb_account WHERE account_id = ?",
      [jwtPayload.account_id]
    );

    if (rows.length === 0) {
      return done(null, false);
    }

    return done(null, rows[0]);
  } catch (err) {
    return done(err, false);
  }
});

export default jwtStrategy;