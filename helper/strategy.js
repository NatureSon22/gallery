import passport from "passport";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { config } from "dotenv";
import db from "../helper/db.js";
import { createSession, findOrCreateGoogleUser } from "../controller/auth.js";

config();

const googleOpt = {
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL,
};

const verifyGoogle = async (accessToken, refreshToken, profile, done) => {
  try {
    // Identify the user
    const accountId = await findOrCreateGoogleUser(profile);

    // Create the tokens
    const tokens = await createSession(accountId);

    console.log(tokens);

    return done(null, { tokens });
  } catch (error) {
    if (error.message === "INACTIVE_ACCOUNT") {
      return done(null, false, { message: "Account is inactive" });
    }
    console.error("Google Auth Error:", error);
    return done(error, null);
  }
};

const jwtOpt = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: process.env.JWT_SECRET,
};

const verifyJwt = async (payload, done) => {
  try {
    const [rows] = await db.execute(
      "SELECT account_id, email, is_active FROM tb_account WHERE account_id = ?",
      [payload.account_id],
    );

    if (rows.length === 0) {
      return done(null, false);
    }

    const user = rows[0];

    // Check if account is active (1 = Active)
    if (user.is_active !== 1) {
      return done(null, false, { message: "Account is inactive or deleted" });
    }

    return done(null, user);
  } catch (error) {
    return done(error, false);
  }
};

passport.use(new GoogleStrategy(googleOpt, verifyGoogle));
passport.use(new JwtStrategy(jwtOpt, verifyJwt));

export default passport;
