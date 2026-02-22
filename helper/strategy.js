import passport from "passport";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { config } from "dotenv";
import db from "../helper/db.js";
import {
  createSession,
  findOrCreateGoogleUser,
} from "../controller/v1/auth.js";

config();

const googleOpt = {
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL,
};

const verifyGoogle = async (accessToken, refreshToken, profile, done) => {
  try {
    // Identify the user
    const { accountId, galleryId, account } =
      await findOrCreateGoogleUser(profile);

    console.log(`account: ${account}`);

    // Create the tokens
    const tokens = await createSession(accountId, galleryId);

    const user = { account_id: accountId, gallery_id: galleryId };

    return done(null, { tokens, user, account });
  } catch (error) {
    if (error.message === "NOT_VERIFIED") {
      return done(null, false, { message: "Account is not verified" });
    }

    if (error.message === "INACTIVE_ACCOUNT") {
      return done(null, false, { message: "Account is inactive" });
    }
    console.error("Google Auth Error:", error);
    return done(error, null);
  }
};

const cookieExtractor = (req) => {
  console.log("All Cookies:", req.cookies);
  console.log("Token:", req.cookies?.access_token);
  return req.cookies?.access_token || null;
};

const jwtOpt = {
  jwtFromRequest: cookieExtractor,
  secretOrKey: process.env.JWT_SECRET,
};

const verifyJwt = async (payload, done) => {
  try {
    const [rows] = await db.execute(
      `SELECT 
         a.account_id,
         a.email,
         a.is_active,
         a.is_verified,
         g.gallery_id
       FROM tb_account a
       LEFT JOIN tb_gallery g 
         ON g.account_id = a.account_id
       WHERE a.account_id = ?
       LIMIT 1`,
      [payload.account_id],
    );

    if (rows.length === 0) {
      return done(null, false);
    }

    const user = rows[0];

    // Block if account is marked as Deleted (0)
    if (user.is_active === 0) {
      return done(null, false, { message: "Account no longer exists." });
    }

    // IMPORTANT: We REMOVED the strict (is_active !== 1) check here.
    // This allows Status 2 users to stay "logged in" just enough
    // to reach the reactivation route in your controller.

    return done(null, user);
  } catch (error) {
    return done(error, false);
  }
};

passport.use(new GoogleStrategy(googleOpt, verifyGoogle));
passport.use(new JwtStrategy(jwtOpt, verifyJwt));

export default passport;
