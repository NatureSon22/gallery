import { Router } from "express";
import passport from "../helper/strategy.js";
import validate from "../middleware/validation.js";
import {
  signup,
  login,
  refreshToken,
  verifyEmail,
  forgotPassword,
  resetPassword
} from "../controller/auth.js";

import { signupSchema, signupQuerySchema, loginSchema } from "../schemas/auth.schema.js";


const authRouter = Router();

// POST   /auth/signup             -> Create tb_account + tb_profile
// POST   /auth/login              -> Validate + Issue JWT & Refresh Token
// GET    /auth/google             -> Passport Google Strategy
// POST   /auth/forgot-password    -> Create tb_password_resets row + Email
// POST   /auth/reset-password     -> Validate reset_token + Update tb_account.password
// POST   /auth/refresh            -> Rotate refresh_token

// POST /auth/signup
authRouter.post(
  "/signup",
  validate(signupSchema, "body"),
  validate(signupQuerySchema, "query"),
  signup,
);

authRouter.get(
  "/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
    session: false,
  }),
);

authRouter.get(
  "/google/callback",
  (req, res, next) => {
    passport.authenticate("google", { session: false }, (err, user, info) => {
      // 1. Handle Errors (e.g., Database errors or "Email already registered")
      if (err) {
        return res.status(400).json({
          status: "error",
          message: err.message
        });
      }

      // 2. Handle Authentication Failure (e.g., User denied access)
      if (!user) {
        return res.status(401).json({
          status: "fail",
          message: info?.message || "Google authentication failed"
        });
      }

      // 3. Success: Manual response with tokens
      // 'user' here contains the { tokens } object returned from your verifyGoogle strategy
      res.status(200).json({
        status: "success",
        message: "Login successful",
        data: user.tokens
      });
    })(req, res, next);
  }
);

// Forgot Password
authRouter.post("/forgot-password", forgotPassword);

// Reset Password
authRouter.post("/reset-password", resetPassword);


// POST /auth/login
authRouter.post(
  "/login",
  validate(loginSchema, "body"),
  login
);

// POST /auth/refresh
authRouter.post(
  "/refresh",
  refreshToken
);

authRouter.get("/verify-email", verifyEmail);


export default authRouter;