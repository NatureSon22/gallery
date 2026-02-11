import { Router } from "express";
import passport from "../helper/strategy.js";
import validate from "../middleware/validation.js";
import { config } from "dotenv";

config();

import {
  signup,
  login,
  refreshToken,
  verifyEmail,
  forgotPassword,
  resetPassword,
  setPassword,
} from "../controller/auth.js";

import {
  signupSchema,
  signupQuerySchema,
  loginSchema,
  setPasswordSchema,
} from "../schemas/auth.schema.js";
import { protect } from "../middleware/index.js";

const authRouter = Router();

/*
  Public - Account creation & authentication
  - signup -> create account/profile
  - login  -> issue access + refresh tokens
  - refresh-> rotate refresh token
*/
authRouter.post(
  "/signup",
  validate(signupSchema, "body"),
  validate(signupQuerySchema, "query"),
  signup,
);
authRouter.post("/login", validate(loginSchema, "body"), login);
authRouter.post("/refresh", refreshToken);

/*
  OAuth (Google)
  - GET /google         -> start OAuth
  - GET /google/callback-> handle callback, return tokens (no session)
*/
authRouter.get(
  "/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
    session: false,
  }),
);
authRouter.get("/google/callback", (req, res, next) => {
  passport.authenticate("google", { session: false }, (err, user, info) => {
    if (err) {
      return res.status(400).json({
        status: "error",
        message: err.message,
      });
    }

    // Handle Authentication Failure (e.g., User denied access)
    if (!user) {
      return res.status(401).json({
        status: "fail",
        message: info?.message || "Google authentication failed",
      });
    }

    // 3. Success: Manual response with tokens
    // 'user' here contains the { tokens } object returned from verifyGoogle strategy
    res.status(200).json({
      status: "success",
      data: { tokens: user.tokens },
    });
  })(req, res, next);
});

/*
  Password / Verification
  - forgot-password, reset-password, verify-email
*/
authRouter.post("/forgot-password", forgotPassword);
authRouter.post("/reset-password", resetPassword);
authRouter.get("/verify-email", verifyEmail);

authRouter.post(
  "/set-password",
  protect,
  validate(setPasswordSchema),
  setPassword,
);

export default authRouter;
