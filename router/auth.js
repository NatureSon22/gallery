import { Router } from "express";
import passport from "../helper/strategy.js";
import validate from "../middleware/validation.js";

import {
  signup,
  login,
  refreshToken,
  verifyEmail,
  forgotPassword,
  resetPassword,
  setPassword,
  getLoggedInUser,
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
  const FRONTEND = (
    process.env.FRONTEND_ORIGIN || "http://localhost:5173"
  ).replace(/\/$/, "");
  passport.authenticate("google", { session: false }, (err, payload, info) => {
    if (err) {
      return res.redirect(
        `${FRONTEND}/?error=${encodeURIComponent(err.message || "auth_error")}`,
      );
    }

    if (!payload) {
      return res.redirect(
        `${FRONTEND}/?error=${encodeURIComponent(info?.message || "Google authentication failed")}`,
      );
    }

    const { tokens } = payload;
    const accessToken = tokens?.accessToken;
    const refreshToken = tokens?.refreshToken;

    const isProd = process.env.NODE_ENV === "production";
    const sameSite = isProd ? "none" : "lax";

    if (accessToken) {
      res.cookie("access_token", accessToken, {
        httpOnly: true,
        secure: isProd,
        sameSite,
        maxAge: 15 * 60 * 1000, // 15 minutes
        path: "/",
      });
    }

    if (refreshToken) {
      res.cookie("refresh_token", refreshToken, {
        httpOnly: true,
        secure: isProd,
        sameSite,
        path: "/api/v1/auth/refresh", // only send to this endpoint
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });
    }

    return res.redirect(FRONTEND);
  })(req, res, next);
});

authRouter.get("/me", protect, getLoggedInUser);

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
