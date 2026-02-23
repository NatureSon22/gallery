import { Router } from "express";
import passport from "../../helper/strategy.js";
import validate from "../../middleware/validation.js";
import protect from "../../middleware/protect.js";
import setAuthCookies from "../../helper/setAuthCookies.js";

import {
  signup,
  login,
  refreshToken,
  verifyEmail,
  forgotPassword,
  resetPassword,
  setPassword,
  getLoggedInUser,
  logout,
} from "../../controller/v1/auth.js";

import {
  signupSchema,
  signupQuerySchema,
  loginSchema,
  setPasswordSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  verifyEmailSchema,
} from "../../schemas/auth.schema.js";

const authRouter = Router();

authRouter.post("/signup", validate(signupSchema, "body"), validate(signupQuerySchema, "query"), signup);
authRouter.post("/login", validate(loginSchema, "body"), login);
authRouter.post("/refresh", refreshToken);
authRouter.post("/logout", protect, logout);

authRouter.get("/me", protect, getLoggedInUser);

authRouter.get("/verify-email", validate(verifyEmailSchema, "query"), verifyEmail);
authRouter.post("/forgot-password", validate(forgotPasswordSchema, "body"), forgotPassword);
authRouter.patch("/reset-password", validate(resetPasswordSchema, "body"), resetPassword);
authRouter.patch("/set-password", protect, validate(setPasswordSchema, "body"), setPassword);

authRouter.get("/google", passport.authenticate("google", { scope: ["profile", "email"], session: false }));

authRouter.get("/google/callback", (req, res, next) => {
  const FRONTEND = (process.env.FRONTEND_ORIGIN || "http://localhost:5173").replace(/\/$/, "");
  
  passport.authenticate("google", { session: false }, (err, payload, info) => {
    if (err || !payload) {
      const message = err?.message || info?.message || "auth_error";
      return res.redirect(`${FRONTEND}/auth/login?error=${encodeURIComponent(message)}`);
    }

    setAuthCookies(res, { 
      accessToken: payload.tokens?.accessToken, 
      refreshToken: payload.tokens?.refreshToken 
    });

    res.redirect(`${FRONTEND}/auth/googl`);
  })(req, res, next);
});

export default authRouter;