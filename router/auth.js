// router/auth.js
import { Router } from "express";
import { signup, login, refreshToken } from "../controller/auth.js";
import { signupSchema, signupQuerySchema, loginSchema } from "../schemas/auth.schema.js";
import AppError from "../helper/AppError.js";


// POST   /auth/signup             -> Create tb_account + tb_profile
// POST   /auth/login              -> Validate + Issue JWT & Refresh Token
// GET    /auth/google             -> Passport Google Strategy
// POST   /auth/forgot-password    -> Create tb_password_resets row + Email
// POST   /auth/reset-password     -> Validate reset_token + Update tb_account.password
// POST   /auth/refresh            -> Rotate refresh_token



const authRouter = Router();

// Validation middleware (Your original one)
const validate = (schema, type = "body") => (req, res, next) => {
  try {
    const parsed = schema.parse(req[type]);
    if (type === "body") req.validatedBody = parsed;
    if (type === "query") req.validatedQuery = parsed;
    next();
  } catch (err) {
    const message = err?.issues?.[0]?.message || "Validation error";
    return next(new AppError(message, 400));
  }
};

// POST /auth/signup
authRouter.post(
  "/signup",
  validate(signupSchema, "body"),
  validate(signupQuerySchema, "query"),
  signup
);

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

export default authRouter;