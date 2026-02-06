import { Router } from "express";
import { signup } from "../controller/auth.js";
import { signupSchema, signupQuerySchema } from "../schemas/auth.schema.js";
import passport from "../helper/strategy.js";
import validate from "../middleware/validation.js";

const authRouter = Router();

// POST   /auth/signup             -> Create tb_account + tb_profile
// POST   /auth/login              -> Validate + Issue JWT & Refresh Token
// GET    /auth/google             -> Passport Google Strategy
// POST   /auth/forgot-password    -> Create tb_password_resets row + Email
// POST   /auth/reset-password     -> Validate reset_token + Update tb_account.password
// POST   /auth/refresh            -> Rotate refresh_token

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
  passport.authenticate("google", {
    failureRedirect: "/login",
    session: false,
  }),
  (req, res) => {
    const { tokens } = req.user;

    res.json({ message: "Login successfull", tokens });
  },
);

export default authRouter;
