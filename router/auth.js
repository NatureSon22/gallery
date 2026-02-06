// router/auth.js
import { Router } from "express";
import { signup } from "../controller/auth.js";
import { signupSchema, signupQuerySchema } from "../schemas/auth.schema.js";
import AppError from "../helper/AppError.js";
import passport from "../helper/strategy.js";

const authRouter = Router();

// Validation middleware
const validate = (schema, type = "body") => (req, res, next) => {
  try {
    const parsed = schema.parse(req[type]);

    // Store validated data safely
    if (type === "body") req.validatedBody = parsed;
    if (type === "query") req.validatedQuery = parsed;

    next();
  } catch (err) {
    console.log("ZOD ERROR:", err);

    const message =
      err?.issues?.[0]?.message ||
      err?.errors?.[0]?.message ||
      err.message ||
      "Validation error";

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
