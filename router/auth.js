import { Router } from "express";
import passport from "../helper/strategy.js";

const authRouter = Router();

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
