// middleware/auth.js
import passport from "passport";

export const protect = passport.authenticate("jwt", { session: false });