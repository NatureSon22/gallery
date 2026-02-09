import jwt from "jsonwebtoken";
import passport from 'passport';
import AppError from "../helper/AppError.js";



// This replaces your manual jwt.verify logic
export const protect = (req, res, next) => {
  passport.authenticate('jwt', { session: false }, (err, user, info) => {
    // 1. Handle errors (like connection issues)
    if (err) {
      return next(err);
    }

    // 2. Handle invalid or missing tokens
    if (!user) {
      return next(new AppError("You are not logged in or the token is invalid. Please login to get access.", 401));
    }

    // 3. Attach the user to the request
    // This ensures req.user.account_id is available in your controllers
    req.user = user;
    
    next();
  })(req, res, next);
};