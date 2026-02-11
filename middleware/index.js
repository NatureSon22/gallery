import passport from "passport";
import AppError from "../helper/AppError.js";

export const protect = (req, res, next) => {
  passport.authenticate("jwt", { session: false }, (err, user, info) => {
    if (err) {
      return next(err);
    }

    // Handle invalid or missing tokens
    if (!user) {
      return next(
        new AppError(
          "You are not logged in or the token is invalid. Please login to get access.",
          401,
        ),
      );
    }

    // Attach the user to the request
    // user = { account_id, gallery_id }
    req.user = user;

    next();
  })(req, res, next);
};
