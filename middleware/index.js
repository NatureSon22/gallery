import jwt from "jsonwebtoken";
import AppError from "../helper/AppError.js";

export const protect = (req, res, next) => {
  try {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
      token = req.headers.authorization.split(" ")[1];
    }

    if (!token) {
      return next(new AppError("You are not logged in. Please login to get access.", 401));
    }

    // Verify token
    // Inside middleware/index.js 'protect' function
const decoded = jwt.verify(token, process.env.JWT_SECRET);
console.log("Decoded Token:", decoded); // DEBUG: Check this in your terminal
req.user = decoded; // This makes req.user.account_id available

    // Grant access to the account_id
    req.user = { account_id: decoded.account_id };
    next();
  } catch (err) {
    return next(new AppError("Invalid or expired token.", 401));
  }
};