import AppError from "../helper/AppError.js";
import jwt from "jsonwebtoken";

const protect = (req, res, next) => {
  try {
    const token = req.cookies?.access_token;

    console.log("incoming token " + token);

    if (!token) {
      return next(new AppError("You are not logged in", 401));
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;
      next();
    } catch (err) {
      console.log(err.message);
      return next(new AppError("Token expired or invalid", 401));
    }
  } catch (error) {
    next(error);
  }
};

export default protect;
