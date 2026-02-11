import jwt from "jsonwebtoken";
import { config } from "dotenv";

config();

// Creates access and refresh JWT tokens
const generateTokens = (account_id, gallery_id) => {

  //logs
  console.log(`accont_id: ${account_id}`);
  console.log(`gallery_id: ${gallery_id}`);

  // Get secrets from environment variables
  const secret = process.env.JWT_SECRET;
  const refreshSecret = process.env.JWT_REFRESH_SECRET;


   // Stop if secrets are missing
  if (!secret || !refreshSecret) {
    throw new Error("JWT Secrets are missing from .env file");
  }

  // Create short-lived access token
  const accessToken = jwt.sign({ account_id, gallery_id }, secret, {
    expiresIn: "15m",
  });

  // Create long-lived refresh token
  const refreshToken = jwt.sign({ account_id, gallery_id }, refreshSecret, {
    expiresIn: "7d",
  });

  return { accessToken, refreshToken };
};

export default generateTokens;
