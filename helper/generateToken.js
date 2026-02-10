import jwt from "jsonwebtoken";
import { config } from "dotenv";

config();

const generateTokens = (account_id, gallery_id) => {
  console.log(`accont_id: ${account_id}`);
  console.log(`gallery_id: ${gallery_id}`);

  const secret = process.env.JWT_SECRET;
  const refreshSecret = process.env.JWT_REFRESH_SECRET;

  if (!secret || !refreshSecret) {
    throw new Error("JWT Secrets are missing from .env file");
  }

  const accessToken = jwt.sign({ account_id, gallery_id }, secret, {
    expiresIn: "15m",
  });

  const refreshToken = jwt.sign({ account_id, gallery_id }, refreshSecret, {
    expiresIn: "7d",
  });

  return { accessToken, refreshToken };
};

export default generateTokens;
