import jwt from "jsonwebtoken";
import { config } from "dotenv";

config();

const generateTokens = (account_id) => {
  const accessToken = jwt.sign(
    { account_id: account_id },
    process.env.JWT_SECRET,
    {
      expiresIn: "15m",
    },
  );

  const refreshToken = jwt.sign(
    { account_id: account_id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: "7d" },
  );

  return { accessToken, refreshToken };
};

export default generateTokens;
