// controller/auth.js
import argon2 from "argon2";
import AppError from "../helper/AppError.js";

export const signup = async (req, res, next) => {
  try {

const { email, password, display_name, age } = req.validatedBody;
const plan = req.validatedQuery?.plan || "free";


    // Check if email exists
    const [rows] = await req.db.query(
      "SELECT account_id FROM tb_account WHERE email = ?",
      [email]
    );

    if (rows.length > 0) {
      return next(new AppError("Email already registered", 400));
    }

    // Hash password
    const hashedPassword = await argon2.hash(password, { type: argon2.argon2id });

    // Insert account
    const [accountResult] = await req.db.query(
      "INSERT INTO tb_account (email, password, created_at) VALUES (?, ?, NOW())",
      [email, hashedPassword]
    );

    const accountId = accountResult.insertId;

    // Insert profile
    await req.db.query(
      "INSERT INTO tb_profile (account_id, display_name, age, updated_at) VALUES (?, ?, ?, NOW())",
      [accountId, display_name || null, age || null]
    );

    // Insert default gallery
    await req.db.query(
      "INSERT INTO tb_gallery (account_id, title, created_at) VALUES (?, 'My Uploads', NOW())",
      [accountId]
    );

    res.status(201).json({
      status: "success",
      message: `Account created successfully with plan "${plan}"`,
    });
  } catch (err) {
    next(err);
  }
};



