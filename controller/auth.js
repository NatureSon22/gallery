// controller/auth.js
import argon2 from "argon2";
import AppError from "../helper/AppError.js";
import db from "../helper/db.js";
import generateTokens from "../helper/generateToken.js";

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


export const findOrCreateGoogleUser = async (profile) => {
  const { id, _json } = profile;
  const email = _json.email;

  //  Check if user exists
  const [existingUser] = await db.execute(
    "SELECT account_id, is_active FROM tb_account WHERE google_id = ? OR email = ?",
    [id, email],
  );

  if (existingUser.length > 0) {
    const user = existingUser[0];
    if (user.is_active !== 1) throw new Error("INACTIVE_ACCOUNT");
    return user.account_id;
  }

  // Create User using a Transaction
  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();

    const [account] = await connection.execute(
      "INSERT INTO tb_account (email, google_id, is_verified) VALUES (?, ?, 1)",
      [email, id],
    );
    const accountId = account.insertId;

    await connection.execute(
      "INSERT INTO tb_profile (account_id, display_name, avatar_url) VALUES (?, ?, ?)",
      [accountId, _json.name, _json.picture],
    );

    await connection.execute("INSERT INTO tb_gallery (account_id) VALUES (?)", [
      accountId,
    ]);

    await connection.commit();
    return accountId;
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
};

export const createSession = async (accountId) => {
  const tokens = generateTokens(accountId);
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 7);

  await db.execute(
    "INSERT INTO tb_refresh_token (account_id, refresh_token, expires_at) VALUES (?, ?, ?)",
    [accountId, tokens.refreshToken, expiresAt],
  );

  return tokens;
};