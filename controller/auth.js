import argon2 from "argon2";
import jwt from "jsonwebtoken";
import AppError from "../helper/AppError.js";
import db from "../helper/db.js";
import generateTokens from "../helper/generateToken.js";

// 1. SIGNUP CONTROLLER
export const signup = async (req, res, next) => {
  try {
    const { email, password, display_name, age } = req.validatedBody;
    const plan = req.validatedQuery?.plan || "free";

    // Check if email exists
    const [existing] = await req.db.query(
      "SELECT account_id FROM tb_account WHERE email = ?",
      [email],
    );

    if (existing.length > 0) {
      return next(new AppError("Email already registered", 400));
    }

    // Hash password
    const hashedPassword = await argon2.hash(password, {
      type: argon2.argon2id,
    });

    // Insert account
    const [accountResult] = await req.db.query(
      "INSERT INTO tb_account (email, password, created_at) VALUES (?, ?, NOW())",
      [email, hashedPassword],
    );

    const accountId = accountResult.insertId;

    // Insert profile
    await req.db.query(
      "INSERT INTO tb_profile (account_id, display_name, age, updated_at) VALUES (?, ?, ?, NOW())",
      [accountId, display_name || null, age || null],
    );

    // Insert default gallery
    await req.db.query(
      "INSERT INTO tb_gallery (account_id, title, created_at) VALUES (?, 'My Uploads', NOW())",
      [accountId],
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
    "SELECT account_id, is_active, is_verified FROM tb_account WHERE google_id = ? OR email = ?",
    [id, email],
  );

  if (existingUser.length > 0) {
    const user = existingUser[0];
    if (user.is_verified !== 1) throw new Error("NOT_VERIFIED");
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

export const forgotPassword = async (req, res, next) => {
  try {
    // check if email exists in tb account
    // still send email even account doesnt exist
    // token generation
    
  } catch (error) {
    next(error);
  }
};

// 2. LOGIN CONTROLLER
export const login = async (req, res, next) => {
  try {
    const { email, password } = req.validatedBody;

    // 1. Fetch user with status and verification flags
    const [loginRows] = await req.db.query(
      "SELECT account_id, email, password, is_active, is_verified FROM tb_account WHERE email = ?",
      [email]
    );

    if (loginRows.length === 0) {
      return next(new AppError("Invalid email or password", 401));
    }

    const loginAccount = loginRows[0];

    // 2. CHECK STATUS (1=Active, 0=Deactivated, 2=Deleted)
    if (loginAccount.is_active === 2) {
      return next(new AppError("Invalid email or password", 401)); // Treat as non-existent
    }
    
    if (loginAccount.is_active === 0) {
      return next(new AppError("This account is deactivated.", 403));
    }

    // 3. CHECK VERIFICATION (0=Not Verified, 1=Verified)
    if (loginAccount.is_verified === 0) {
      return next(new AppError("Please verify your email before logging in.", 403));
    }

    // 4. VERIFY PASSWORD
    const isPasswordValid = await argon2.verify(loginAccount.password, password);
    if (!isPasswordValid) {
      return next(new AppError("Invalid email or password", 401));
    }

    // 5. GENERATE TOKENS
    const { accessToken, refreshToken } = generateTokens(loginAccount.account_id);

    await req.db.query(
      "UPDATE tb_account SET refresh_token = ? WHERE account_id = ?",
      [refreshToken, loginAccount.account_id]
    );

    res.status(200).json({
      status: "success",
      data: { accessToken, refreshToken }
    });
  } catch (err) {
    next(err);
  }
};

// 3. REFRESH TOKEN CONTROLLER
export const refreshToken = async (req, res, next) => {
  try {
    const { refreshToken: incomingToken } = req.body;

    if (!incomingToken) {
      return next(new AppError("Refresh token required", 400));
    }

    // Verify token signature
    const decoded = jwt.verify(incomingToken, process.env.JWT_REFRESH_SECRET);

    // Check if token exists in DB (revocation check)
    const [userRows] = await req.db.query(
      "SELECT account_id, refresh_token FROM tb_account WHERE account_id = ?",
      [decoded.account_id]
    );

    if (userRows.length === 0 || userRows[0].refresh_token !== incomingToken) {
      return next(new AppError("Invalid refresh token", 403));
    }

    // Generate new pair (Rotation)
    const tokens = generateTokens(decoded.account_id);

    // Update DB with new refresh token
    await req.db.query(
      "UPDATE tb_account SET refresh_token = ? WHERE account_id = ?",
      [tokens.refreshToken, decoded.account_id]
    );

    res.status(200).json({
      status: "success",
      ...tokens,
    });
  } catch (err) {
    next(new AppError("Invalid or expired refresh token", 403));
  }
};