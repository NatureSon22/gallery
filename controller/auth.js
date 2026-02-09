import argon2 from "argon2";
import passport from 'passport';
import jwt from "jsonwebtoken";
import AppError from "../helper/AppError.js";
import db from "../helper/db.js";
import generateTokens from "../helper/generateToken.js";
import crypto from "crypto";
import { sendVerificationEmail } from "../helper/mailer.js";


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

        // Create verification token
    const verifyToken = crypto.randomBytes(32).toString("hex");

    // Store token (expires in 24h)
    await req.db.query(
      `INSERT INTO tb_email_verifications (account_id, verify_token, expires_at)
      VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 1 DAY))`,
      [accountId, verifyToken]
    );

    // Send email
    await sendVerificationEmail(email, verifyToken);


    res.status(201).json({
  status: "success",
  message: "Account created. Please verify your email.",
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

// 2. LOGIN CONTROLLER
export const login = async (req, res, next) => {
  try {
    const { email, password } = req.validatedBody;

    // 1. Fetch user - including google_id and status flags
    const [loginRows] = await req.db.query(
      "SELECT account_id, email, password, google_id, is_active, is_verified FROM tb_account WHERE email = ?",
      [email]
    );

    if (loginRows.length === 0) {
      return next(new AppError("Invalid email or password", 401));
    }

    const loginAccount = loginRows[0];

    // 2. CHECK STATUS: DELETED (0)
    // If status is 0, we act like the account doesn't exist for security
    if (loginAccount.is_active === 0) {
      return next(new AppError("Invalid email or password", 401));
    }

    // 3. VERIFY PASSWORD (Only for manual accounts)
    // If google_id is NULL, they signed up manually and MUST have a password
    if (!loginAccount.google_id) {
      const isPasswordValid = await argon2.verify(loginAccount.password, password);
      if (!isPasswordValid) {
        return next(new AppError("Invalid email or password", 401));
      }
    } else if (!password && loginAccount.google_id) {
        // If they try to manual login to a Google account without a password
        return next(new AppError("This account uses Google Login. Please sign in with Google.", 401));
    }

    // 4. CHECK VERIFICATION
    if (loginAccount.is_verified === 0) {
      return next(new AppError("Please verify your email before logging in.", 403));
    }

    // 5. GENERATE PASSPORT-COMPATIBLE TOKENS
    // We allow Deactivated (2) users to get a token so they can reactivate themselves
    const { accessToken, refreshToken } = generateTokens(loginAccount.account_id);

    await req.db.query(
      "UPDATE tb_account SET refresh_token = ? WHERE account_id = ?",
      [refreshToken, loginAccount.account_id]
    );

    // 6. RESPONSE
    // If they are deactivated, we send a success status but a warning message
    const message = loginAccount.is_active === 2 
      ? "Login successful. Please reactivate your account to access all features." 
      : "Login successful";

    res.status(200).json({
      status: "success",
      message,
      data: { accessToken, refreshToken },
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
      [decoded.account_id],
    );

    if (userRows.length === 0 || userRows[0].refresh_token !== incomingToken) {
      return next(new AppError("Invalid refresh token", 403));
    }

    // Generate new pair (Rotation)
    const tokens = generateTokens(decoded.account_id);

    // Update DB with new refresh token
    await req.db.query(
      "UPDATE tb_account SET refresh_token = ? WHERE account_id = ?",
      [tokens.refreshToken, decoded.account_id],
    );

    res.status(200).json({
      status: "success",
      ...tokens,
    });
  } catch (err) {
    next(new AppError("Invalid or expired refresh token", 403));
  }
};

export const verifyEmail = async (req, res, next) => {
  try {
    const { token } = req.query;

    if (!token) {
      return next(new AppError("Verification token missing", 400));
    }

    const [rows] = await req.db.query(
      `SELECT account_id FROM tb_email_verifications
       WHERE verify_token = ? AND expires_at > NOW()`,
      [token]
    );

    if (rows.length === 0) {
      return next(new AppError("Invalid or expired token", 400));
    }

    const accountId = rows[0].account_id;

    // Mark verified
    await req.db.query(
      "UPDATE tb_account SET is_verified = 1 WHERE account_id = ?",
      [accountId]
    );

    // Remove token
    await req.db.query(
      "DELETE FROM tb_email_verifications WHERE account_id = ?",
      [accountId]
    );

    res.json({
      status: "success",
      message: "Email verified successfully",
    });
  } catch (err) {
    next(err);
  }
};


export const forgotPassword = async (req, res, next) => {
  try {
    const { email } = req.body;

    const [existingUser] = await db.execute(
      "SELECT account_id, is_active, is_verified FROM tb_account WHERE email = ?",
      [email],
    );

    if (existingUser.length > 0) {
      const user = existingUser[0];

      if (user.is_verified === 1 && user.is_active === 1) {
        const resetToken = crypto.randomBytes(32).toString("hex");
        const expiresAt = new Date(Date.now() + 3600000); // 1 hour expiry

        // Clean up any existing tokens for this specific user
        await db.execute(
          "DELETE FROM tb_password_resets WHERE account_id = ?",
          [user.account_id],
        );

        // Insert the new token
        await db.execute(
          "INSERT INTO tb_password_resets (account_id, reset_token, expires_at) VALUES (?, ?, ?)",
          [user.account_id, resetToken, expiresAt],
        );

        // TODO: Send Email logic here
        console.log(`Token for ${email}: ${resetToken}`);
      }
    }

    // Always return success to prevent email fishing
    return res.status(200).json({
      message:
        "If an account with that email exists, a reset link has been sent.",
    });
  } catch (error) {
    next(error);
  }
};

export const resetPassword = async (req, res, next) => {
  const connection = await db.getConnection();
  try {
    const { token, newPassword } = req.body; // 'token' coming from frontend body

    // Find user by 'reset_token' and check expiry
    const [resetRecord] = await connection.execute(
      "SELECT account_id FROM tb_password_resets WHERE reset_token = ? AND expires_at > NOW()",
      [token],
    );

    if (resetRecord.length === 0) {
      throw new AppError("Invalid or expired reset token", 400);
    }

    const accountId = resetRecord[0].account_id;
    const hashedPassword = await argon2.hash(newPassword, {
      type: argon2.argon2id,
    });

    await connection.beginTransaction();

    // Update password
    await connection.execute(
      "UPDATE tb_account SET password = ? WHERE account_id = ?",
      [hashedPassword, accountId],
    );

    // Delete the used token from tb_password_resets
    await connection.execute(
      "DELETE FROM tb_password_resets WHERE account_id = ?",
      [accountId],
    );

    // Invalidate all sessions/refresh tokens
    await connection.execute(
      "DELETE FROM tb_refresh_token WHERE account_id = ?",
      [accountId],
    );

    await connection.commit();
    res.status(200).json({ message: "Password updated successfully." });
  } catch (error) {
    await connection.rollback();
    next(error);
  } finally {
    connection.release();
  }
};
