import argon2 from "argon2";
import passport from "passport";
import jwt from "jsonwebtoken";
import AppError from "../helper/AppError.js";
import db from "../helper/db.js";
import generateTokens from "../helper/generateToken.js";
import crypto from "crypto";
import { sendVerificationEmail, sendPasswordResetEmail } from "../helper/mailer.js";
import { token } from "morgan";


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
      [accountId, verifyToken],
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

  // 1. Check if the email exists in any form
  const [existingUser] = await db.execute(
    "SELECT account_id, google_id, is_active, is_verified FROM tb_account WHERE email = ?",
    [email],
  );

  if (existingUser.length > 0) {
    const user = existingUser[0];

    // 2. PRIORITY CHECK: Is this a manual account?
    // If google_id is NULL, they have a password and shouldn't use Google signup
    if (user.google_id === null) {
      throw new Error(
        "This email is already registered with a password. Please log in manually.",
      );
    }

    // 3. Status checks (Verified/Active)
    if (user.is_verified !== 1) throw new Error("NOT_VERIFIED");
    if (user.is_active === 0) throw new Error("DELETED_ACCOUNT");

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

    const [gallery] = await connection.execute(
      "INSERT INTO tb_gallery (account_id) VALUES (?)",
      [accountId],
    );

    const galleryId = gallery.insertId;

    await connection.commit();
    return { accountId, galleryId };
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
      [email],
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
      const isPasswordValid = await argon2.verify(
        loginAccount.password,
        password,
      );
      if (!isPasswordValid) {
        return next(new AppError("Invalid email or password", 401));
      }
    } else if (!password && loginAccount.google_id) {
      // If they try to manual login to a Google account without a password
      return next(
        new AppError(
          "This account uses Google Login. Please sign in with Google.",
          401,
        ),
      );
    }

    // 4. CHECK VERIFICATION
    if (loginAccount.is_verified === 0) {
      return next(
        new AppError("Please verify your email before logging in.", 403),
      );
    }

    // 5. GENERATE PASSPORT-COMPATIBLE TOKENS
    // We allow Deactivated (2) users to get a token so they can reactivate themselves
    const { accessToken, refreshToken } = generateTokens(
      loginAccount.account_id,
    );

    await req.db.query(
      "UPDATE tb_account SET refresh_token = ? WHERE account_id = ?",
      [refreshToken, loginAccount.account_id],
    );

    // 6. RESPONSE
    // If they are deactivated, we send a success status but a warning message
    // 1. Handle Deactivated Case (Status 2)
    if (loginAccount.is_active === 2) {
      return res.status(403).json({
        status: "fail", // Changed from "success"
        message: "Account deactivated, please reactivate your account to access all features.",
        data: { accessToken, refreshToken },
      });
    }

    // 2. Handle Successful Case (Status 1)
    res.status(200).json({
      status: "success",
      message: "Login successful",
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
      [token],
    );

    if (rows.length === 0) {
      return next(new AppError("Invalid or expired token", 400));
    }

    const accountId = rows[0].account_id;

    // Mark verified
    await req.db.query(
      "UPDATE tb_account SET is_verified = 1 WHERE account_id = ?",
      [accountId],
    );

    // Remove token
    await req.db.query(
      "DELETE FROM tb_email_verifications WHERE account_id = ?",
      [accountId],
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
  let resetToken = null; // ✅ DECLARED IN FUNCTION SCOPE

  try {
    const { email } = req.body;

    const [users] = await req.db.query(
      "SELECT account_id, is_verified, is_active FROM tb_account WHERE email = ?",
      [email]
    );

    if (users.length > 0) {
      const user = users[0];

      // Only allow verified + active accounts
      if (user.is_verified === 1 && user.is_active === 1) {
        resetToken = crypto.randomBytes(32).toString("hex");
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

        // Remove old tokens
        await req.db.query(
          "DELETE FROM tb_password_resets WHERE account_id = ?",
          [user.account_id]
        );

        // Insert new token
        await req.db.query(
          `INSERT INTO tb_password_resets (account_id, reset_token, expires_at)
           VALUES (?, ?, ?)`,
          [user.account_id, resetToken, expiresAt]
        );

        await sendPasswordResetEmail(email, resetToken);

        console.log("🔐 PASSWORD RESET TOKEN:", resetToken);
      }
    }

    // ✅ ALWAYS RETURN SUCCESS
    res.status(200).json({
      status: "success",
      message: "If an account with that email exists, a reset link has been sent.",
      ...(process.env.NODE_ENV === "development" && resetToken
        ? { debug: { resetToken } }
        : {})
    });

  } catch (err) {
    next(err);
  }
};



export const resetPassword = async (req, res, next) => {
  const connection = await req.db.getConnection();
  try {
    const { token, newPassword } = req.body;

    const [rows] = await connection.execute(
      `SELECT account_id FROM tb_password_resets
       WHERE reset_token = ? AND expires_at > NOW()`,
      [token]
    );

    if (rows.length === 0) {
      throw new AppError("Invalid or expired reset token", 400);
    }

    const accountId = rows[0].account_id;

    const hashedPassword = await argon2.hash(newPassword, {
      type: argon2.argon2id,
    });

    await connection.beginTransaction();

    await connection.execute(
      "UPDATE tb_account SET password = ? WHERE account_id = ?",
      [hashedPassword, accountId]
    );

    await connection.execute(
      "DELETE FROM tb_password_resets WHERE account_id = ?",
      [accountId]
    );

    await connection.execute(
      "DELETE FROM tb_refresh_token WHERE account_id = ?",
      [accountId]
    );

    await connection.commit();

    res.status(200).json({
      status: "success",
      message: "Password reset successful. Please log in again.",
    });
  } catch (err) {
    await connection.rollback();
    next(err);
  } finally {
    connection.release();
  }
};

export const setPassword = async (req, res, next) => {
  try {
    const { new_password } = req.validatedBody;
    const { account_id } = req.user; // From your Passport-JWT protect middleware

    // 1. Hash with Argon2
    // Argon2 handles salting automatically
    const hashedPassword = await argon2.hash(new_password);

    // 2. Update the DB
    const [result] = await req.db.query(
      "UPDATE tb_account SET password = ? WHERE account_id = ?",
      [hashedPassword, account_id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        status: "fail", 
        message: "Account not found." 
      });
    }

    res.status(200).json({
      status: "success",
      message: "Password set successfully. You can now login with your email and password."
    });
  } catch (err) {
    next(err);
  }
};