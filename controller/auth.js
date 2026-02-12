import argon2 from "argon2";
import jwt from "jsonwebtoken";
import AppError from "../helper/AppError.js";
import db from "../helper/db.js";
import generateTokens from "../helper/generateToken.js";
import crypto from "crypto";
import {
  sendVerificationEmail,
  sendPasswordResetEmail,
} from "../helper/mailer.js";
import path from "path";

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

  // Fetch account + gallery (if any)
  const [rows] = await db.execute(
    `SELECT 
        a.account_id,
        a.google_id,
        a.is_active,
        a.is_verified,
        g.gallery_id
     FROM tb_account a
     LEFT JOIN tb_gallery g 
       ON g.account_id = a.account_id
     WHERE a.email = ?
     LIMIT 1`,
    [email],
  );

  if (rows.length > 0) {
    const user = rows[0];

    if (user.is_verified !== 1) throw new Error("NOT_VERIFIED");
    if (user.is_active === 0) throw new Error("DELETED_ACCOUNT");

    console.log(user);

    return { accountId: user.account_id, galleryId: user.gallery_id };
  }

  // 2) Create User using a Transaction
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

export const createSession = async (accountId, galleryId) => {
  const tokens = generateTokens(accountId, galleryId);
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 7);

  await db.execute(
    "INSERT INTO tb_refresh_token (account_id, refresh_token, expires_at) VALUES (?, ?, ?)",
    [accountId, tokens.refreshToken, expiresAt],
  );

  return tokens;
};

//LOGIN CONTROLLER
export const login = async (req, res, next) => {
  try {
    const { email, password } = req.validatedBody;

    // Fetch users - including google_id
    const [loginRows] = await req.db.query(
      `SELECT 
         a.account_id, a.email, a.password, a.google_id, a.is_active, a.is_verified,
         g.gallery_id
       FROM tb_account a
       LEFT JOIN tb_gallery g ON g.account_id = a.account_id
       WHERE a.email = ?
       LIMIT 1`,
      [email],
    );

    if (loginRows.length === 0) {
      return next(new AppError("Invalid credentials", 401));
    }

    const loginAccount = loginRows[0];

    // if the account is deleted(0)
    if (loginAccount.is_active === 0) {
      return next(new AppError("Invalid credentials", 401));
    }

    // verify passswords of account made from manual signup
    // If google_id is null, they signed up manually and must have a password
    if (!loginAccount.google_id) {
      const isPasswordValid = await argon2.verify(
        loginAccount.password,
        password,
      );
      if (!isPasswordValid) {
        return next(new AppError("Invalid credentials", 401));
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

    // checks if the email is verified(1) or not(0)
    if (loginAccount.is_verified === 0) {
      return next(
        new AppError("Please verify your email before logging in.", 403),
      );
    }

    // generate passport compatible tokens
    // allow deactivated(2) users to get a token so they can reactivate
    const { accessToken, refreshToken } = generateTokens(
      loginAccount.account_id,
      loginAccount.gallery_id,
    );

    // TODO: check this
    await req.db.query(
      "UPDATE tb_account SET refresh_token = ? WHERE account_id = ?",
      [refreshToken, loginAccount.account_id],
    );

    // if the account is deactivated(2), send a fail and a warning message
    if (loginAccount.is_active === 2) {
      return res.status(403).json({
        status: "fail",
        message:
          "Account deactivated, please reactivate your account to access all features."
      });
    }

    // successful login for active(1)
    res.status(200).json({
      status: "success",
      message: "Login successful",
      data: { accessToken, refreshToken },
    });
  } catch (err) {
    next(err);
  }
};

//REFRESH TOKEN CONTROLLER
export const refreshToken = async (req, res, next) => {
  try {
    const { refreshToken: incomingToken } = req.body;

    if (!incomingToken) {
      return next(new AppError("Refresh token required", 400));
    }

    // Verify token signature
    const decoded = jwt.verify(incomingToken, process.env.JWT_REFRESH_SECRET);

    // Check if token exists in db
    const [userRows] = await req.db.query(
      "SELECT account_id, refresh_token FROM tb_account WHERE account_id = ?",
      [decoded.account_id],
    );

    if (userRows.length === 0 || userRows[0].refresh_token !== incomingToken) {
      return next(new AppError("Invalid refresh token", 403));
    }

    // Generate new pair
    const tokens = generateTokens(decoded.account_id, decoded.gallery_id);

    // Update db with new refresh token
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

    const __dirname = path.resolve();
    res.sendFile(path.join(__dirname, "/public/verified.html"));
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
      [email],
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
          [user.account_id],
        );

        // Insert new token
        await req.db.query(
          `INSERT INTO tb_password_resets (account_id, reset_token, expires_at)
           VALUES (?, ?, ?)`,
          [user.account_id, resetToken, expiresAt],
        );

        await sendPasswordResetEmail(email, resetToken);

        console.log("🔐 PASSWORD RESET TOKEN:", resetToken);
      }
    }

    // ✅ ALWAYS RETURN SUCCESS
    res.status(200).json({
      status: "success",
      message:
        "If an account with that email exists, a reset link has been sent.",
      ...(process.env.NODE_ENV === "development" && resetToken
        ? { debug: { resetToken } }
        : {}),
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
      [token],
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
      [hashedPassword, accountId],
    );

    await connection.execute(
      "DELETE FROM tb_password_resets WHERE account_id = ?",
      [accountId],
    );

    await connection.execute(
      "DELETE FROM tb_refresh_token WHERE account_id = ?",
      [accountId],
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

//set password
export const setPassword = async (req, res, next) => {
  try {
    // Get new password from validated request body
    const { new_password } = req.validatedBody;

    // Get account_id from JWT middleware
    const { account_id } = req.user;

    // Hash the new password
    const hashedPassword = await argon2.hash(new_password);

    // Update password in database
    const [result] = await req.db.query(
      "UPDATE tb_account SET password = ? WHERE account_id = ?",
      [hashedPassword, account_id],
    );

    // If no rows updated, account does not exist
    if (result.affectedRows === 0) {
      return res.status(404).json({
        status: "fail",
        message: "Account not found.",
      });
    }

    res.status(200).json({
      status: "success",
      message:
        "Password set successfully. You can now login with your email and password.",
    });
  } catch (err) {
    next(err);
  }
};
