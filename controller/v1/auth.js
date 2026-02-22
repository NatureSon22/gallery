import argon2 from "argon2";
import jwt from "jsonwebtoken";
import AppError from "../../helper/AppError.js";
import db from "../../helper/db.js";
import generateTokens from "../../helper/generateToken.js";
import crypto from "crypto";
import {
  sendVerificationEmail,
  sendPasswordResetEmail,
} from "../../helper/mailer.js";
import path from "path";
import setAuthCookies from "../../helper/setAuthCookies.js";

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
    const [accountResult] = await req.db.query("INSERT INTO tb_account SET ?", {
      email,
      password: hashedPassword,
      created_at: new Date(),
    });

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
        a.email,
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

    return {
      accountId: user.account_id,
      galleryId: user.gallery_id,
      // account: user,
    };
  }

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
    return { accountId, galleryId, account };
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

export const getLoggedInUser = async (req, res) => {
  res.status(200).json({ status: "success", data: req.user });
};

export const getTokens = (req, res, next) => {
  try {
    const accessToken = req.cookies?.access_token || null;
    const refreshToken = req.cookies?.refresh_token | null;

    if (!accessToken && !refreshToken)
      throw new AppError("No tokens available", 401);

    res
      .status(200)
      .json({ status: "success", data: { accessToken, refreshToken } });
  } catch (error) {
    next(error);
  }
};

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

    if (loginAccount.is_active === 0) {
      return next(new AppError("Invalid credentials", 401));
    }

    // Check if it's a Google-only account
    if (loginAccount.google_id && !loginAccount.password) {
      return next(
        new AppError(
          "Please sign in using the method you used to register.",
          401,
        ),
      );
    }

    // If it's a standard account (or has a password), verify it
    const isPasswordValid = await argon2.verify(
      loginAccount.password,
      password,
    );

    if (!isPasswordValid) {
      return next(new AppError("Invalid credentials", 401));
    }

    if (loginAccount.is_verified === 0) {
      return next(
        new AppError("Please verify your email before logging in.", 403),
      );
    }

    const [profileRows] = await req.db.query(
      `SELECT display_name, age, avatar_url FROM tb_profile WHERE account_id = ?`,
      [loginAccount.account_id],
    );

    const profile = profileRows.length > 0 ? profileRows[0] : {};

    const { accessToken, refreshToken } = generateTokens(
      loginAccount.account_id,
      loginAccount.gallery_id,
    );

    if (loginAccount.is_active === 2) {
      return res.status(403).json({
        status: "fail",
        message:
          "Account deactivated, please reactivate your account to access all features.",
      });
    }

    await req.db.query(
      "UPDATE tb_account SET refresh_token = ? WHERE account_id = ?",
      [refreshToken, loginAccount.account_id],
    );

    setAuthCookies(res, { accessToken, refreshToken });

    res.status(200).json({
      status: "success",
      message: "Login successful",
      data: {
        account_id: loginAccount.account_id,
        google_id: loginAccount.google_id,
        email: loginAccount.email,
        gallery_id: loginAccount.gallery_id,
        display_name: profile.display_name || null,
        age: profile.age || null,
        avatar_url: profile.avatar_url || null,
        is_active: loginAccount.is_active,
      },
    });
  } catch (err) {
    next(err);
  }
};

export const refreshToken = async (req, res, next) => {
  try {
    const incomingToken = req.cookies?.refresh_token;

    if (!incomingToken) {
      return next(new AppError("Refresh token missing", 401));
    }

    // Verify the Token
    let decoded;
    try {
      decoded = jwt.verify(incomingToken, process.env.JWT_REFRESH_SECRET);
    } catch (err) {
      res.clearCookie("access_token");
      res.clearCookie("refresh_token");
      return next(new AppError("Invalid or expired refresh token", 401));
    }

    // Fetch User & Stored Token
    const [userRows] = await req.db.query(
      `SELECT account_id AS accountId, refresh_token AS storedToken 
       FROM tb_account WHERE account_id = ?`,
      [decoded.account_id],
    );

    const user = userRows[0];

    // This prevents "Token Reuse" if a token was stolen or already used
    if (!user || user.storedToken !== incomingToken) {
      res.clearCookie("access_token");
      res.clearCookie("refresh_token");
      return next(new AppError("Invalid or compromised session", 403));
    }

    const tokens = generateTokens(user.accountId, decoded.gallery_id);

    await req.db.query(
      "UPDATE tb_account SET refresh_token = ? WHERE account_id = ?",
      [tokens.refreshToken, user.accountId],
    );

    setAuthCookies(res, tokens);

    res.status(200).json({
      status: "success",
      user: { account_id: user.accountId, gallery_id: decoded.gallery_id },
    });
  } catch (err) {
    res.clearCookie("access_token");
    res.clearCookie("refresh_token");
    next(new AppError("Session expired. Please log in again.", 403));
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
  let resetToken = null;

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
      }
    }

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

export const logout = async (req, res) => {
  const isProd = process.env.NODE_ENV === "production";
  const cookieOpts = {
    httpOnly: true,
    secure: isProd || req.headers["x-forwarded-proto"] === "https",
    sameSite: isProd ? "none" : "lax",
    path: "/",
  };

  try {
    // Revoke the token in the DB so it can't be used again
    if (req.user?.account_id) {
      await req.db.query(
        "UPDATE tb_account SET refresh_token = NULL WHERE account_id = ?",
        [req.user.account_id],
      );
    }
  } catch (err) {
    console.error("Logout DB Error:", err.message);
  }

  // Always clear cookies, even if the DB update failed
  res.clearCookie("access_token", cookieOpts);
  res.clearCookie("refresh_token", cookieOpts);

  return res.status(200).json({
    status: "success",
    message: "Logged out successfully",
  });
};
