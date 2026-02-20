import AppError from "../helper/AppError.js";
import argon2 from "argon2";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { sendDeactivationEmail } from "../helper/mailer.js";

// Get logged-in user's profile
// controller/profile.js

export const getProfile = async (req, res, next) => {
  try {
    const { account_id } = req.user;

    const [rows] = await req.db.query(
      `SELECT 
        p.avatar_url,
        a.email, 
        p.display_name, 
        p.age,
        a.google_id
       FROM tb_account a
       LEFT JOIN tb_profile p ON a.account_id = p.account_id
       WHERE a.account_id = ?`,
      [account_id],
    );

    if (rows.length === 0) {
      return res
        .status(404)
        .json({ status: "fail", message: "User not found" });
    }

    res.status(200).json({
      status: "success",
      data: rows[0],
    });
  } catch (err) {
    next(err);
  }
};

export const updateProfile = async (req, res, next) => {
  try {
    const { display_name, age } = req.body;
    const { account_id } = req.user;

    // 1. Perform the update
    const [result] = await req.db.query(
      "UPDATE tb_profile SET display_name = ?, age = ?, updated_at = NOW() WHERE account_id = ?",
      [display_name, age, account_id],
    );

    // Note: If display_name and age were ALREADY the same,
    // affectedRows might be 0 in some configurations.
    if (result.matchedRows === 0) {
      return next(new AppError("Profile not found", 404));
    }

    // 2. Fetch the fresh data
    const [updatedRows] = await req.db.query(
      "SELECT display_name, age, updated_at FROM tb_profile WHERE account_id = ?",
      [account_id],
    );

    res.status(200).json({
      status: "success",
      message: "Profile updated successfully",
      data: updatedRows[0], // Return the first (and only) row
    });
  } catch (err) {
    next(err);
  }
};

export const setAvatar = async (req, res, next) => {
  try {
    const { account_id } = req.user;
    const file = req.file;

    console.log(req.file);

    if (!file) throw new AppError("No file uploaded!", 400);

    const avatar_url = `/uploads/${file.filename}`;

    const [result] = await req.db.query(
      "UPDATE tb_profile SET avatar_url = ? WHERE account_id = ?",
      [avatar_url, account_id],
    );

    if (!result || result.affectedRows === 0)
      throw new AppError("Failed to upload avatar", 404);

    res.status(200).json({
      status: "success",
      message: "Uploaded avatar successfully!",
      data: {
        avatar_url,
      },
    });
  } catch (error) {
    console.error(error);
    next(error);
  }
};

// Verify password 
export const verifyPassword = async (req, res, next) => {
  try {
    const { password } = req.validatedBody;
    const { account_id } = req.user;

    // Get the user's hashed password
    const [rows] = await req.db.query(
      "SELECT password, google_id FROM tb_account WHERE account_id = ?",
      [account_id],
    );

    if (rows.length === 0) {
      return next(new AppError("Account not found", 404));
    }

    const account = rows[0];

    // Check if account uses Google login (no password)
    if (account.google_id) {
      return next(
        new AppError(
          "This account uses Google Login and doesn't have a password",
          400,
        ),
      );
    }

    // Verify password
    const isPasswordValid = await argon2.verify(account.password, password);

    if (!isPasswordValid) {
      return next(new AppError("Invalid password", 401));
    }

    // Generate a short-lived verification token (valid for 5 minutes)
    const verificationToken = jwt.sign(
      { account_id, purpose: "deactivation" },
      process.env.JWT_SECRET,
      { expiresIn: "5m" },
    );

    res.status(200).json({
      status: "success",
      message: "Password verified successfully",
      data: {
        verificationToken,
      },
    });
  } catch (err) {
    next(err);
  }
};

// deactivate(2)
export const deactivateAccount = async (req, res, next) => {
  try {
    // Update account status using account_id from JWT
    const [result] = await req.db.query(
      "UPDATE tb_account SET is_active = 2 WHERE account_id = ?",
      [req.user.account_id],
    );

    // If no rows updated, account does not exist
    if (result.affectedRows === 0) {
      return next(new AppError("Account not found", 404));
    }

    res.status(200).json({
      status: "success",
      message:    
        "Account deactivated successfully. Your next login will be unlock the account again.",
    });
  } catch (err) {
    next(err);
  }
};

// Send deactivation confirmation email (Google users only)
export const sendGoogleDeactivationEmail = async (req, res, next) => {
  try {
    const { account_id } = req.user;

    // Fetch email and verify account is a Google user
    const [rows] = await req.db.query(
      "SELECT email, google_id FROM tb_account WHERE account_id = ?",
      [account_id],
    );

    if (rows.length === 0) {
      return next(new AppError("Account not found", 404));
    }

    const account = rows[0];

    if (!account.google_id) {
      return next(
        new AppError(
          "This endpoint is only available for Google accounts",
          400,
        ),
      );
    }

    // Generate a unique deactivation token
    const deactivationToken = crypto.randomBytes(32).toString("hex");

    // Remove any existing tokens for this account
    await req.db.query(
      "DELETE FROM tb_email_verifications WHERE account_id = ?",
      [account_id],
    );

    // Store token in db (expires in 24 hours)
    await req.db.query(
      `INSERT INTO tb_email_verifications (account_id, verify_token, expires_at)
       VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 1 DAY))`,
      [account_id, deactivationToken],
    );

    // Send deactivation confirmation email
    await sendDeactivationEmail(account.email, deactivationToken);

    res.status(200).json({
      status: "success",
      message: "Deactivation confirmation email sent. Please check your inbox.",
    });
  } catch (err) {
    next(err);
  }
};

// Confirm deactivation via email token (Google users only)
export const confirmGoogleDeactivation = async (req, res, next) => {
  try {
    const { token } = req.query;

    if (!token) {
      return next(new AppError("Deactivation token missing", 400));
    }

    // Look up the token
    const [rows] = await req.db.query(
      `SELECT account_id FROM tb_email_verifications
       WHERE verify_token = ? AND expires_at > NOW()`,
      [token],
    );

    if (rows.length === 0) {
      return next(new AppError("Invalid or expired deactivation token", 400));
    }

    const { account_id } = rows[0];

    // Deactivate the account
    const [result] = await req.db.query(
      "UPDATE tb_account SET is_active = 2 WHERE account_id = ?",
      [account_id],
    );

    if (result.affectedRows === 0) {
      return next(new AppError("Account not found", 404));
    }

    // Remove the used token
    await req.db.query(
      "DELETE FROM tb_email_verifications WHERE account_id = ?",
      [account_id],
    );

    res.status(200).json({
      status: "success",
      message: "Account deactivated successfully. Your next login will be blocked.",
    });
  } catch (err) {
    next(err);
  }
};

// reactivate(1)
export const reactivateAccount = async (req, res, next) => {
  try {
    // Update account status using account_id from JWT
    const [result] = await req.db.query(
      "UPDATE tb_account SET is_active = 1 WHERE account_id = ?",
      [req.user.account_id],
    );

    // If no rows updated, account does not exist
    if (result.affectedRows === 0)
      return next(new AppError("Account not found", 404));

    res.status(200).json({
      status: "success",
      message: "Welcome back! Account reactivated.",
    });
  } catch (err) {
    next(err);
  }
};

// delete(0)
export const deleteAccount = async (req, res, next) => {
  try {
    //soft delete, set is_active to 0, delete refreshToken(to invalidate sessions)
    const [result] = await req.db.query(
      "UPDATE tb_account SET is_active = 0, refresh_token = NULL WHERE account_id = ?",
      [req.user.account_id],
    );

    // If no rows updated, account does not exist
    if (result.affectedRows === 0) {
      return next(new AppError("Account not found", 404));
    }

    res.status(200).json({
      status: "success",
      message: "Account successfully deleted. You have been logged out.",
    });
  } catch (err) {
    next(err);
  }
};
