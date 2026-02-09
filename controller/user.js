import AppError from "../helper/AppError.js";

// This fixes the "does not provide an export named 'getProfile'" error
export const getProfile = async (req, res, next) => {
  try {
    const { account_id } = req.user;

    const [rows] = await req.db.query(
      `SELECT a.email, a.is_verified, p.display_name, p.age, p.avatar_url 
       FROM tb_account a 
       JOIN tb_profile p ON a.account_id = p.account_id 
       WHERE a.account_id = ?`,
      [account_id]
    );

    if (rows.length === 0) {
      return next(new AppError("User profile not found", 404));
    }

    res.status(200).json({
      status: "success",
      data: rows[0]
    });
  } catch (err) {
    next(err);
  }
};

export const updateProfile = async (req, res, next) => {
  try {
    const { display_name, age } = req.body;
    const { account_id } = req.user;

    // We check affectedRows to ensure the update actually happened
    const [result] = await req.db.query(
      "UPDATE tb_profile SET display_name = ?, age = ?, updated_at = NOW() WHERE account_id = ?",
      [display_name, age, account_id]
    );

    if (result.affectedRows === 0) {
      return next(new AppError("Update failed: Profile not found or no changes made", 400));
    }

    res.status(200).json({
      status: "success",
      message: "Profile updated successfully"
    });
  } catch (err) {
    next(err);
  }
};

// 1. DEACTIVATE (Set is_active = 2)
export const deactivateAccount = async (req, res, next) => {
  try {
    // req.user.account_id comes from your 'protect' middleware
    const [result] = await req.db.query(
      "UPDATE tb_account SET is_active = 2 WHERE account_id = ?",
      [req.user.account_id]
    );

    if (result.affectedRows === 0) {
      return next(new AppError("Account not found", 404));
    }

    res.status(200).json({ 
      status: "success", 
      message: "Account deactivated successfully. Your next login will be blocked." 
    });
  } catch (err) {
    next(err);
  }
};

// 2. REACTIVATE (Set is_active = 1)
export const reactivateAccount = async (req, res, next) => {
  try {
    const [result] = await req.db.query(
      "UPDATE tb_account SET is_active = 1 WHERE account_id = ?",
      [req.user.account_id]
    );

    if (result.affectedRows === 0) return next(new AppError("Account not found", 404));

    res.status(200).json({ 
      status: "success", 
      message: "Welcome back! Account reactivated." 
    });
  } catch (err) {
    next(err);
  }
};

// 3. DELETE (Set is_active = 0 - Soft Delete)
// Add this to controller/user.js
export const deleteAccount = async (req, res, next) => {
  try {
    // Soft delete: set status to 0 and clear refresh token
    const [result] = await req.db.query(
      "UPDATE tb_account SET is_active = 0, refresh_token = NULL WHERE account_id = ?",
      [req.user.account_id]
    );

    if (result.affectedRows === 0) {
      return next(new AppError("Account not found", 404));
    }

    res.status(200).json({ 
      status: "success", 
      message: "Account successfully deleted. You have been logged out." 
    });
  } catch (err) {
    next(err);
  }
};