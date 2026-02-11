import AppError from "../helper/AppError.js";

// Get logged-in user's profile
export const getProfile = async (req, res, next) => {
  try {
    // Get account_id from decoded JWT
    const { account_id } = req.user;

     // Query account and profile data
    const [rows] = await req.db.query(
      `SELECT a.email, a.is_verified, p.display_name, p.age, p.avatar_url 
       FROM tb_account a 
       JOIN tb_profile p ON a.account_id = p.account_id 
       WHERE a.account_id = ?`,
      [account_id],
    );

    // If no user found return 404 error
    if (rows.length === 0) {
      return next(new AppError("User profile not found", 404));
    }

     // Send user profile data
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

    // We check affectedRows to ensure the update actually happened
    const [result] = await req.db.query(
      "UPDATE tb_profile SET display_name = ?, age = ?, updated_at = NOW() WHERE account_id = ?",
      [display_name, age, account_id],
    );

    if (result.affectedRows === 0) {
      return next(
        new AppError(
          "Update failed: Profile not found or no changes made",
          400,
        ),
      );
    }

    res.status(200).json({
      status: "success",
      message: "Profile updated successfully",
    });
  } catch (err) {
    next(err);
  }
};

export const setAvatar = async (req, res, next) => {
  try {
    const { account_id } = req.user;
    const file = req.file;

    if (!file) throw new AppError("No file uploaded!", 400);

    const avatarUrl = `/uploads/${file.filename}`;

    const [result] = await req.db.query(
      "UPDATE tb_profile SET avatar_url = ? WHERE account_id = ?",
      [avatarUrl, account_id],
    );

    if (!result || result.affectedRows === 0)
      throw new AppError("Failed to upload avatar", 404);

    res.status(200).json({
      status: "success",
      message: "Uploaded avatar successfully!",
      data: {
        avatarUrl,
      },
    });
  } catch (error) {
    next(error);
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
        "Account deactivated successfully. Your next login will be blocked.",
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
