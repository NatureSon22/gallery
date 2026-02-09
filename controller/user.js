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