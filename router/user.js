import { Router } from "express";
import { getProfile, updateProfile } from "../controller/user.js";
import { protect } from "../middleware/index.js";

const userRouter = Router();

// GET    /user/profile            -> Join tb_account + tb_profile
// PATCH  /user/profile            -> Update tb_profile fields
// POST   /user/upload-avatar      -> Update tb_profile.avatar_url
// PATCH  /user/deactivate         -> Set tb_account.is_active = 0
// DELETE /user/delete             -> Cascade delete all user records

userRouter.use(protect);

userRouter.get("/profile", getProfile);
userRouter.patch("/profile", updateProfile);

export default userRouter;
