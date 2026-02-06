import { Router } from "express";

const userRouter = Router();

// GET    /user/profile            -> Join tb_account + tb_profile
// PATCH  /user/profile            -> Update tb_profile fields
// POST   /user/upload-avatar      -> Update tb_profile.avatar_url
// PATCH  /user/deactivate         -> Set tb_account.is_active = 0
// DELETE /user/delete             -> Cascade delete all user records

export default userRouter;
