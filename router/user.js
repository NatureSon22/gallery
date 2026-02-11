import { Router } from "express";
import {
  getProfile,
  updateProfile,
  deactivateAccount,
  reactivateAccount,
  deleteAccount,
  setAvatar,
} from "../controller/user.js";
import { protect } from "../middleware/index.js";
import upload from "../helper/storage.js";

const userRouter = Router();

// GET    /user/profile            -> Join tb_account + tb_profile
// PATCH  /user/profile            -> Update tb_profile fields
// POST   /user/upload-avatar      -> Update tb_profile.avatar_url
// PATCH  /user/deactivate         -> Set tb_account.is_active = 0
// DELETE /user/delete             -> Cascade delete all user records

userRouter.use(protect);
userRouter.post("/profile/avatar", upload.single("avatar"), setAvatar);





userRouter.get("/profile", getProfile);
userRouter.patch("/profile", updateProfile);



userRouter.patch("/deactivate", deactivateAccount);
userRouter.patch("/reactivate", reactivateAccount);
userRouter.delete("/delete", deleteAccount);

export default userRouter;
