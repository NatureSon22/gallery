import { Router } from "express";
import upload from "../../helper/storage.js";
import protect from "../../middleware/protect.js";
import {
  getProfile,
  updateProfile,
  deactivateAccount,
  reactivateAccount,
  deleteAccount,
  setAvatar,
} from "../../controller/v1/user.js";

const userRouter = Router();

userRouter.use(protect);

userRouter.get("/profile", getProfile);
userRouter.patch("/profile", updateProfile);
userRouter.post("/profile/avatar", upload.single("avatar"), setAvatar);

userRouter.patch("/account/deactivate", deactivateAccount);
userRouter.patch("/account/reactivate", reactivateAccount);
userRouter.delete("/account", deleteAccount);

export default userRouter;