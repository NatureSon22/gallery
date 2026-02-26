import { Router } from "express";

import {
  getProfile,
  updateProfile,
  deactivateAccount,
  reactivateAccount,
  deleteAccount,
  setAvatar,
  verifyPassword,
  sendGoogleDeactivationEmail,
  confirmGoogleDeactivation,
} from "../../controller/v1/user.js";

import protect from "../../middleware/protect.js";
import upload from "../../helper/storage.js";

const userRouter = Router();

userRouter.use(protect);

userRouter.get("/profile", getProfile);
userRouter.patch("/profile", updateProfile);
userRouter.post("/profile/avatar", upload.single("avatar"), setAvatar);

userRouter.post("/verify", verifyPassword);
userRouter.patch("/account/deactivate", deactivateAccount);
userRouter.patch("/account/reactivate", reactivateAccount);
userRouter.delete("/account", deleteAccount);

userRouter.post("/google/deactivate", sendGoogleDeactivationEmail);
userRouter.get("/confirm-deactivation", confirmGoogleDeactivation);

export default userRouter;
