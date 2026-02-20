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
} from "../controller/user.js";
import protect from "../middleware/protect.js";
import upload from "../helper/storage.js";
import validate from "../middleware/validation.js";

const userRouter = Router();

userRouter.use(protect);
userRouter.post("/profile/avatar", upload.single("avatar"), setAvatar);
userRouter.get("/profile", getProfile);
userRouter.patch("/profile", updateProfile);

userRouter.post(
  "/verify",
  verifyPassword,
);

userRouter.patch(
  "/deactivate",
  deactivateAccount,
);

userRouter.delete(
  "/",
  deleteAccount, 
);


// Google account deactivation flow
userRouter.post("/google/deactivate", sendGoogleDeactivationEmail);
userRouter.get("/confirm-deactivation", confirmGoogleDeactivation);


// Reactivation route
userRouter.patch("/reactivate", reactivateAccount);

export default userRouter;
