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

userRouter.use(protect);
userRouter.post("/profile/avatar", upload.single("avatar"), setAvatar);
userRouter.get("/profile", getProfile);
userRouter.patch("/profile", updateProfile);
userRouter.patch("/deactivate", deactivateAccount);
userRouter.patch("/reactivate", reactivateAccount);
userRouter.delete("/", deleteAccount);

export default userRouter;
