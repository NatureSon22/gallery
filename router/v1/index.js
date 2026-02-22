import { Router } from "express";
import authRouter from "./auth.js";
import userRouter from "./user.js";
import uploadRouter from "./upload.js";

const routes = [
  {
    path: "/auth",
    router: authRouter,
  },
  {
    path: "/user", 
    router: userRouter,
  },
  {
    path: "/upload",
    router: uploadRouter,
  },
];

const router = Router();

routes.forEach((route) => {
  router.use(route.path, route.router);
});

export default router;
