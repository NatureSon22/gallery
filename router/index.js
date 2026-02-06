import { Router } from "express";
import authRouter from "./auth.js";
import userRouter from "./user.js";

const routes = [
  {
    path: "/auth",
    router: authRouter,
  },
  {
    path: "/user",
    router: userRouter,
  },
];

const router = Router();

routes.forEach((route) => {
  router.use(route.path, route.router);
});

export default router;
