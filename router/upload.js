import { Router } from "express";
import upload from "../helper/storage.js";
import { protect } from "../middleware/index.js";
import { getPhotos, uploadPhotos } from "../controller/upload.js";

const uploadRouter = Router();

uploadRouter.use(protect);
uploadRouter.get("/", getPhotos);
uploadRouter.post("/", upload.array("photos"), uploadPhotos);
//uploadRouter.post();

export default uploadRouter;
