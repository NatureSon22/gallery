import { Router } from "express";
import upload from "../helper/storage.js";
import protect from "../middleware/protect.js";
import { deletePhotos, getPhotos, uploadPhotos } from "../controller/upload.js";
import validate from "../middleware/validation.js";
import { deletePhotosSchema } from "../schemas/upload.schema.js";

const uploadRouter = Router();

uploadRouter.use(protect);
uploadRouter.get("/", getPhotos);
uploadRouter.post("/single", upload.single("photo"), (req, res, next) => {
  req.files = req.file ? [req.file] : [];
  return uploadPhotos(req, res, next);
});
uploadRouter.post("/", upload.array("photos"), uploadPhotos);
uploadRouter.delete("/", validate(deletePhotosSchema, "body"), deletePhotos);

export default uploadRouter;
