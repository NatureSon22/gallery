import { Router } from "express";
import upload from "../../helper/storage.js";
import protect from "../../middleware/protect.js";
import validate from "../../middleware/validation.js";
import { deletePhotosSchema } from "../../schemas/upload.schema.js";
import {
  deletePhotos,
  getPhotos,
  uploadPhotos,
} from "../../controller/v1/upload.js";

const uploadRouter = Router();

uploadRouter.use(protect);

uploadRouter.get("/", getPhotos);

uploadRouter.post("/", upload.array("photos"), uploadPhotos);

uploadRouter.post("/single", upload.single("photo"), (req, res, next) => {
  req.files = req.file ? [req.file] : [];
  uploadPhotos(req, res, next);
});

uploadRouter.delete("/", validate(deletePhotosSchema, "body"), deletePhotos);

export default uploadRouter;