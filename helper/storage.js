import multer from "multer";
import path from "path";
import fs from "fs";
import checkFileType from "./checkFileType.js";

const uploadDir = path.resolve(process.cwd(), "uploads");

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    try {
      // create directory if it doesn't exists
      fs.mkdirSync(uploadDir, { recursive: true });
      cb(null, uploadDir);
    } catch (error) {
      cb(error);
    }
  },
  filename: (req, file, cb) => {
    const unique = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    const safeOriginal = file.originalname.replace(/[^\w.-]/g, "_");
    cb(null, `${unique}-${safeOriginal}`);
  },
});

const upload = multer({
  storage,
  fileFilter: checkFileType,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB per file
    files: 10,
  },
});

export default upload;
