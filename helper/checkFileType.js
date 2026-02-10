import path from "path";

const checkFileType = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  const mime = (file.mimetype || "").toLowerCase();
  const allowedFileTypes = [".jpeg", ".jpg", ".png"];
  const allowedMimeTypes = ["image/jpeg", "image/png"];
  const ok = allowedFileTypes.includes(ext) && allowedMimeTypes.includes(mime);

  if (!ok) {
    return cb(
      new Error(`Only ${allowedFileTypes.join(" ")} images are allowed`),
      false,
    );
  }

  cb(null, true);
};

export default checkFileType;
