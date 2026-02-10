import AppError from "../helper/AppError.js";

export const getPhotos = async (req, res, next) => {
  try {
    const { gallery_id } = req.user;

    const [photos] = await req.db.execute(
      "SELECT photo_id, url FROM tb_photos WHERE gallery_id = ?",
      [Number(gallery_id)],
    );

    res.status(200).json({
      status: "success",
      data: photos,
    });
  } catch (error) {
    next(error);
  }
};

export const uploadPhotos = async (req, res, next) => {
  try {
    const { gallery_id } = req.user;
    const files = req.files;

    if (!files || files.length == 0)
      throw new AppError("No file uploaded!", 400);

    const filesURL = files.map((file) => `/uploads/${file.filename}`);

    const insertPromises = filesURL.map((url) =>
      req.db.execute("INSERT INTO tb_photos (url, gallery_id) VALUES (?, ?)", [
        url,
        Number(gallery_id),
      ]),
    );

    const results = await Promise.all(insertPromises);

    // Ensure all photos are uploaded
    const inserted = results.every(([r]) => r && r.affectedRows === 1);
    if (!inserted) throw new AppError("Failed to upload photos", 400);

    res.status(201).json({
      status: "success",
      message: "Uploaded successfully",
      data: {
        photos: filesURL,
      },
    });
  } catch (error) {
    next(error);
  }
};

export const deletePhotos = async (req, res, next) => {
  try {
    const { photo_ids } = req.body;
  } catch (error) {
    next(error);
  }
};
