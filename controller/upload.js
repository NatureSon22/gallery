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
  const connection = await req.db.getConnection();
  try {
    const { gallery_id } = req.user;
    const { photo_ids } = req.body;

    console.log(gallery_id);
    console.log(photo_ids);

    const ids = photo_ids.map((photo_id) => Number(photo_id));

    if (ids.some((n) => !Number.isInteger(n))) {
      throw new AppError("photo_ids must contain only positive integers", 400);
    }

    const placeholder = ids.map(() => "?").join(",");

    await connection.beginTransaction();

    const [result] = await connection.execute(
      `DELETE FROM tb_photos 
       WHERE gallery_id = ? AND photo_id IN (${placeholder})`,
      [Number(gallery_id), ...ids],
    );

    if (!result || result.affectedRows === 0) {
      throw new AppError("Failed to delete selected photos", 404);
    }

    await connection.commit();

    res.status(200).json({
      status: "success",
      message: "Photos deleted successfully!",
      data: { deleted: result.affectedRows },
    });
  } catch (error) {
    await connection.rollback();
    next(error);
  } finally {
    connection.release();
  }
};
