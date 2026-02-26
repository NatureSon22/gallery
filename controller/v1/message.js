import AppError from "../../helper/AppError";

export const getMessages = async (req, res, next) => {
  try {
    const room_id = req.body.room_id;
    const limit = Number(req.query.limit || 100);
    const offset = Number(req.query.offset || 0);

    if (!room_id) return next(new AppError("room_id is required", 400));

    const [messages] = await req.db.query(
      `SELECT m.id, m.room_id, m.sender_id, m.message_text, m.message_type,
              m.reply_to, m.is_deleted, m.edited_at, m.created_at
       FROM messages m
       WHERE m.room_id = ? AND m.is_deleted = 0
       ORDER BY m.created_at ASC
       LIMIT ? OFFSET ?`,
      [room_id, limit, offset],
    );

    res.status(200).json({
      status: "success",
      data: messages,
      meta: {
        count: Array.isArray(messages) ? messages.length : 0,
        limit,
        offset,
      },
    });
  } catch (error) {
    next(error);
  }
};

export const sendMessage = async (req, res, next) => {
  try {
    const { room_id, message_text, message_type } = req.body;
    const sender_id = req.user?.account_id;

    if (!sender_id) return next(new AppError("Authentication required", 401));
    if (!room_id) return next(new AppError("room_id is required", 400));
    if (!message_text && !req.files)
      return next(new AppError("message_text or attachment required", 400));

    const [result] = await req.db.query(
      `INSERT INTO messages (room_id, sender_id, message_text, message_type)
       VALUES (?, ?, ?, ?)`,
      [room_id, sender_id, message_text || null, message_type || "text"],
    );

    const insertedId = result.insertId;

    const [rows] = await req.db.query(
      "SELECT id, room_id, sender_id, message_text, message_type, reply_to, edited_at, created_at FROM messages WHERE id = ? LIMIT 1",
      [insertedId],
    );

    res.status(201).json({ status: "success", data: rows[0] || null });
  } catch (error) {
    next(error);
  }
};

export const updateMessage = async (req, res, next) => {
  try {
    const { message_id, message_text } = req.body;
    const userId = req.user?.account_id;

    if (!userId) return next(new AppError("Authentication required", 401));
    if (!message_id || typeof message_text !== "string")
      return next(
        new AppError("message_id and message_text are required", 400),
      );

    const [result] = await req.db.query(
      `UPDATE messages
       SET message_text = ?, edited_at = NOW()
       WHERE id = ? AND sender_id = ? AND is_deleted = 0`,
      [message_text, message_id, userId],
    );

    if (result.affectedRows === 0) {
      return next(new AppError("Message not found or not authorized", 404));
    }

    const [rows] = await req.db.query(
      "SELECT id, message_text, edited_at FROM messages WHERE id = ? LIMIT 1",
      [message_id],
    );

    res.status(200).json({ status: "success", data: rows[0] || null });
  } catch (error) {
    next(error);
  }
};

export const replyMessage = async (req, res, next) => {
  try {
    const { room_id, message_text, message_type, reply_to } = req.body;
    const sender_id = req.user?.account_id;

    if (!sender_id) return next(new AppError("Authentication required", 401));
    if (!room_id || !reply_to)
      return next(new AppError("room_id and reply_to are required", 400));

    const [result] = await req.db.query(
      `INSERT INTO messages (room_id, sender_id, message_text, message_type, reply_to)
       VALUES (?, ?, ?, ?, ?)`,
      [
        room_id,
        sender_id,
        message_text || null,
        message_type || "text",
        reply_to,
      ],
    );

    const insertedId = result.insertId;
    const [rows] = await req.db.query(
      "SELECT id, room_id, sender_id, message_text, message_type, reply_to, created_at FROM messages WHERE id = ? LIMIT 1",
      [insertedId],
    );

    res.status(201).json({ status: "success", data: rows[0] || null });
  } catch (error) {
    next(error);
  }
};

export const deleteMessage = async (req, res, next) => {
  try {
    const { message_id } = req.params;
    const userId = req.user?.account_id;

    if (!userId) return next(new AppError("Authentication required", 401));
    if (!message_id) return next(new AppError("message_id is required", 400));

    // soft-delete: allow sender or room admin to delete
    const [check] = await req.db.query(
      `SELECT sender_id FROM messages WHERE id = ? LIMIT 1`,
      [message_id],
    );

    if (check.length === 0) return next(new AppError("Message not found", 404));

    const senderId = check[0].sender_id;
    // if not sender, additional permission check could go here (e.g., room admin)
    if (senderId !== userId) {
      return next(new AppError("Not authorized to delete this message", 403));
    }

    const [result] = await req.db.query(
      `UPDATE messages SET is_deleted = 1, edited_at = NOW() WHERE id = ?`,
      [message_id],
    );

    if (result.affectedRows === 0)
      return next(new AppError("Failed to delete message", 500));

    res.status(200).json({ status: "success", message: "Message deleted" });
  } catch (error) {
    next(error);
  }
};
