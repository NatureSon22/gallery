import AppError from "../../helper/AppError";

export const getRooms = async (req, res, next) => {
  try {
    const { account_id } = req.user;

    // get rooms where the current user is member of (private & group)
    const [rooms] = await req.db.query(
      `SELECT r.id, r.room_name, r.room_type
       FROM tb_room AS r
       INNER JOIN tb_room_members AS m ON r.id = m.room_id
       WHERE m.user_id = ?`,
      [account_id],
    );

    res.status(200).json({
      status: "success",
      data: rooms,
    });
  } catch (error) {
    next(error);
  }
};

export const getRoom = async (req, res, next) => {
  const { room_id } = req.query;
  try {
    const [rows] = await req.db.query(
      `SELECT r.id, r.room_name, r.room_type
       FROM tb_room AS r
       WHERE r.id = ?`,
      [room_id],
    );

    if (rows.length == 0) {
      throw new AppError("Room not found");
    }

    res.status(200).json({
      status: "success",
      data: room,
    });
  } catch (error) {
    next(error);
  }
};

export const createRoom = async (req, res, next) => {
  const connection = await req.db.getConnection();
  try {
    const { room_name, room_type } = req.body;
    const userId = req.user?.account_id;

    await connection.beginTransaction();

    const [roomResult] = await connection.query(
      "INSERT INTO tb_room (room_name, room_type) VALUES (?, ?)",
      [room_name.trim(), room_type],
    );

    const roomId = roomResult.insertId;

    // add creator as owner/member
    if (roomId) {
      await connection.query(
        "INSERT INTO tb_room_members (room_id, user_id, role, joined_at) VALUES (?, ?, ?, NOW())",
        [roomId, userId, "owner"],
      );
    }

    await connection.commit();

    const [selectedRoomResult] = await req.db.query(
      "SELECT id AS room_id, room_name, room_type, created_at FROM tb_room WHERE id = ? LIMIT 1",
      [roomId],
    );

    res.status(201).json({
      status: "success",
      message: "Room created successfully",
      data: selectedRoomResult[0] || null,
    });
  } catch (error) {
    await connection.rollback();
    next(error);
  } finally {
    connection.release();
  }
};

export const updateRoom = async (req, res, next) => {
  try {
    const { room_name, room_id } = req.body;

    const [result] = await req.db.query(
      "UPDATE tb_room SET room_name = ? WHERE id = ?",
      [room_name, room_id],
    );

    if (result.affectedRows === 0) {
      return next(new AppError("Room not found", 404));
    }

    const [rows] = await req.db.query(
      "SELECT id AS room_id, room_name, room_type, created_at FROM tb_room WHERE id = ? LIMIT 1",
      [room_id],
    );

    res.status(200).json({
      status: "success",
      message: "Room updated successfully",
      data: rows[0] || null,
    });
  } catch (error) {
    next(error);
  }
};

export const deleteRooms = async (req, res, next) => {
  const room_id = req.params.room_id || req.body.room_id;
  const userId = req.user?.account_id;

  const connection = await req.db.getConnection();
  try {
    // check membership/role: only owner/admin may delete
    const [members] = await connection.query(
      "SELECT role FROM tb_room_members WHERE room_id = ? AND user_id = ? LIMIT 1",
      [room_id, userId],
    );

    if (members.length === 0) {
      connection.release();
      return next(new AppError("Not a member of the room", 403));
    }

    const role = members[0].role;
    if (!["owner", "admin"].includes(role)) {
      connection.release();
      return next(new AppError("Insufficient permissions to delete room", 403));
    }

    await connection.beginTransaction();
    const [delResult] = await connection.query(
      "DELETE FROM tb_room WHERE id = ?",
      [room_id],
    );

    if (delResult.affectedRows === 0) {
      return next(new AppError("Room not found or already deleted", 404));
    }

    await connection.commit();

    res.status(200).json({
      status: "success",
      message: "Room deleted successfully",
      deleted: { room_id },
    });
  } catch (err) {
    await connection.rollback();
    next(err);
  } finally {
    connection.release();
  }
};
