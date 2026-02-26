import { Server } from "socket.io";

const EVENTS = {
  // --- Connection & Lifecycle ---
  CONNECTION: "connection",
  DISCONNECT: "disconnect",
  USER_ONLINE: "user_online", // Broadcast when a user comes online
  USER_OFFLINE: "user_offline", // Broadcast when a user goes offline

  // --- Room/Channel Management ---
  JOIN_ROOM: "join_room", // includes lastTimestamp for recovery
  LEAVE_ROOM: "leave_room",
  // ROOM_DATA: "room_data", // Sending room metadata (pinned messages, member list)

  // --- Real-Time Chat ---
  MESSAGE: {
    SEND: "message:send", // Client -> Server
    // RECEIVE: "message:receive", // Server -> Client
    // EDIT: "message:edit", // Update existing message text
    // DELETE: "message:delete", // Soft or hard delete
    // REACTION: "message:reaction", // Add/Remove emojis
    // REPLY: "message:reply", // Threaded messaging
  },

  // --- Status & Feedback ---
  STATUS: {
    TYPING: "status:typing", // "User is typing..."
    // DELIVERED: "status:delivered", // Message reached the device
    // READ: "status:read", // User actually opened the chat
  },

  // --- Live Polls ---
  POLL: {
    CREATE: "poll:create",
    // VOTE: "poll:vote",
    // UNVOTE: "poll:unvote",
    // UPDATE: "poll:update", // e.g., adding an option or pinning
    // CLOSE: "poll:close", // Stop accepting votes
    // VOTE_UPDATE: "poll:vote_update", // Live bar chart updates (broadcast)
  },

  // --- Media & Files ---
  MEDIA: {
    // UPLOAD_PROGRESS: "media:progress",
    // UPLOAD_COMPLETE: "media:complete",
  },

  // --- Notifications ---
  NOTIFY: {
    NEW_ALERT: "notify:new_alert", // General notifications
    // BADGE_UPDATE: "notify:badge", // Update unread counts
  },

  // --- Search & Discovery ---
  // SEARCH: {
  //   USER: "search:user",
  //   GROUP: "search:group",
  //   RESULTS: "search:results",
  // },

  // --- Error Handling ---
  ERROR: "error:internal", // Generic catch-all for socket failures
};

const configSocket = (server) => {
  const io = new Server(server, {
    cors: {
      origin: process.env.FRONTEND_ORIGIN,
      methods: ["GET", "POST"],
    },
  });

  // middleware
  io.use((socket, next) => {
    
  });

  io.on("connection", (socket) => {
    console.log("A user connected: " + socket.id);

    socket.on(EVENTS.DISCONNECT, () => {
      console.log("User disconnected: " + socket.id);
    });

    socket.on(EVENTS.JOIN_ROOM, (room) => {
      socket.join(room);
      console.log("User joined room: " + room);
    });

    socket.on(EVENTS.LEAVE_ROOM, (room) => {
      socket.leave(room);
      console.log("User left room: " + room);
    });

    socket.on(EVENTS.SEND_MESSAGE, (message) => {
      socket.broadcast.emit(EVENTS.SEND_MESSAGE, message);
      console.log("Message received: " + message);
    });

    if (!socket.recovered) {
    }
  });

  return io;
};

export default configSocket;

// -- Query logic: Get messages newer than this time OR
// -- same time but a higher ID (to handle simultaneous messages)
// SELECT * FROM messages
// WHERE room_name = ?
//   AND (created_at > ? OR (created_at = ? AND id > ?))
// ORDER BY created_at ASC, id ASC;
