=========================================================
PROJECT: REAL-TIME MESSAGING & POLL SYSTEM
DOCUMENTATION: SOCKET.IO + MYSQL (INTEGRATED STATUS)
=========================================================

1. EVENT REGISTRY

---

const EVENTS = {
CONNECTION: "connection",
DISCONNECT: "disconnect",
USER_ONLINE: "user_online", // Broadcast when a user comes online
USER_OFFLINE: "user_offline", // Broadcast when a user goes offline
JOIN_ROOM: "join_room",
LEAVE_ROOM: "leave_room",
ROOM_DATA: "room_data",

MESSAGE: {
SEND: "message:send",
RECEIVE: "message:receive",
EDIT: "message:edit",
DELETE: "message:delete",
REACTION: "message:reaction",
REPLY: "message:reply",
},

STATUS: {
TYPING: "status:typing",
DELIVERED: "status:delivered",
READ: "status:read",
},

POLL: {
CREATE: "poll:create",
VOTE: "poll:vote",
UNVOTE: "poll:unvote",
UPDATE: "poll:update",
VOTE_UPDATE: "poll:vote_update",
},

NOTIFY: {
NEW_ALERT: "notify:new_alert",
BADGE_UPDATE: "notify:badge",
},

ERROR: "error:internal",
};

2. INTERACTION FLOWS (Trigger-Effect Design)

---

A. GLOBAL STATUS & CONNECTION
[User 1] --(CONNECTION)--> [Server]
|
|--> 1. MySQL: UPDATE users SET is_online = 1 WHERE id = ?
|
|--> 2. Broadcast: USER_ONLINE { userId: 1, username: "Alice" }
| (Sent to everyone Alice is sharing a room with)

[User 1] --(DISCONNECT)--> [Server]
|
|--> 1. MySQL: UPDATE users SET is_online = 0, last_seen = NOW() WHERE id = ?
|
|--> 2. Broadcast: USER_OFFLINE { userId: 1, lastSeen: "2026-02-23..." }

B. ROOM RECOVERY (WITH STATUS)
[User 1] --(JOIN_ROOM)--> [Server]
|
|--> 1. MySQL: SELECT \* FROM messages
| WHERE room_id = ? AND created_at > lastTimestamp
|
|--> 2. MySQL: SELECT id, username, is_online FROM users
| WHERE id IN (SELECT user_id FROM room_members WHERE room_id = ?)
|
|--> 3. Emit: ROOM_DATA (History + Online Member List) to [User 1]

C. MESSAGING & POLLS
[User 1] --(MESSAGE.SEND)--> [Server]
|
|--> 1. MySQL: INSERT INTO messages (text, sender_id, room_id)
|--> 2. Broadcast: MESSAGE.RECEIVE to Room members

[User 2] --(POLL.VOTE)--> [Server]
|
|--> 1. MySQL: INSERT INTO poll_votes (poll_id, user_id, option_id)
| ON DUPLICATE KEY UPDATE option_id = ?
|
|--> 2. Broadcast: POLL.VOTE_UPDATE { pollId, results }

3. FINAL MYSQL SCHEMA (Production Ready)

---

-- Users Table (The heartbeat of the app)
CREATE TABLE users (
id INT AUTO_INCREMENT PRIMARY KEY,
username VARCHAR(50) NOT NULL UNIQUE,
is_online BOOLEAN DEFAULT FALSE,
last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Messages Table
CREATE TABLE messages (
id INT AUTO_INCREMENT PRIMARY KEY,
room_id VARCHAR(50) NOT NULL,
sender_id INT NOT NULL,
message_text TEXT NOT NULL,
created_at TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP(6),
FOREIGN KEY (sender_id) REFERENCES users(id)
);

-- Polls Table
CREATE TABLE polls (
id INT AUTO_INCREMENT PRIMARY KEY,
room_id VARCHAR(50) NOT NULL,
creator_id INT NOT NULL,
question TEXT NOT NULL,
is_active BOOLEAN DEFAULT TRUE,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
FOREIGN KEY (creator_id) REFERENCES users(id)
);

-- Poll Votes Table (Ensures 1 vote per user per poll)
CREATE TABLE poll_votes (
id INT AUTO_INCREMENT PRIMARY KEY,
poll_id INT NOT NULL,
user_id INT NOT NULL,
option_id INT NOT NULL,
UNIQUE KEY unique_vote (poll_id, user_id),
FOREIGN KEY (poll_id) REFERENCES polls(id),
FOREIGN KEY (user_id) REFERENCES users(id)
);

=========================================================
END OF DOCUMENTATION
=========================================================
