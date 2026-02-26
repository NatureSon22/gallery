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

--- =========================================================
-- 1. Accounts Table (The Heart of the App)
-- =========================================================
CREATE TABLE `tb_account` (
`account_id` INT AUTO_INCREMENT PRIMARY KEY,
`username` VARCHAR(50) NOT NULL UNIQUE,
`is_online` BOOLEAN DEFAULT FALSE,
`last_seen` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- =========================================================
-- 2. Rooms Table (Defining the Chat Groups)
-- =========================================================
CREATE TABLE `tb_room` (
`id` VARCHAR(50) PRIMARY KEY,
`room_name` VARCHAR(100) NOT NULL,
<!-- `room_type` ENUM('private', 'group') DEFAULT 'group', // filter -->
`created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =========================================================
-- 3. Room Members Table (Who belongs where)
-- =========================================================
CREATE TABLE `tb_room_members` (
`room_id` VARCHAR(50) NOT NULL,
`user_id` INT NOT NULL,
`role` ENUM('member', 'admin', 'owner') DEFAULT 'member',
`joined_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
`last_read_at` TIMESTAMP NULL,
`muted_until` DATETIME NULL,
PRIMARY KEY (`room_id`, `user_id`),
FOREIGN KEY (`room_id`) REFERENCES `tb_room` (`id`) ON DELETE CASCADE,
FOREIGN KEY (`user_id`) REFERENCES `tb_account` (`account_id`) ON DELETE CASCADE,
INDEX `idx_member_joined` (`user_id`, `room_id`)
);

-- =========================================================
-- 4. Messages & Attachments
-- =========================================================
CREATE TABLE `messages` (
`id` INT AUTO_INCREMENT PRIMARY KEY,
`room_id` VARCHAR(50) NOT NULL,
`sender_id` INT NOT NULL,
`message_text` TEXT,
`message_type` ENUM('text', 'image', 'file', 'system') DEFAULT 'text',
`reply_to` INT NULL,
`is_deleted` TINYINT(1) DEFAULT 0,
`edited_at` DATETIME NULL,
`created_at` TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP(6),
FULLTEXT KEY `ft_message_text` (`message_text`),
INDEX `idx_room_created` (`room_id`, `created_at`),
FOREIGN KEY (`room_id`) REFERENCES `tb_room` (`id`) ON DELETE CASCADE,
FOREIGN KEY (`sender_id`) REFERENCES `tb_account` (`account_id`) ON DELETE CASCADE,
FOREIGN KEY (`reply_to`) REFERENCES `messages` (`id`) ON DELETE SET NULL
);

CREATE TABLE `message_reactions` (
`message_id` INT NOT NULL,
`user_id` INT NOT NULL,
`emoji` VARCHAR(64) NOT NULL,
`created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
PRIMARY KEY (`message_id`, `user_id`, `emoji`),
FOREIGN KEY (`message_id`) REFERENCES `messages` (`id`) ON DELETE CASCADE,
FOREIGN KEY (`user_id`) REFERENCES `tb_account` (`account_id`) ON DELETE CASCADE,
INDEX `idx_msg_reaction` (`message_id`)
);

CREATE TABLE `message_attachments` (
`id` INT AUTO_INCREMENT PRIMARY KEY,
`message_id` INT NOT NULL,
`filename` VARCHAR(255),
`mime` VARCHAR(100),
`url` VARCHAR(1024),
`size` INT,
`created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
FOREIGN KEY (`message_id`) REFERENCES `messages` (`id`) ON DELETE CASCADE,
INDEX `idx_attachment_msg` (`message_id`)
);

-- =========================================================
-- 5. Polls System
-- =========================================================
CREATE TABLE `polls` (
`id` INT AUTO_INCREMENT PRIMARY KEY,
`room_id` VARCHAR(50) NOT NULL,
`creator_id` INT NOT NULL,
`question` TEXT NOT NULL,
`is_active` BOOLEAN DEFAULT TRUE,
`is_multiple` BOOLEAN DEFAULT FALSE,
`pinned` TINYINT(1) DEFAULT 0,
`created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
FOREIGN KEY (`room_id`) REFERENCES `tb_room` (`id`) ON DELETE CASCADE,
FOREIGN KEY (`creator_id`) REFERENCES `tb_account` (`account_id`) ON DELETE SET NULL
);

CREATE TABLE `poll_options` (
`id` INT AUTO_INCREMENT PRIMARY KEY,
`poll_id` INT NOT NULL,
`label` VARCHAR(255),
`votes` INT DEFAULT 0,
FOREIGN KEY (`poll_id`) REFERENCES `polls` (`id`) ON DELETE CASCADE
);

CREATE TABLE `poll_votes` (
`poll_id` INT NOT NULL,
`option_id` INT NOT NULL,
`user_id` INT NOT NULL,
`created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
PRIMARY KEY (`poll_id`, `user_id`, `option_id`),
FOREIGN KEY (`poll_id`) REFERENCES `polls` (`id`) ON DELETE CASCADE,
FOREIGN KEY (`option_id`) REFERENCES `poll_options` (`id`) ON DELETE CASCADE,
FOREIGN KEY (`user_id`) REFERENCES `tb_account` (`account_id`) ON DELETE CASCADE
);

-- =========================================================
-- 6. Notifications & Unread Tracking
-- =========================================================
CREATE TABLE `notifications` (
`id` INT AUTO_INCREMENT PRIMARY KEY,
`user_id` INT NOT NULL,
`actor_id` INT NULL,
`type` VARCHAR(50),
`payload` JSON,
`is_read` TINYINT(1) DEFAULT 0,
`created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
FOREIGN KEY (`user_id`) REFERENCES `tb_account` (`account_id`) ON DELETE CASCADE,
INDEX `idx_user_unread` (`user_id`, `is_read`)
);

=========================================================
END OF DOCUMENTATION
=========================================================
