import winston from "winston";
import DailyRotateFile from "winston-daily-rotate-file";
import path from "path";

const { combine, timestamp, json, printf, colorize, align } = winston.format;

const logDir = "logs";

/* ---------------------------------------------------
 * ROTATING FILE TRANSPORTS
 * --------------------------------------------------- */
const combinedRotate = new DailyRotateFile({
  filename: path.join(logDir, "combined-%DATE%.log"),
  datePattern: "YYYY-MM-DD",
  zippedArchive: true,
  maxSize: "20m",
  maxFiles: "14d", // keep logs for 14 days
});

const errorRotate = new DailyRotateFile({
  filename: path.join(logDir, "error-%DATE%.log"),
  datePattern: "YYYY-MM-DD",
  zippedArchive: true,
  maxSize: "10m",
  maxFiles: "30d", // keep errors longer
  level: "error",
});

/* ---------------------------------------------------
 * LOGGER INSTANCE
 * --------------------------------------------------- */
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: combine(timestamp(), json()),
  transports: [
    combinedRotate,
    errorRotate,
  ],
});

/* ---------------------------------------------------
 * CONSOLE LOGGING (DEV ONLY)
 * --------------------------------------------------- */
if (process.env.NODE_ENV !== "production") {
  logger.add(
    new winston.transports.Console({
      format: combine(
        colorize({ all: true }),
        timestamp({
          format: "YYYY-MM-DD hh:mm:ss.SSS A",
        }),
        align(),
        printf(
          (info) => `[${info.timestamp}] ${info.level}: ${info.message}`
        )
      ),
    })
  );
}

/* ---------------------------------------------------
 * MORGAN STREAM
 * --------------------------------------------------- */
logger.stream = {
  write: (message) => logger.info(message.trim()),
};

export default logger;
