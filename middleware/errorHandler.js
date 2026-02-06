const errorHandler = (err, req, res) => {
  let statusCode = err.statusCode || 500;
  let message = err.message || "Internal Server Error";

  res.status(statusCode).json({
    status: statusCode >= 500 ? "error" : "fail",
    message: message,
    stack: process.env.NODE_ENV === "development" ? err.stack : undefined,
  });
};
