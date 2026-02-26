const socketProtect = (socket, next) => {
  try {
  } catch (error) {
    console.error(`Socket Auth Error: ${error.message}`);
    next(new Error("Authentication error: Invalid token"));
  }
};

export default socketProtect;
