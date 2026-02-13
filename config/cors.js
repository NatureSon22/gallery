const isProduction = process.env.NODE_ENV === "production";

// 1. Define who is allowed to talk to your API
const allowedOrigins = isProduction
  ? ["https://myapp.com", "https://admin.myapp.com"]
  : ["http://localhost:3000", "http://localhost:5173"];

const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);

    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true, // Allow cookies to be sent
  maxAge: 600, // How long the browser should cache the "Preflight" (OPTIONS) request
};

