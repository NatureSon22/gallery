const isProduction = process.env.NODE_ENV === "production";

// 1. Define who is allowed to talk to your API
const allowedOrigins = isProduction
  ? ["https://myapp.com", "https://admin.myapp.com"]
  : ["http://localhost:3000", "http://localhost:5173"];

const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);

    // Return the matching canonical origin from your whitelist
    const match = allowedOrigins.find(allowed => 
      allowed === origin || allowed === origin.replace(/\/$/, "")
    );

    if (match) {
      callback(null, match); // ✅ Return YOUR origin, not theirs
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true, // Allow cookies to be sent
  maxAge: 600, // How long the browser should cache the "Preflight" (OPTIONS) request
};

export default corsOptions;