import argon2 from "argon2";
import jwt from "jsonwebtoken";
import AppError from "../helper/AppError.js";
import db from "../helper/db.js";
import generateTokens from "../helper/generateToken.js";
import crypto from "crypto";
import {
  sendVerificationEmail,
  sendPasswordResetEmail,
} from "../helper/mailer.js";
import path from "path";
import setAuthCookies from "../helper/setAuthCookies.js";

// 1. SIGNUP CONTROLLER
export const signup = async (req, res, next) => {
  try {
    const { email, password, display_name, age } = req.validatedBody;
    const plan = req.validatedQuery?.plan || "free";

    // Check if email exists
    const [existing] = await req.db.query(
      "SELECT account_id FROM tb_account WHERE email = ?",
      [email],
    );

    if (existing.length > 0) {
      return next(new AppError("Email already registered", 400));
    }

    // Hash password
    const hashedPassword = await argon2.hash(password, {
      type: argon2.argon2id,
    });

    // Insert account
    const [accountResult] = await req.db.query("INSERT INTO tb_account SET ?", {
      email,
      password: hashedPassword,
      created_at: new Date(),
    });

    const accountId = accountResult.insertId;

    // Insert profile
    await req.db.query(
      "INSERT INTO tb_profile (account_id, display_name, age, updated_at) VALUES (?, ?, ?, NOW())",
      [accountId, display_name || null, age || null],
    );

    // Insert default gallery
    await req.db.query(
      "INSERT INTO tb_gallery (account_id, title, created_at) VALUES (?, 'My Uploads', NOW())",
      [accountId],
    );

    // Create verification token
    const verifyToken = crypto.randomBytes(32).toString("hex");

    // Store token (expires in 24h)
    await req.db.query(
      `INSERT INTO tb_email_verifications (account_id, verify_token, expires_at)
      VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 1 DAY))`,
      [accountId, verifyToken],
    );

    // Send email
    await sendVerificationEmail(email, verifyToken);

    res.status(201).json({
      status: "success",
      message: "Account created. Please verify your email.",
    });
  } catch (err) {
    next(err);
  }
};

export const findOrCreateGoogleUser = async (profile) => {
  const { id, _json } = profile;
  const email = _json.email;

  // Fetch account + gallery (if any)
  const [rows] = await db.execute(
    `SELECT 
        a.account_id,
        a.google_id,
        a.is_active,
        a.is_verified,
        g.gallery_id
     FROM tb_account a
     LEFT JOIN tb_gallery g 
       ON g.account_id = a.account_id
     WHERE a.email = ?
     LIMIT 1`,
    [email],
  );

  if (rows.length > 0) {
    const user = rows[0];

    if (user.is_verified !== 1) throw new Error("NOT_VERIFIED");
    if (user.is_active === 0) throw new Error("DELETED_ACCOUNT");

    console.log(user);

    return { accountId: user.account_id, galleryId: user.gallery_id };
  }

  // 2) Create User using a Transaction
  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();

    const [account] = await connection.execute(
      "INSERT INTO tb_account (email, google_id, is_verified) VALUES (?, ?, 1)",
      [email, id],
    );

    const accountId = account.insertId;

    await connection.execute(
      "INSERT INTO tb_profile (account_id, display_name, avatar_url) VALUES (?, ?, ?)",
      [accountId, _json.name, _json.picture],
    );

    const [gallery] = await connection.execute(
      "INSERT INTO tb_gallery (account_id) VALUES (?)",
      [accountId],
    );

    const galleryId = gallery.insertId;

    await connection.commit();
    return { accountId, galleryId };
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
};

export const createSession = async (accountId, galleryId) => {
  const tokens = generateTokens(accountId, galleryId);
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 7);

  await db.execute(
    "INSERT INTO tb_refresh_token (account_id, refresh_token, expires_at) VALUES (?, ?, ?)",
    [accountId, tokens.refreshToken, expiresAt],
  );

  return tokens;
};

export const getLoggedInUser = async (req, res) => {
  res.status(200).json({ status: "success", data: req.user });
};

export const getTokens = (req, res, next) => {
  try {
    const accessToken = req.cookies?.access_token || null;
    const refreshToken = req.cookies?.refresh_token | null;

    if (!accessToken && !refreshToken)
      throw new AppError("No tokens available", 401);

    res
      .status(200)
      .json({ status: "success", data: { accessToken, refreshToken } });
  } catch (error) {
    next(error);
  }
};

//LOGIN CONTROLLER
// ============================================
// IN LOGIN CONTROLLER (where token is created)
// ============================================
export const login = async (req, res, next) => {
  try {
    const { email, password } = req.validatedBody;

    // Fetch users - including google_id
    const [loginRows] = await req.db.query(
      `SELECT 
         a.account_id, a.email, a.password, a.google_id, a.is_active, a.is_verified,
         g.gallery_id
       FROM tb_account a
       LEFT JOIN tb_gallery g ON g.account_id = a.account_id
       WHERE a.email = ?
       LIMIT 1`,
      [email],
    );

    if (loginRows.length === 0) {
      return next(new AppError("Invalid credentials", 401));
    }

    const loginAccount = loginRows[0];

    // if the account is deleted(0)
    if (loginAccount.is_active === 0) {
      return next(new AppError("Invalid credentials", 401));
    }

    // verify passswords of account made from manual signup
    // If google_id is null, they signed up manually and must have a password
    if (!loginAccount.google_id) {
      const isPasswordValid = await argon2.verify(
        loginAccount.password,
        password,
      );
      if (!isPasswordValid) {
        return next(new AppError("Invalid credentials", 401));
      }
    } else if (!password && loginAccount.google_id) {
      // If they try to manual login to a Google account without a password
      return next(
        new AppError(
          "This account uses Google Login. Please sign in with Google.",
          401,
        ),
      );
    }

    // checks if the email is verified(1) or not(0)
    if (loginAccount.is_verified === 0) {
      return next(
        new AppError("Please verify your email before logging in.", 403),
      );
    }

    // generate passport compatible tokens
    // allow deactivated(2) users to get a token so they can reactivate
    const { accessToken, refreshToken } = generateTokens(
      loginAccount.account_id,
      loginAccount.gallery_id,
    );

    console.log("\n🔐 ========== TOKEN GENERATION (LOGIN) ==========");
    console.log("📝 Generated accessToken length:", accessToken.length);
    console.log("📝 Generated refreshToken:", refreshToken);
    console.log("📏 RefreshToken length:", refreshToken.length);
    console.log("🔤 First 100 chars:", refreshToken.substring(0, 100));
    console.log(
      "🔤 Last 100 chars:",
      refreshToken.substring(refreshToken.length - 100),
    );
    console.log(
      "🔍 Starts with 'eyJ'?",
      refreshToken.startsWith("eyJ") ? "YES ✅" : "NO ❌",
    );

    // if the account is deactivated(2), send a fail and a warning message
    if (loginAccount.is_active === 2) {
      return res.status(403).json({
        status: "fail",
        message:
          "Account deactivated, please reactivate your account to access all features.",
      });
    }

    console.log("\n💾 SAVING TO DATABASE...");
    console.log("Account ID:", loginAccount.account_id);
    console.log(
      "Token to save (first 50 chars):",
      refreshToken.substring(0, 50),
    );

    await req.db.query(
      "UPDATE tb_account SET refresh_token = ? WHERE account_id = ?",
      [refreshToken, loginAccount.account_id],
    );

    // IMMEDIATELY verify what was saved
    const [dbCheck] = await req.db.query(
      "SELECT refresh_token, CHAR_LENGTH(refresh_token) as token_length FROM tb_account WHERE account_id = ?",
      [loginAccount.account_id],
    );

    console.log("\n💾 DATABASE VERIFICATION (immediately after save):");
    console.log("📏 Generated token length:", refreshToken.length);
    console.log("📏 DB token length:", dbCheck[0].token_length);
    console.log(
      "📝 DB token (first 100):",
      dbCheck[0].refresh_token?.substring(0, 100),
    );
    console.log(
      "📝 DB token (last 100):",
      dbCheck[0].refresh_token?.substring(
        dbCheck[0].refresh_token.length - 100,
      ),
    );
    console.log(
      "✅ Tokens match?",
      refreshToken === dbCheck[0].refresh_token ? "YES ✅" : "NO ❌ PROBLEM!",
    );

    if (refreshToken !== dbCheck[0].refresh_token) {
      console.log("\n🚨 CRITICAL: TOKEN MISMATCH AFTER DATABASE SAVE!");
      console.log("Expected length:", refreshToken.length);
      console.log("Actual length:", dbCheck[0].token_length);
      console.log(
        "Difference:",
        refreshToken.length - dbCheck[0].token_length,
        "characters lost",
      );
      console.log("⚠️  This indicates DATABASE TRUNCATION");
      console.log(
        "📋 Solution: ALTER TABLE tb_account MODIFY COLUMN refresh_token TEXT;",
      );

      // Find first difference
      let firstDiff = -1;
      for (
        let i = 0;
        i <
        Math.min(refreshToken.length, dbCheck[0].refresh_token?.length || 0);
        i++
      ) {
        if (refreshToken[i] !== dbCheck[0].refresh_token[i]) {
          firstDiff = i;
          break;
        }
      }
      if (firstDiff !== -1) {
        console.log("First difference at index:", firstDiff);
      } else {
        console.log(
          "Tokens match up to index:",
          Math.min(refreshToken.length, dbCheck[0].refresh_token?.length || 0),
        );
        console.log("Token was truncated at this point");
      }
    }

    //setAuthCookies(res, { accessToken, refreshToken });

    const isProd = process.env.NODE_ENV === "production";

    // sameSite controls when cookies are sent on cross-site requests:
    // - "none": cookie is sent in all contexts (cross-site allowed). Modern browsers require Secure=true when using "none".
    // - "lax": cookie is sent on top-level navigations (safe for most auth redirects) but NOT on most cross-site subrequests (good CSRF protection).
    // - "strict": cookie is only sent for same-site requests (strictest CSRF protection; may break cross-site OAuth redirects).
    const sameSite = isProd ? "none" : "lax";

    console.log("\n🍪 SETTING COOKIES...");
    console.log("Environment:", isProd ? "PRODUCTION" : "DEVELOPMENT");
    console.log("sameSite:", sameSite);

    // Short-lived access token cookie (sent to all routes)
    if (accessToken) {
      res.cookie("access_token", accessToken, {
        httpOnly: true, // not accessible to JavaScript — defends against XSS
        secure: false, // only send over HTTPS in production
        sameSite: "lax", // as defined above
        maxAge: 60 * 1000, // 1 minute for testing (change to 15 * 60 * 1000 for production)
        path: "/", // cookie sent for all paths under the origin
      });
      console.log("✅ access_token cookie set (expires in 1 minute)");
    }

    // Long-lived refresh token cookie (scoped to refresh endpoint)
    if (refreshToken) {
      res.cookie("refresh_token", refreshToken, {
        httpOnly: true,
        secure: false,
        sameSite: "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        // path: controls which request paths the browser will include this cookie on.
        // Example:
        // - "/api/v1/auth/refresh" => browser sends cookie only when request path starts with that value.
        // - "/" => browser sends cookie on all requests to the origin.
        // Scoping refresh_token to the refresh endpoint reduces token exposure.
        path: "/", // Using "/" for now, consider "/api/v1/auth/refresh" for production
      });
      console.log("✅ refresh_token cookie set (expires in 7 days)");
      console.log("Cookie value length:", refreshToken.length);
      console.log("Cookie value (first 50):", refreshToken.substring(0, 50));
    }

    console.log("\n📤 RESPONSE HEADERS:");
    const setCookieHeaders = res.getHeader("Set-Cookie");
    if (setCookieHeaders) {
      console.log("Set-Cookie headers:", setCookieHeaders);
    }

    console.log("\n✅ ========== LOGIN SUCCESSFUL ==========");
    console.log("Account ID:", loginAccount.account_id);
    console.log("Gallery ID:", loginAccount.gallery_id);
    console.log("========================================\n");

    // Note: You can't read cookies from res.cookies (that's for request)
    // Cookies are sent via Set-Cookie header in the response

    // successful login for active(1)
    // TODO: redirect to login
    res.status(200).json({
      status: "success",
      message: "Login successful",
      data: { userData: loginAccount },
    });
  } catch (err) {
    console.log("\n❌ LOGIN ERROR:", err.message);
    next(err);
  }
};
//REFRESH TOKEN CONTROLLER
// ============================================
// IN REFRESH TOKEN CONTROLLER (where token is received)
// ============================================
export const refreshToken = async (req, res, next) => {
  console.log("\n🔄 ========== REFRESH TOKEN PROCESS STARTED ==========");
  console.log("⏰ Timestamp:", new Date().toISOString());
  console.log("📍 Endpoint: /auth/refresh");

  try {
    // ============================================
    // PHASE 1: EXTRACT TOKEN FROM COOKIES
    // ============================================
    console.log("\n📋 Phase 1: Extracting refresh token from cookies");
    console.log("🌐 Raw Cookie Header:", req.headers.cookie);
    console.log("🍪 Parsed Cookies:", req.cookies);

    const incomingToken = req.cookies?.refresh_token;
    console.log("🔑 Refresh token found:", incomingToken ? "YES ✅" : "NO ❌");

    if (!incomingToken) {
      console.log("❌ ERROR: Refresh token missing in cookies");
      console.log("📤 Responding with 401\n");
      return next(new AppError("Refresh token missing", 401));
    }

    console.log("📏 Incoming token length:", incomingToken.length);
    console.log("📝 Incoming token:", incomingToken);
    console.log("🔤 First 100 chars:", incomingToken.substring(0, 100));
    console.log(
      "🔤 Last 100 chars:",
      incomingToken.substring(incomingToken.length - 100),
    );
    console.log(
      "🔍 Starts with 'eyJ'?",
      incomingToken.startsWith("eyJ") ? "YES ✅" : "NO ❌",
    );
    console.log(
      "🔍 Contains whitespace?",
      /\s/.test(incomingToken) ? "YES ❌" : "NO ✅",
    );

    // ============================================
    // PHASE 2: VERIFY JWT SIGNATURE
    // ============================================
    console.log("\n📋 Phase 2: Verifying JWT signature");
    console.log(
      "🔐 Using JWT_REFRESH_SECRET:",
      process.env.JWT_REFRESH_SECRET ? "Available ✅" : "Missing ❌",
    );

    let decoded;
    try {
      decoded = jwt.verify(incomingToken, process.env.JWT_REFRESH_SECRET);
      console.log("✅ JWT verification successful");
      console.log("👤 Decoded payload:", {
        account_id: decoded.account_id,
        gallery_id: decoded.gallery_id,
        iat: decoded.iat,
        exp: decoded.exp,
      });
      console.log(
        "⏰ Token issued at:",
        new Date(decoded.iat * 1000).toISOString(),
      );
      console.log(
        "⏰ Token expires at:",
        new Date(decoded.exp * 1000).toISOString(),
      );

      const now = Date.now();
      const expiresIn = decoded.exp * 1000 - now;
      console.log(
        "⏱️  Time until expiry:",
        Math.floor(expiresIn / 1000 / 60 / 60 / 24),
        "days",
      );
    } catch (jwtError) {
      console.log("❌ JWT verification failed!");
      console.log("💥 Error name:", jwtError.name);
      console.log("💥 Error message:", jwtError.message);
      if (jwtError.name === "TokenExpiredError") {
        console.log(
          "⏰ Token expired at:",
          new Date(jwtError.expiredAt).toISOString(),
        );
      }
      throw jwtError;
    }

    // ============================================
    // PHASE 3: CHECK DATABASE FOR USER AND TOKEN
    // ============================================
    console.log("\n📋 Phase 3: Checking database for user and token match");
    console.log("🔍 Looking up account_id:", decoded.account_id);

    const [userRows] = await req.db.query(
      `SELECT 
        a.account_id AS accountId, 
        g.gallery_id AS galleryId, 
        a.refresh_token AS storedToken,
        CHAR_LENGTH(a.refresh_token) AS storedTokenLength
      FROM tb_account a 
      LEFT JOIN tb_gallery g ON g.account_id = a.account_id 
      WHERE a.account_id = ?`,
      [decoded.account_id],
    );

    console.log("📊 Database query result:");
    console.log("  Rows found:", userRows.length);

    if (userRows.length === 0) {
      console.log("❌ ERROR: User not found in database");
      console.log("  Account ID searched:", decoded.account_id);
      res.clearCookie("access_token");
      res.clearCookie("refresh_token");
      console.log("📤 Responding with 403\n");
      return next(new AppError("Invalid or compromised refresh token", 403));
    }

    const user = userRows[0];
    const storedToken = user.storedToken;

    console.log("✅ User found:");
    console.log("  Account ID:", user.accountId);
    console.log("  Gallery ID:", user.galleryId);
    console.log("  Has stored token:", !!storedToken ? "YES ✅" : "NO ❌");
    console.log("  Stored token length:", user.storedTokenLength);

    console.log("\n💾 Stored token from database:");
    console.log("📝 Full token:", storedToken);
    console.log("🔤 First 100 chars:", storedToken?.substring(0, 100));
    console.log(
      "🔤 Last 100 chars:",
      storedToken?.substring(storedToken?.length - 100),
    );

    // ============================================
    // PHASE 3.5: DETAILED TOKEN COMPARISON
    // ============================================
    console.log("\n🔍 ========== DETAILED TOKEN COMPARISON ==========");
    console.log("📏 Incoming token length:", incomingToken.length);
    console.log("📏 Stored token length:  ", storedToken?.length);
    console.log(
      "📏 Length difference:    ",
      Math.abs(incomingToken.length - (storedToken?.length || 0)),
    );

    // Check if lengths match
    if (incomingToken.length !== storedToken?.length) {
      console.log("⚠️  WARNING: Token lengths don't match!");
      if (storedToken && storedToken.length < incomingToken.length) {
        console.log(
          "   → Stored token is SHORTER (possible database truncation)",
        );
      } else if (storedToken && storedToken.length > incomingToken.length) {
        console.log(
          "   → Incoming token is SHORTER (possible cookie corruption)",
        );
      }
    } else {
      console.log("✅ Token lengths match");
    }

    // Character-by-character comparison
    let firstDiffIndex = -1;
    const minLength = Math.min(incomingToken.length, storedToken?.length || 0);

    for (let i = 0; i < minLength; i++) {
      if (incomingToken[i] !== storedToken[i]) {
        firstDiffIndex = i;
        break;
      }
    }

    if (firstDiffIndex !== -1) {
      console.log(
        "\n🚨 First character difference found at index:",
        firstDiffIndex,
      );
      const contextStart = Math.max(0, firstDiffIndex - 20);
      const contextEnd = Math.min(minLength, firstDiffIndex + 20);
      console.log("Context window (±20 chars):");
      console.log(
        "  Incoming:",
        incomingToken.substring(contextStart, contextEnd),
      );
      console.log(
        "  Stored:  ",
        storedToken.substring(contextStart, contextEnd),
      );
      console.log("\nExact character difference:");
      console.log(
        "  Incoming char:",
        `'${incomingToken[firstDiffIndex]}'`,
        "(ASCII:",
        incomingToken.charCodeAt(firstDiffIndex),
        ")",
      );
      console.log(
        "  Stored char:  ",
        `'${storedToken[firstDiffIndex]}'`,
        "(ASCII:",
        storedToken.charCodeAt(firstDiffIndex),
        ")",
      );
    } else if (incomingToken.length === storedToken?.length) {
      console.log("✅ All characters match perfectly");
    } else {
      console.log("⚠️  Tokens match up to index:", minLength);
      console.log("   One token continues beyond this point (truncation)");
    }

    // Final comparison
    const tokenMatches = storedToken === incomingToken;
    console.log(
      "\n🔐 FINAL COMPARISON RESULT:",
      tokenMatches ? "MATCH ✅" : "MISMATCH ❌",
    );

    if (!tokenMatches) {
      console.log("\n❌ ========== TOKEN MISMATCH DETECTED ==========");

      // Try to decode stored token to get more info
      try {
        const storedDecoded = jwt.verify(
          storedToken,
          process.env.JWT_REFRESH_SECRET,
        );
        console.log("\n📊 STORED TOKEN ANALYSIS:");
        console.log("  Account ID:", storedDecoded.account_id);
        console.log("  Gallery ID:", storedDecoded.gallery_id);
        console.log(
          "  Issued at:",
          new Date(storedDecoded.iat * 1000).toISOString(),
        );
        console.log(
          "  Expires at:",
          new Date(storedDecoded.exp * 1000).toISOString(),
        );

        console.log("\n📊 INCOMING TOKEN ANALYSIS:");
        console.log("  Account ID:", decoded.account_id);
        console.log("  Gallery ID:", decoded.gallery_id);
        console.log("  Issued at:", new Date(decoded.iat * 1000).toISOString());
        console.log(
          "  Expires at:",
          new Date(decoded.exp * 1000).toISOString(),
        );

        console.log("\n⏰ TIMING COMPARISON:");
        if (storedDecoded.iat > decoded.iat) {
          const timeDiff = storedDecoded.iat - decoded.iat;
          console.log("  Stored token is NEWER by", timeDiff, "seconds");
          console.log("\n💡 DIAGNOSIS: Token Reuse / Already Refreshed");
          console.log("  Possible causes:");
          console.log("    1. Token was already refreshed in another request");
          console.log("    2. Multiple refresh requests (race condition)");
          console.log("    3. Browser cached old cookie");
          console.log("    4. Multiple tabs making concurrent requests");
        } else if (storedDecoded.iat < decoded.iat) {
          const timeDiff = decoded.iat - storedDecoded.iat;
          console.log("  Incoming token is NEWER by", timeDiff, "seconds");
          console.log("\n💡 DIAGNOSIS: Token Overwritten");
          console.log("  Possible causes:");
          console.log("    1. Multiple login sessions");
          console.log("    2. Another device/tab logged in");
          console.log("    3. Token was replaced by newer login");
        } else {
          console.log("  Tokens issued at SAME time but content differs");
          console.log("\n💡 DIAGNOSIS: Unknown Corruption");
          console.log("  Possible causes:");
          console.log("    1. Database corruption");
          console.log("    2. Encoding/charset issue");
          console.log("    3. Memory corruption");
        }
      } catch (storedTokenError) {
        console.log(
          "\n⚠️  Could not decode stored token:",
          storedTokenError.message,
        );
        console.log("The stored token in database may be corrupted or invalid");
      }

      console.log("\n🧹 Clearing cookies and rejecting request");
      res.clearCookie("access_token");
      res.clearCookie("refresh_token");
      console.log("📤 Responding with 403\n");
      return next(new AppError("Invalid or compromised refresh token", 403));
    }

    console.log("✅ Tokens match! User validated successfully");
    console.log("  Account ID:", user.accountId);
    console.log("  Gallery ID:", user.galleryId);

    // ============================================
    // PHASE 4: GENERATE NEW TOKEN PAIR
    // ============================================
    console.log("\n📋 Phase 4: Generating new token pair");
    const tokens = generateTokens(user.accountId, user.galleryId);

    console.log("✅ New tokens generated:");
    console.log(
      "  Access token:",
      tokens.accessToken ? "Generated ✅" : "Missing ❌",
    );
    console.log(
      "  Refresh token:",
      tokens.refreshToken ? "Generated ✅" : "Missing ❌",
    );
    console.log("  Access token length:", tokens.accessToken?.length);
    console.log("  Refresh token length:", tokens.refreshToken?.length);
    console.log(
      "  New refresh token (first 50):",
      tokens.refreshToken?.substring(0, 50),
    );

    // ============================================
    // PHASE 5: UPDATE DATABASE WITH NEW TOKEN
    // ============================================
    console.log("\n📋 Phase 5: Updating database with new refresh token");
    console.log("🔄 Updating account_id:", user.accountId);

    const [updateResult] = await req.db.query(
      "UPDATE tb_account SET refresh_token = ? WHERE account_id = ?",
      [tokens.refreshToken, user.accountId],
    );

    console.log("✅ Database update result:");
    console.log("  Affected rows:", updateResult.affectedRows);
    console.log("  Changed rows:", updateResult.changedRows);
    console.log("  Warnings:", updateResult.warningCount);

    // Verify the update
    const [verifyUpdate] = await req.db.query(
      "SELECT CHAR_LENGTH(refresh_token) as new_length FROM tb_account WHERE account_id = ?",
      [user.accountId],
    );
    console.log(
      "✅ Verification: New token length in DB:",
      verifyUpdate[0].new_length,
    );

    // ============================================
    // PHASE 6: SET NEW COOKIES
    // ============================================
    console.log("\n📋 Phase 6: Setting new cookies");

    if (tokens.accessToken) {
      res.cookie("access_token", tokens.accessToken, {
        httpOnly: true,
        secure: false,
        sameSite: "lax",
        maxAge: 60 * 1000, // 1 minute (for testing)
        path: "/",
      });
      console.log("✅ access_token cookie set");
      console.log("  Expires in: 1 minute");
      console.log("  Length:", tokens.accessToken.length);
    } else {
      console.log("❌ WARNING: No access token to set");
    }

    if (tokens.refreshToken) {
      res.cookie("refresh_token", tokens.refreshToken, {
        httpOnly: true,
        secure: false,
        sameSite: "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        path: "/",
      });
      console.log("✅ refresh_token cookie set");
      console.log("  Expires in: 7 days");
      console.log("  Length:", tokens.refreshToken.length);
    } else {
      console.log("❌ WARNING: No refresh token to set");
    }

    const setCookieHeaders = res.getHeader("Set-Cookie");
    if (setCookieHeaders) {
      console.log("\n🍪 Set-Cookie headers being sent:");
      if (Array.isArray(setCookieHeaders)) {
        setCookieHeaders.forEach((header, index) => {
          console.log(`  [${index}]:`, header.substring(0, 100) + "...");
        });
      } else {
        console.log("  ", setCookieHeaders.substring(0, 100) + "...");
      }
    }

    console.log("\n✅ ========== TOKENS REFRESHED SUCCESSFULLY ==========");
    console.log("📤 Sending success response to client");
    console.log("  Account ID:", user.accountId);
    console.log("  Gallery ID:", user.galleryId);
    console.log("========================================\n");

    res.status(200).json({
      status: "success",
      user: { account_id: user.accountId, gallery_id: user.galleryId },
    });
  } catch (err) {
    console.log("\n❌ ========== REFRESH TOKEN ERROR ==========");
    console.log("💥 Error type:", err.name);
    console.log("💥 Error message:", err.message);
    console.log("💥 Error stack:", err.stack?.substring(0, 500));

    console.log("\n🧹 Clearing all cookies due to error");
    res.clearCookie("access_token");
    res.clearCookie("refresh_token");

    console.log("📤 Sending error response to client");
    console.log("========================================\n");

    next(new AppError("Session expired. Please log in again.", 403));
  }
};

export const verifyEmail = async (req, res, next) => {
  try {
    const { token } = req.query;

    if (!token) {
      return next(new AppError("Verification token missing", 400));
    }

    const [rows] = await req.db.query(
      `SELECT account_id FROM tb_email_verifications
       WHERE verify_token = ? AND expires_at > NOW()`,
      [token],
    );

    if (rows.length === 0) {
      return next(new AppError("Invalid or expired token", 400));
    }

    const accountId = rows[0].account_id;

    // Mark verified
    await req.db.query(
      "UPDATE tb_account SET is_verified = 1 WHERE account_id = ?",
      [accountId],
    );

    // Remove token
    await req.db.query(
      "DELETE FROM tb_email_verifications WHERE account_id = ?",
      [accountId],
    );

    const __dirname = path.resolve();
    res.sendFile(path.join(__dirname, "/public/verified.html"));
  } catch (err) {
    next(err);
  }
};

export const forgotPassword = async (req, res, next) => {
  let resetToken = null;

  try {
    const { email } = req.body;

    const [users] = await req.db.query(
      "SELECT account_id, is_verified, is_active FROM tb_account WHERE email = ?",
      [email],
    );

    if (users.length > 0) {
      const user = users[0];

      // Only allow verified + active accounts
      if (user.is_verified === 1 && user.is_active === 1) {
        resetToken = crypto.randomBytes(32).toString("hex");
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

        // Remove old tokens
        await req.db.query(
          "DELETE FROM tb_password_resets WHERE account_id = ?",
          [user.account_id],
        );

        // Insert new token
        await req.db.query(
          `INSERT INTO tb_password_resets (account_id, reset_token, expires_at)
           VALUES (?, ?, ?)`,
          [user.account_id, resetToken, expiresAt],
        );

        await sendPasswordResetEmail(email, resetToken);

        console.log("🔐 PASSWORD RESET TOKEN:", resetToken);
      }
    }

    res.status(200).json({
      status: "success",
      message:
        "If an account with that email exists, a reset link has been sent.",
      ...(process.env.NODE_ENV === "development" && resetToken
        ? { debug: { resetToken } }
        : {}),
    });
  } catch (err) {
    next(err);
  }
};

export const resetPassword = async (req, res, next) => {
  const connection = await req.db.getConnection();
  try {
    const { token, newPassword } = req.body;

    const [rows] = await connection.execute(
      `SELECT account_id FROM tb_password_resets
       WHERE reset_token = ? AND expires_at > NOW()`,
      [token],
    );

    if (rows.length === 0) {
      throw new AppError("Invalid or expired reset token", 400);
    }

    const accountId = rows[0].account_id;

    const hashedPassword = await argon2.hash(newPassword, {
      type: argon2.argon2id,
    });

    await connection.beginTransaction();

    await connection.execute(
      "UPDATE tb_account SET password = ? WHERE account_id = ?",
      [hashedPassword, accountId],
    );

    await connection.execute(
      "DELETE FROM tb_password_resets WHERE account_id = ?",
      [accountId],
    );

    await connection.execute(
      "DELETE FROM tb_refresh_token WHERE account_id = ?",
      [accountId],
    );

    await connection.commit();

    res.status(200).json({
      status: "success",
      message: "Password reset successful. Please log in again.",
    });
  } catch (err) {
    await connection.rollback();
    next(err);
  } finally {
    connection.release();
  }
};

//set password
export const setPassword = async (req, res, next) => {
  try {
    // Get new password from validated request body
    const { new_password } = req.validatedBody;

    // Get account_id from JWT middleware
    const { account_id } = req.user;

    // Hash the new password
    const hashedPassword = await argon2.hash(new_password);

    // Update password in database
    const [result] = await req.db.query(
      "UPDATE tb_account SET password = ? WHERE account_id = ?",
      [hashedPassword, account_id],
    );

    // If no rows updated, account does not exist
    if (result.affectedRows === 0) {
      return res.status(404).json({
        status: "fail",
        message: "Account not found.",
      });
    }

    res.status(200).json({
      status: "success",
      message:
        "Password set successfully. You can now login with your email and password.",
    });
  } catch (err) {
    next(err);
  }
};
