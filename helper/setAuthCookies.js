/**
 * setAuthCookies(res, tokens, opts)
 *
 * @param {import('express').Response} res - Express response object (required)
 * @param {{ accessToken?: string, refreshToken?: string }} [tokens] - tokens to set as cookies
 */

const setAuthCookies = (res, tokens = {}) => {
  const { accessToken, refreshToken } = tokens;
  console.log(`access_token: ${accessToken}`);
  console.log(`refresh_token: ${refreshToken}`);

  const isProd = process.env.NODE_ENV === "production";

  // sameSite controls when cookies are sent on cross-site requests:
  // - "none": cookie is sent in all contexts (cross-site allowed). Modern browsers require Secure=true when using "none".
  // - "lax": cookie is sent on top-level navigations (safe for most auth redirects) but NOT on most cross-site subrequests (good CSRF protection).
  // - "strict": cookie is only sent for same-site requests (strictest CSRF protection; may break cross-site OAuth redirects).
  const sameSite = isProd ? "none" : "lax";

  // Short-lived access token cookie (sent to all routes)
  if (accessToken) {
    res.cookie("access_token", accessToken, {
      httpOnly: true, // not accessible to JavaScript — defends against XSS
      secure: isProd, // only send over HTTPS in production
      sameSite,
      maxAge: 15 * 60 * 1000, // 15 minutes
    });
  }

  // Long-lived refresh token cookie (scoped to refresh endpoint)
  if (refreshToken) {
    res.cookie("refresh_token", refreshToken, {
      httpOnly: true,
      secure: isProd, // only send over HTTPS in production
      sameSite,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      // path: controls which request paths the browser will include this cookie on.
      // Example:
      // - "/api/v1/auth/refresh" => browser sends cookie only when request path starts with that value.
      // - "/" => browser sends cookie on all requests to the origin.
      // Scoping refresh_token to the refresh endpoint reduces token exposure.
    });
  }
};

export default setAuthCookies;
