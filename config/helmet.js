const isDevelopment = process.env.NODE_ENV === "development";
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN;

const helmetConfig = {
  // Content-Security-Policy: Mitigates attacks like cross-site scripting (XSS).
  // Directives are merged into a default policy.
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      // Explicitly allowing the frontend URL for script and connection sources.
      "script-src": ["'self'", FRONTEND_ORIGIN],
      "connect-src": ["'self'", FRONTEND_ORIGIN],
      // upgrade-insecure-requests is set by default but can cause issues on localhost in some browsers.
      // It is disabled here for development environments.
      "upgrade-insecure-requests": isDevelopment ? null : [],
    },
  },
  // Cross-Origin-Embedder-Policy: Helps control what resources can be loaded cross-origin.
  // This is not set by default; setting it to 'credentialless' here.
  crossOriginResourcePolicy: {
    policy: isDevelopment ? "cross-origin" : "same-origin",
  },
  crossOriginEmbedderPolicy: {
    policy: isDevelopment ? "unsafe-none" : "credentialless",
  },
  crossOriginOpenerPolicy: { policy: "same-origin" },
  // Origin-Agent-Cluster: Allows web applications to isolate origins from other processes.
  // Set to "?1" by default and takes no additional options.
  originAgentCluster: true,
  // Referrer-Policy: Controls the information sent in the Referer request header.
  // Default is "no-referrer".
  referrerPolicy: { policy: "no-referrer" },
  // Strict-Transport-Security: Tells browsers to prefer HTTPS over insecure HTTP.
  // It is often disabled in development to avoid forced redirects on localhost.
  strictTransportSecurity: isDevelopment
    ? false
    : {
        maxAge: 31536000, // Default is 365 days in seconds.
        includeSubDomains: true, // Extends the policy to all subdomains.
        preload: true, // Adds the preload directive for browser inclusion.
      },
  // X-Content-Type-Options: Mitigates MIME type sniffing.
  // Set to "nosniff" by default and takes no options.
  xContentTypeOptions: true,
  // X-DNS-Prefetch-Control: Controls DNS prefetching to improve privacy.
  // Default is "off".
  xDnsPrefetchControl: { allow: false },
  // X-Download-Options: Specific to IE8; forces potentially unsafe downloads to be saved.
  // Set to "noopen" by default.
  xDownloadOptions: true,
  // X-Frame-Options: Legacy header to help mitigate clickjacking attacks.
  // Default is "SAMEORIGIN".
  xFrameOptions: { action: "sameorigin" },
  // X-Permitted-Cross-Domain-Policies: Policy for loading cross-domain content in some clients (Adobe).
  // Default is "none".
  xPermittedCrossDomainPolicies: { permittedPolicies: "none" },
  // X-Powered-By: Removes the X-Powered-By header to hide technology details and save bandwidth.
  // This behavior is enabled by default.
  xPoweredBy: false,
  // X-XSS-Protection: Disables the browser's often buggy cross-site scripting filter.
  // Set to "0" by default.
  xXssProtection: true,
};

export default helmetConfig;