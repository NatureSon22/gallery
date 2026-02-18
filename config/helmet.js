const isProduction = process.env.NODE_ENV === "production";
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN;

const helmetConfig = {
  // 1. Content Security Policy (CSP)
  // - Purpose: Prevents injection-based attacks (XSS) by restricting where
  //   scripts, styles, images, fonts, and network requests can be loaded from.
  // - useDefaults: starts with Helmet's sensible defaults, then we add rules.
  // - directives: whitelist only trusted sources. Example below allows scripts
  //   from your origin and Google's APIs. Add other hosts only if needed.
  // - Note: overly strict CSP can break third-party widgets, inline scripts,
  //   or analytics; loosen intentionally and test.
  contentSecurityPolicy: isProduction
    ? {
        useDefaults: true,
        directives: {
          "script-src": ["'self'", "https://apis.google.com", FRONTEND_ORIGIN],
          "connect-src": ["'self'", FRONTEND_ORIGIN],
        },
      }
    : false,

  // 2. Strict-Transport-Security (HSTS)
  // - Purpose: tells browsers to always use HTTPS for your site for the given
  //   maxAge. Prevents downgrade attacks / accidental HTTP usage.
  // - includeSubDomains: apply policy to subdomains as well.
  // - preload: if true, you can request inclusion in browsers' HSTS preload list
  //   (only set after careful testing, and only on sites serving HTTPS).
  // - Warning: once enabled in production + preload, it is hard to undo.
  strictTransportSecurity: isProduction
    ? {
        maxAge: 31536000, // 1 year in seconds
        includeSubDomains: true,
        preload: true,
      }
    : false,

  // 3. Referrer-Policy
  // - Purpose: controls the Referer header sent when navigating away from your site.
  // - "strict-origin-when-cross-origin": sends full URL on same-origin, only
  //   origin on cross-origin navigations (good balance of privacy and usability).
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },

  // 4. X-Frame-Options (Clickjacking protection)
  // - Purpose: prevents other sites from embedding your pages in an iframe.
  // - "deny": do not allow embedding at all. "sameorigin": allow only same origin.
  // - Use "sameorigin" in dev to allow local testing (e.g. dashboards), use "deny"
  //   or a CSP frame-ancestors directive in production if you never embed.
  xFrameOptions: { action: isProduction ? "deny" : "sameorigin" },

  // 5. Cross-Origin-Embedder-Policy (COEP)
  // - Purpose: controls whether cross-origin resources can be embedded.
  // - "require-corp" forces cross-origin resources to provide explicit permission
  //   (via CORP/CORS headers). Required for certain browser features (e.g. SharedArrayBuffer).
  // - Enabling can break third-party embeds unless those hosts opt-in.
  crossOriginEmbedderPolicy: isProduction ? { policy: "credentialless" } : false,

  // 6. Cross-Origin-Opener-Policy (COOP)
  // - Purpose: isolates window browsing contexts (tabs/windows) to separate processes.
  // - "same-origin" prevents other origins from being able to open/communicate with your window,
  //   improving security for cross-origin data leaks. Useful with COEP for powerful isolation features.
  crossOriginOpenerPolicy: { policy: "same-origin" },

  // 7. Cross-Origin-Resource-Policy (CORP)
  // - Purpose: restricts which origins can fetch resources (images/scripts) from your site.
  // - "same-origin" prevents other origins from embedding or fetching your resources,
  //   reducing data leakage. Loosen if you intentionally serve public assets to other sites.
  crossOriginResourcePolicy: { policy: "same-origin" },

  // 8. Origin-Agent-Cluster
  // - Purpose: opts-in to a new process isolation model for web pages, which can
  //   improve security and privacy boundaries between origins.
  // - Keep enabled unless you have legacy compat reasons.
  originAgentCluster: true,

  // 9. X-Content-Type-Options
  // - Purpose: sets "X-Content-Type-Options: nosniff" to stop browsers from
  //   guessing MIME types. Prevents some types of drive-by downloads and XSS.
  xContentTypeOptions: true,

  // 10. X-DNS-Prefetch-Control
  // - Purpose: disables the browser's DNS prefetching (privacy & perf tradeoff).
  // - Default false here to avoid the browser pre-resolving links automatically.
  xDnsPrefetchControl: { allow: false },

  // 11. X-Download-Options
  // - Purpose: (IE-specific) prevents downloads from being executed in your site's context.
  // - Mostly legacy but harmless to enable for defense in depth.
  xDownloadOptions: true,

  // 12. X-Permitted-Cross-Domain-Policies
  // - Purpose: instructs Adobe/Flash clients whether they can load cross-domain policies.
  // - "none" prevents such plugins from accessing your site — safe default.
  xPermittedCrossDomainPolicies: { permittedPolicies: "none" },

  // 13. X-XSS-Protection
  // - Purpose: enables legacy browser XSS filters. Modern browsers ignore it,
  //   but keeping it enabled is low risk. Do not rely on it as a primary defense.
  xXssProtection: true,

  // 14. X-Powered-By
  // - Purpose: hides the "X-Powered-By: Express" header to reduce fingerprinting.
  // - Doesn't improve security directly but reduces information leakage.
  xPoweredBy: false,
};

export default helmetConfig;
