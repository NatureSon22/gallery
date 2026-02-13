import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: false, // TLS
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

/**
 * Email Verification
 */
export const sendVerificationEmail = async (to, token) => {
  const link = `http://localhost:8000/api/v1/auth/verify-email?token=${token}`;

  await transporter.sendMail({
    from: `"Base" <${process.env.SMTP_USER}>`,
    to,
    subject: "Verify your email",
    html: `
      <div style="font-family: Arial, Helvetica, sans-serif; color: #111; line-height: 1.4;">
        <h3 style="margin-top:0">Email Verification</h3>
        <p>Click the button below to verify your account:</p>
        <p>
          <a
            href="${link}"
            style="
              display:inline-block;
              padding:12px 20px;
              background-color:#1a73e8;
              color:#ffffff;
              text-decoration:none;
              border-radius:6px;
              font-weight:600;
            "
            target="_blank"
            rel="noopener noreferrer"
          >
            Verify Email
          </a>
        </p>
        <p style="color:#555; font-size:0.9em">This link expires in 24 hours.</p>
      </div>
    `,
  });
};

/**
 * Password Reset Email
 */
export const sendPasswordResetEmail = async (to, token) => {
  const FRONTEND = (
    process.env.FRONTEND_ORIGIN || "http://localhost:5173"
  ).replace(/\/$/, "");
  const link = `${FRONTEND}/forgot-password/set-up-new-password?token=${encodeURIComponent(token)}&email=${encodeURIComponent(to)}`;

  const html = `
    <div style="font-family: Arial, Helvetica, sans-serif; color: #111; line-height: 1.4;">
      <h3>Password Reset</h3>
      <p>You requested a password reset. Click the button below to reset your password:</p>
      <p>
        <a
          href="${link}"
          style="display:inline-block;padding:12px 20px;background-color:#1a73e8;color:#fff;text-decoration:none;border-radius:6px;font-weight:600;"
          target="_blank" rel="noopener noreferrer"
        >
          Reset Password
        </a>
      </p>
      <p style="margin-top:12px;word-break:break-all"><a href="${link}">${link}</a></p>
      <p style="color:#555;font-size:0.9em">This link expires in 1 hour.</p>
    </div>
  `;

  try {
    return await transporter.sendMail({
      from: `"Base Support" <${process.env.SMTP_USER}>`,
      to,
      subject: "Reset your password",
      html,
    });
  } catch (err) {
    console.error("Failed to send reset email:", err);
    throw err;
  }
};

transporter.verify((error, success) => {
  if (error) {
    console.error("SMTP ERROR:", error);
  } else {
    console.log("SMTP READY: Server is ready to send emails");
  }
});
