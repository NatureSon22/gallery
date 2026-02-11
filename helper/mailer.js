import nodemailer from "nodemailer";
import { config } from "dotenv";

config();

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
      <h3>Email Verification</h3>
      <p>Click the link below to verify your account:</p>
      <a href="${link}">${link}</a>
      <p>This link expires in 24 hours.</p>
    `,
  });
};

/**
 * Password Reset Email
 */
export const sendPasswordResetEmail = async (to, token) => {
  const link = `${process.env.FRONTEND_ORIGIN}/forgot-password/set-up-new-password?token=${token}&email=${to}`;

  await transporter.sendMail({
    from: `"Base Support" <${process.env.SMTP_USER}>`,
    to,
    subject: "Reset your password",
    html: `
      <h3>Password Reset</h3>
      <p>You requested a password reset.</p>
      <p>Click the link below to reset your password:</p>
      <a href="${link}">${link}</a>
      <p>This link expires in 1 hour.</p>
      <br/>
      <p>If you did not request this, you can safely ignore this email.</p>
    `,
  });
};

transporter.verify((error, success) => {
  if (error) {
    console.error("SMTP ERROR:", error);
  } else {
    console.log("SMTP READY: Server is ready to send emails");
  }
});
