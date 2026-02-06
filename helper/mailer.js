import nodemailer from "nodemailer";

export const sendVerificationEmail = async (to, token) => {
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });

  const link = `http://localhost:8000/api/v1/auth/verify-email?token=${token}`;

  await transporter.sendMail({
    from: `"Base" <${process.env.SMTP_USER}>`,
    to,
    subject: "Verify your email",
    html: `
      <h3>Verify your email</h3>
      <p>Click the link below:</p>
      <a href="${link}">${link}</a>
    `,
  });
};
