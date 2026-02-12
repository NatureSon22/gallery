import nodemailer from "nodemailer";
import { config } from "dotenv";
import { Resend } from "resend";

config();

const resend = new Resend(process.env.RESEND_KEY);

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
// ...existing code...
export const sendVerificationEmail = async (to, token) => {
  const link = `http://localhost:8000/api/v1/auth/verify-email?token=${token}`;

  const { data, error } = await resend.emails.send({
    from: "GALLERY API",
    to: [to],
    subject: "Verify Email",
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
        <p style="margin:12px 0 0">Or open this link manually:</p>
        <p style="word-break:break-all"><a href="${link}">${link}</a></p>
        <p style="color:#555; font-size:0.9em">This link expires in 24 hours.</p>
      </div>
    `,
  });

  if (error) {
    return console.error({ error });
  }

  console.log({ data });

  // await transporter.sendMail({
  //   from: `"Base" <${process.env.SMTP_USER}>`,
  //   to,
  //   subject: "Verify your email",
  //   html: `
  //     <div style="font-family: Arial, Helvetica, sans-serif; color: #111; line-height: 1.4;">
  //       <h3 style="margin-top:0">Email Verification</h3>
  //       <p>Click the button below to verify your account:</p>
  //       <p>
  //         <a
  //           href="${link}"
  //           style="
  //             display:inline-block;
  //             padding:12px 20px;
  //             background-color:#1a73e8;
  //             color:#ffffff;
  //             text-decoration:none;
  //             border-radius:6px;
  //             font-weight:600;
  //           "
  //           target="_blank"
  //           rel="noopener noreferrer"
  //         >
  //           Verify Email
  //         </a>
  //       </p>
  //       <p style="margin:12px 0 0">Or open this link manually:</p>
  //       <p style="word-break:break-all"><a href="${link}">${link}</a></p>
  //       <p style="color:#555; font-size:0.9em">This link expires in 24 hours.</p>
  //     </div>
  //   `,
  // });
};
// ...existing code...

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
