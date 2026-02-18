import { z } from "zod";

export const signupSchema = z.object({
  email: z.string().email("Invalid email format"),
  password: z.string().min(6, "Password must be at least 6 characters"),
  display_name: z.string().optional(),
  age: z.coerce.number().int().positive().optional(),
});

export const signupQuerySchema = z.object({
  plan: z.string().optional(),
});


//login schema
export const loginSchema = z.object({
  email: z.string().email("Invalid email format"),
  password: z.string().min(1, "Password is required"),
});

//set password schema
export const setPasswordSchema = z.object({
  new_password: z
    .string()
    .min(6, "Password must be at least 6 characters long"), // Minimum 6 characters
  confirm_password: z.string()
}).refine((data) => data.new_password === data.confirm_password, {
  message: "Passwords do not match",
  path: ["confirm_password"],
});

//set forgotpassword schema
export const forgotPasswordSchema = z.object({
  email: z.string().email("Invalid email format"),
});

///set reset password schema
export const resetPasswordSchema = z.object({
  token: z.string().min(32, "Invalid or missing reset token"),
  newPassword: z
    .string()
    .min(6, "Password must be at least 6 characters long"),
});

// verify email schema
export const verifyEmailSchema = z.object({
  token: z.string().min(32, "Invalid or missing verification token"),
});