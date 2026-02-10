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

export const loginSchema = z.object({
  email: z.string().email("Invalid email format"),
  password: z.string().min(1, "Password is required"),
});

export const setPasswordSchema = z.object({
  new_password: z
    .string()
    .min(6, "Password must be at least 6 characters long"), // Minimum 6 characters
  confirm_password: z.string()
}).refine((data) => data.new_password === data.confirm_password, {
  message: "Passwords do not match",
  path: ["confirm_password"],
});