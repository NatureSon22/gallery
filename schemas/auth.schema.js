// schemas/auth.schema.js
import { z } from "zod";

export const signupSchema = z.object({
  email: z.string().email("Invalid email"),
  password: z.string().min(6, "Password must be at least 6 characters"),
  display_name: z.string().optional(),
  age: z.coerce.number().int().positive().optional(),

});

export const signupQuerySchema = z.object({
  plan: z.string().optional(),
});
