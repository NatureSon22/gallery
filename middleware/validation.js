import AppError from "../helper/AppError.js";

/**
 * Zod Validation Middleware
 * @param {import("zod").ZodSchema} schema - The Zod schema
 * @param {"body" | "query" | "params"} type - The part of the request to validate
 */
const validate =
  (schema, type = "body") =>
  (req, res, next) => {
    try {
      const parsed = schema.parse(req[type]);

      // Store validated data safely
      if (type === "body") req.validatedBody = parsed;
      if (type === "query") req.validatedQuery = parsed;
      if (type === "params") req.validatedParams = parsed;

      next();
    } catch (err) {
      const message =
        err?.issues?.[0]?.message ||
        err?.errors?.[0]?.message ||
        err.message ||
        "Validation error";

      return next(new AppError(message, 400));
    }
  };

export default validate;