import { z } from "zod";

export const deletePhotosSchema = z.object({
  photo_ids: z
    .array(z.coerce.number().int().positive())
    .min(1, "photo_ids must be a non-empty array"),
});
