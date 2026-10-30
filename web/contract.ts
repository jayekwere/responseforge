import { z } from "zod";

const operation = z
  .object({
    operation: z.enum(["ingest", "plan", "approve", "execute", "list", "evidence"]),
    record_id: z
      .string()
      .regex(/^[a-z0-9-]{0,128}$/)
      .default(""),
    data: z.record(z.string(), z.unknown()).default({}),
  })
  .strict();
export const parseOperation = (value: unknown) => operation.parse(value);
