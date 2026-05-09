import { z } from "zod";

// --- Sub-esquemas ---

export const EngineResultSchema = z.object({
  name: z.string(),
  status: z.string(),
  result: z.string().nullable(),
  method: z.string(),
});

export const ThreatStatsSchema = z.object({
  malicious: z.number(),
  suspicious: z.number(),
  undetected: z.number(),
  harmless: z.number(),
  timeout: z.number(),
  full_results: z.array(EngineResultSchema).optional(),
  heuristic_flag: z.string().optional(),
});

export const AISummarySchema = z.union([
  z.string(),
  z.object({
    summary: z.string(),
    action_steps: z.array(z.string()),
  }),
]).nullable();

export const GeolocationSchema = z.object({
  ip: z.string().optional(),
  lat: z.number().optional(),
  lon: z.number().optional(),
  country: z.string().optional(),
  countryCode: z.string().optional(),
  city: z.string().optional(),
  isp: z.string().optional(),
}).nullable();

export const OSINTDataSchema = z.object({
  geolocation: GeolocationSchema.nullish(),
  is_typosquatting: z.boolean().nullish(),
  target_brand: z.string().nullish(),
  has_dangerous_form: z.boolean().nullish(),
  redirect_chain: z.array(z.string()).nullish(),
  screenshot_desktop: z.string().nullish(),
  screenshot_mobile: z.string().nullish(),
  cloaking_detected: z.boolean().nullish(),
  // Añadir más campos según sea necesario...
}).passthrough(); // Permitimos campos extra para no romper si el backend añade algo nuevo

// --- Esquema Principal ---

export const ScanResultSchema = z.object({
  type: z.enum(["url", "image"]),
  stats: ThreatStatsSchema.nullable().optional(),
  ai_summary: AISummarySchema.optional(),
  status: z.enum(["success", "error"]),
  message: z.string().optional(),
  resourceName: z.string().optional(),
  timestamp: z.string().optional(),
  osint_data: OSINTDataSchema.nullable().optional(),
  image_analysis: z.any().nullable().optional(), // Podemos detallar más luego
});

export type ScanResultValidated = z.infer<typeof ScanResultSchema>;
