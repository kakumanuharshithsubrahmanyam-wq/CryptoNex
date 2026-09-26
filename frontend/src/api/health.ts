import { apiGet } from "./client"

export interface HealthResponse {
  status: "ok"
  service: string
}

function isHealthResponse(value: unknown): value is HealthResponse {
  if (typeof value !== "object" || value === null) {
    return false
  }
  const record = value as Record<string, unknown>
  return record.status === "ok" && typeof record.service === "string"
}

export function getHealth(): Promise<HealthResponse> {
  return apiGet("/api/v1/health", (value) => {
    if (!isHealthResponse(value)) {
      throw new Error("CryptoNex API returned an unexpected health response.")
    }
    return value
  })
}
