export class ApiError extends Error {
  constructor(message: string) {
    super(message)
    this.name = "ApiError"
  }
}

export function apiBaseUrl(): string {
  const configured = import.meta.env.VITE_API_BASE_URL?.trim()
  if (!configured) {
    throw new ApiError(
      "VITE_API_BASE_URL is not configured. Set it to the CryptoNex API origin.",
    )
  }
  return configured.replace(/\/+$/, "")
}

export async function apiGet<T>(path: string, parse: (value: unknown) => T): Promise<T> {
  const url = `${apiBaseUrl()}${path.startsWith("/") ? path : `/${path}`}`
  let response: Response
  try {
    response = await fetch(url, {
      method: "GET",
      headers: { Accept: "application/json" },
    })
  } catch {
    throw new ApiError(
      "Unable to reach the CryptoNex API. Check that the backend is running and VITE_API_BASE_URL is correct.",
    )
  }

  if (!response.ok) {
    throw new ApiError(`CryptoNex API returned HTTP ${response.status}.`)
  }

  let body: unknown
  try {
    body = await response.json()
  } catch {
    throw new ApiError("CryptoNex API returned a response that was not JSON.")
  }

  return parse(body)
}
