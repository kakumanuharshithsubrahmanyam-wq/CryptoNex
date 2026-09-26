export class ApiError extends Error {
  readonly code: string | null

  constructor(message: string, code: string | null = null) {
    super(message)
    this.name = "ApiError"
    this.code = code
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
  return request(path, { method: "GET", headers: { Accept: "application/json" } }, parse)
}

export async function apiPostJson<T>(
  path: string,
  body: unknown,
  parse: (value: unknown) => T,
): Promise<T> {
  return request(
    path,
    {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify(body),
    },
    parse,
  )
}

export async function apiPostForm<T>(
  path: string,
  body: FormData,
  parse: (value: unknown) => T,
): Promise<T> {
  return request(path, { method: "POST", headers: { Accept: "application/json" }, body }, parse)
}

async function request<T>(
  path: string,
  init: RequestInit,
  parse: (value: unknown) => T,
): Promise<T> {
  const url = `${apiBaseUrl()}${path.startsWith("/") ? path : `/${path}`}`
  let response: Response
  try {
    response = await fetch(url, init)
  } catch {
    throw new ApiError(
      "Unable to reach the CryptoNex API. Check that the backend is running and VITE_API_BASE_URL is correct.",
    )
  }

  if (!response.ok) {
    throw await apiErrorFromResponse(response)
  }

  let body: unknown
  try {
    body = await response.json()
  } catch {
    throw new ApiError("CryptoNex API returned a response that was not JSON.")
  }

  return parse(body)
}

async function apiErrorFromResponse(response: Response): Promise<ApiError> {
  try {
    const body: unknown = await response.json()
    if (typeof body === "object" && body !== null && "error" in body) {
      const error = (body as { error?: { code?: unknown; message?: unknown } }).error
      const message = typeof error?.message === "string" ? error.message : ""
      const code = typeof error?.code === "string" ? error.code : null
      if (message) {
        return new ApiError(message, code)
      }
    }
  } catch {
    return new ApiError(`CryptoNex API returned HTTP ${response.status}.`)
  }
  return new ApiError(`CryptoNex API returned HTTP ${response.status}.`)
}
