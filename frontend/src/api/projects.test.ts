import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { scanProject } from "./projects"

// `parseCryptoScan` is module-private, so these tests exercise it through the
// public `scanProject` call. Only the network boundary (`fetch`) is replaced.

const PROJECT_ID = 7

interface ScanPayload extends Record<string, unknown> {
  summary: Record<string, unknown>
}

// A fresh payload per call, shaped like POST /api/v1/projects/{id}/scan. It
// includes summary fields the frontend does not use, as the real backend sends.
function validScan(): ScanPayload {
  return {
    scan_id: 42,
    project_id: PROJECT_ID,
    status: "completed",
    summary: {
      files_scanned: 120,
      files_skipped: 3,
      findings: 9,
      high_confidence: 5,
      algorithms: { RSA: 4, "AES-128": 3, SHA1: 2 },
    },
  }
}

function scanWith(overrides: Record<string, unknown>): ScanPayload {
  return { ...validScan(), ...overrides }
}

function scanWithout(field: string): ScanPayload {
  const scan = validScan()
  delete scan[field]
  return scan
}

function summaryWith(overrides: Record<string, unknown>): ScanPayload {
  const scan = validScan()
  return { ...scan, summary: { ...scan.summary, ...overrides } }
}

function summaryWithout(field: string): ScanPayload {
  const scan = validScan()
  delete scan.summary[field]
  return scan
}

function respondWith(body: unknown) {
  const fetchMock = vi.fn(
    async () =>
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
  )
  vi.stubGlobal("fetch", fetchMock)
  return fetchMock
}

describe("scanProject response parsing", () => {
  beforeEach(() => {
    vi.stubEnv("VITE_API_BASE_URL", "http://cryptonex.test")
  })

  afterEach(() => {
    vi.unstubAllEnvs()
    vi.unstubAllGlobals()
  })

  describe("valid responses", () => {
    it("preserves the scan identity, status, counts and every algorithm", async () => {
      respondWith(validScan())

      const result = await scanProject(PROJECT_ID)

      expect(result.scan_id).toBe(42)
      expect(result.project_id).toBe(PROJECT_ID)
      expect(result.status).toBe("completed")
      expect(result.summary.files_scanned).toBe(120)
      expect(result.summary.findings).toBe(9)
      expect(result.summary.algorithms).toEqual({ RSA: 4, "AES-128": 3, SHA1: 2 })
    })

    it("accepts a scan that scanned nothing and found nothing", async () => {
      respondWith(summaryWith({ files_scanned: 0, findings: 0, algorithms: {} }))

      const result = await scanProject(PROJECT_ID)

      expect(result.summary.files_scanned).toBe(0)
      expect(result.summary.findings).toBe(0)
      expect(result.summary.algorithms).toEqual({})
    })
  })

  describe("malformed algorithms", () => {
    // The parser does not reject these; it keeps only well-formed counts so the
    // UI can always iterate `summary.algorithms` as a name -> number map.
    it("drops algorithm entries whose count is not a number", async () => {
      respondWith(
        summaryWith({ algorithms: { RSA: 4, ECDSA: "many", MD5: null, SHA1: { n: 1 } } }),
      )

      const result = await scanProject(PROJECT_ID)

      expect(result.summary.algorithms).toEqual({ RSA: 4 })
    })

    it.each([
      { label: "missing", body: summaryWithout("algorithms") },
      { label: "null", body: summaryWith({ algorithms: null }) },
      { label: "a string", body: summaryWith({ algorithms: "RSA" }) },
    ])("returns an empty algorithm map when algorithms is $label", async ({ body }) => {
      respondWith(body)

      const result = await scanProject(PROJECT_ID)

      expect(result.summary.algorithms).toEqual({})
    })
  })

  describe("invalid responses", () => {
    it.each([
      { label: "the body is null", body: null },
      { label: "the body is a string", body: "completed" },
      { label: "the body is a number", body: 42 },
      { label: "the body is an array of scans", body: [validScan()] },
      { label: "scan_id is missing", body: scanWithout("scan_id") },
      { label: "scan_id is a string", body: scanWith({ scan_id: "42" }) },
      { label: "project_id is missing", body: scanWithout("project_id") },
      { label: "project_id is a string", body: scanWith({ project_id: "7" }) },
      { label: "status is missing", body: scanWithout("status") },
      { label: "status is a number", body: scanWith({ status: 200 }) },
      { label: "summary is missing", body: scanWithout("summary") },
      { label: "summary is null", body: scanWith({ summary: null }) },
      { label: "files_scanned is missing", body: summaryWithout("files_scanned") },
      { label: "files_scanned is a string", body: summaryWith({ files_scanned: "120" }) },
      { label: "findings is missing", body: summaryWithout("findings") },
      { label: "findings is a string", body: summaryWith({ findings: "9" }) },
    ])("rejects a response when $label", async ({ body }) => {
      const fetchMock = respondWith(body)

      await expect(scanProject(PROJECT_ID)).rejects.toThrow()

      // The request must have reached the parser; otherwise a setup problem
      // (for example a missing API base URL) would make this pass vacuously.
      expect(fetchMock).toHaveBeenCalledOnce()
    })
  })
})
