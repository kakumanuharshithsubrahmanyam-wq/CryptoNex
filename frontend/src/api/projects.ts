import { apiPostForm, apiPostJson } from "./client"

export interface ProjectResult {
  id: number
  name: string
  repository_url: string | null
  source_type: "github" | "zip"
  status: "created" | "ingesting" | "ready" | "failed"
  manifest: {
    file_count: number
    total_size: number
    languages: Record<string, number>
  } | null
}

function isProjectResult(value: unknown): value is ProjectResult {
  if (typeof value !== "object" || value === null) {
    return false
  }
  const record = value as Record<string, unknown>
  return (
    typeof record.id === "number" &&
    typeof record.name === "string" &&
    (record.repository_url === null || typeof record.repository_url === "string") &&
    (record.source_type === "github" || record.source_type === "zip") &&
    (record.status === "created" ||
      record.status === "ingesting" ||
      record.status === "ready" ||
      record.status === "failed")
  )
}

function parseProject(value: unknown): ProjectResult {
  if (!isProjectResult(value)) {
    throw new Error("CryptoNex API returned an unexpected project response.")
  }
  const record = value as unknown as Record<string, unknown>
  return {
    id: record.id as number,
    name: record.name as string,
    repository_url: record.repository_url as string | null,
    source_type: record.source_type as ProjectResult["source_type"],
    status: record.status as ProjectResult["status"],
    manifest: parseManifest(record.manifest),
  }
}

function parseManifest(value: unknown): ProjectResult["manifest"] {
  if (typeof value !== "object" || value === null) {
    return null
  }
  const record = value as Record<string, unknown>
  if (typeof record.file_count !== "number" || typeof record.total_size !== "number") {
    return null
  }
  const languages: Record<string, number> = {}
  if (typeof record.languages === "object" && record.languages !== null) {
    for (const [language, count] of Object.entries(record.languages)) {
      if (typeof count === "number") {
        languages[language] = count
      }
    }
  }
  return {
    file_count: record.file_count,
    total_size: record.total_size,
    languages,
  }
}

export function createGitHubProject(name: string, repositoryUrl: string): Promise<ProjectResult> {
  return apiPostJson(
    "/api/v1/projects",
    { name, repository_url: repositoryUrl },
    parseProject,
  )
}

export function createZipProject(name: string, file: File): Promise<ProjectResult> {
  const body = new FormData()
  body.append("name", name)
  body.append("file", file)
  return apiPostForm("/api/v1/projects/uploads", body, parseProject)
}

export function ingestProject(projectId: number): Promise<ProjectResult> {
  return apiPostJson(`/api/v1/projects/${projectId}/ingest`, {}, parseProject)
}

export interface CryptoScanResult {
  scan_id: number
  project_id: number
  status: string
  summary: {
    files_scanned: number
    findings: number
    algorithms: Record<string, number>
  }
}

function parseCryptoScan(value: unknown): CryptoScanResult {
  if (typeof value !== "object" || value === null) {
    throw new Error("CryptoNex API returned an unexpected scan response.")
  }
  const record = value as Record<string, unknown>
  const summary = record.summary
  if (
    typeof record.scan_id !== "number" ||
    typeof record.project_id !== "number" ||
    typeof record.status !== "string" ||
    typeof summary !== "object" ||
    summary === null
  ) {
    throw new Error("CryptoNex API returned an unexpected scan response.")
  }
  const summaryRecord = summary as Record<string, unknown>
  if (
    typeof summaryRecord.files_scanned !== "number" ||
    typeof summaryRecord.findings !== "number"
  ) {
    throw new Error("CryptoNex API returned an unexpected scan response.")
  }
  const algorithms: Record<string, number> = {}
  if (typeof summaryRecord.algorithms === "object" && summaryRecord.algorithms !== null) {
    for (const [name, count] of Object.entries(summaryRecord.algorithms)) {
      if (typeof count === "number") {
        algorithms[name] = count
      }
    }
  }
  return {
    scan_id: record.scan_id,
    project_id: record.project_id,
    status: record.status,
    summary: {
      files_scanned: summaryRecord.files_scanned,
      findings: summaryRecord.findings,
      algorithms,
    },
  }
}

export function scanProject(projectId: number): Promise<CryptoScanResult> {
  return apiPostJson(`/api/v1/projects/${projectId}/scan`, {}, parseCryptoScan)
}

export function repositoryNameFromUrl(repositoryUrl: string): string {
  const trimmed = repositoryUrl.trim().replace(/\/+$/, "").replace(/\.git$/, "")
  const name = trimmed.split("/").filter(Boolean).pop()
  return (name || "Repository").slice(0, 255)
}
