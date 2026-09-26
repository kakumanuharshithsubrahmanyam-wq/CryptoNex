import { useCallback, useEffect, useState, type FormEvent } from "react"
import { getHealth } from "./api/health"
import {
  createGitHubProject,
  createZipProject,
  ingestProject,
  repositoryNameFromUrl,
  scanProject,
  type CryptoScanResult,
  type ProjectResult,
} from "./api/projects"
import "./App.css"

type ConnectionState =
  | { kind: "loading" }
  | { kind: "connected"; service: string }
  | { kind: "error"; message: string }

type ScanState =
  | { kind: "idle" }
  | { kind: "running"; message: string }
  | { kind: "ready"; project: ProjectResult }
  | { kind: "error"; message: string }

type CryptoState =
  | { kind: "idle" }
  | { kind: "running" }
  | { kind: "done"; result: CryptoScanResult }
  | { kind: "error"; message: string }

function App() {
  const [connection, setConnection] = useState<ConnectionState>({ kind: "loading" })
  const [repositoryUrl, setRepositoryUrl] = useState("")
  const [scan, setScan] = useState<ScanState>({ kind: "idle" })
  const [crypto, setCrypto] = useState<CryptoState>({ kind: "idle" })

  const checkConnection = useCallback(() => {
    setConnection({ kind: "loading" })
    getHealth()
      .then((health) => {
        setConnection({ kind: "connected", service: health.service })
      })
      .catch((error: unknown) => {
        const message =
          error instanceof Error ? error.message : "Unable to reach the CryptoNex API."
        setConnection({ kind: "error", message })
      })
  }, [])

  useEffect(() => {
    checkConnection()
  }, [checkConnection])

  async function startGitHubScan(event: FormEvent) {
    event.preventDefault()
    const url = repositoryUrl.trim()
    if (!url) {
      setScan({ kind: "error", message: "Enter a GitHub repository URL." })
      return
    }
    setCrypto({ kind: "idle" })
    setScan({ kind: "running", message: "Ingesting repository…" })
    try {
      const created = await createGitHubProject(repositoryNameFromUrl(url), url)
      const ready = await ingestProject(created.id)
      setScan({ kind: "ready", project: ready })
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Repository ingestion failed."
      setScan({ kind: "error", message })
    }
  }

  async function startZipScan(file: File | undefined) {
    if (!file) {
      return
    }
    const name = file.name.replace(/\.zip$/i, "").slice(0, 255) || "Uploaded repository"
    setCrypto({ kind: "idle" })
    setScan({ kind: "running", message: "Ingesting ZIP archive…" })
    try {
      const created = await createZipProject(name, file)
      const ready = await ingestProject(created.id)
      setScan({ kind: "ready", project: ready })
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "ZIP ingestion failed."
      setScan({ kind: "error", message })
    }
  }

  async function runCryptoScan() {
    if (scan.kind !== "ready") {
      return
    }
    setCrypto({ kind: "running" })
    try {
      const result = await scanProject(scan.project.id)
      setCrypto({ kind: "done", result })
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Crypto scan failed."
      setCrypto({ kind: "error", message })
    }
  }

  const busy = scan.kind === "running" || crypto.kind === "running"

  return (
    <main className="shell">
      <p className="phase">Phase 2 — Deterministic Crypto Detection</p>
      <h1>CryptoNex</h1>
      <p className="lede">
        Ingest a public GitHub repository or a ZIP archive, then run a deterministic crypto scan.
      </p>
      <form className="scan" onSubmit={startGitHubScan}>
        <label htmlFor="repository-url">GitHub Repository URL</label>
        <input
          id="repository-url"
          name="repositoryUrl"
          type="url"
          placeholder="https://github.com/user/repository"
          value={repositoryUrl}
          onChange={(event) => setRepositoryUrl(event.target.value)}
          autoComplete="off"
        />
        <button type="submit" disabled={busy}>
          Start Scan
        </button>
        <p className="or">or</p>
        <label className="upload">
          Upload ZIP
          <input
            type="file"
            accept=".zip,application/zip"
            disabled={busy}
            onChange={(event) => {
              const file = event.target.files?.[0]
              void startZipScan(file)
              event.target.value = ""
            }}
          />
        </label>
      </form>
      <section className="status" aria-live="polite">
        {scan.kind === "running" && <p>{scan.message}</p>}
        {scan.kind === "error" && (
          <>
            <p className="bad">Ingestion failed</p>
            <p>{scan.message}</p>
          </>
        )}
        {scan.kind === "ready" && scan.project.manifest && (
          <>
            <p className="ok">Repository ready</p>
            <p className="meta">
              {formatFileCount(scan.project.manifest.file_count)}, {scan.project.manifest.total_size}{" "}
              bytes
            </p>
            <p className="meta">{formatLanguages(scan.project.manifest.languages)}</p>
            <button type="button" onClick={() => void runCryptoScan()} disabled={busy}>
              {crypto.kind === "running" ? "Scanning…" : "Run crypto scan"}
            </button>
            {crypto.kind === "done" && (
              <div className="crypto-summary">
                <p className="ok">Crypto Scan</p>
                <p className="meta">Status: {crypto.result.status}</p>
                <p className="meta">Files scanned: {crypto.result.summary.files_scanned}</p>
                <p className="meta">Findings: {crypto.result.summary.findings}</p>
                <AlgorithmCounts algorithms={crypto.result.summary.algorithms} />
              </div>
            )}
            {crypto.kind === "error" && (
              <>
                <p className="bad">Crypto scan failed</p>
                <p>{crypto.message}</p>
              </>
            )}
          </>
        )}
        {scan.kind === "ready" && !scan.project.manifest && (
          <p className="bad">Ingestion finished without a manifest.</p>
        )}
      </section>
      <section className="status connection" aria-live="polite">
        {connection.kind === "loading" && <p>Checking API connection…</p>}
        {connection.kind === "connected" && (
          <>
            <p className="ok">CryptoNex API Connected</p>
            <p className="meta">Service: {connection.service}</p>
          </>
        )}
        {connection.kind === "error" && (
          <>
            <p className="bad">Backend unavailable</p>
            <p>{connection.message}</p>
            <button type="button" onClick={checkConnection}>
              Check again
            </button>
          </>
        )}
      </section>
    </main>
  )
}

function AlgorithmCounts({ algorithms }: { algorithms: Record<string, number> }) {
  const entries = Object.entries(algorithms)
  if (entries.length === 0) {
    return <p className="meta">No algorithms detected</p>
  }
  return (
    <ul className="algorithms">
      {entries.map(([name, count]) => (
        <li key={name}>
          {name}: {count}
        </li>
      ))}
    </ul>
  )
}

function formatFileCount(count: number): string {
  return `${count} ${count === 1 ? "file" : "files"}`
}

function formatLanguages(languages: Record<string, number>): string {
  const entries = Object.entries(languages)
  if (entries.length === 0) {
    return "No source languages detected"
  }
  return entries.map(([language, count]) => `${language} ${count}`).join(", ")
}

export default App
