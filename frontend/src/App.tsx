import { useCallback, useEffect, useState } from "react"
import { getHealth } from "./api/health"
import "./App.css"

type ConnectionState =
  | { kind: "loading" }
  | { kind: "connected"; service: string }
  | { kind: "error"; message: string }

function App() {
  const [connection, setConnection] = useState<ConnectionState>({ kind: "loading" })

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

  return (
    <main className="shell">
      <p className="phase">Phase 0 — Foundation</p>
      <h1>CryptoNex</h1>
      <p className="lede">API connection status for the local CryptoNex backend.</p>
      <section className="status" aria-live="polite">
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

export default App
