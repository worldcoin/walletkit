"use client";

import { useEffect, useRef, useState } from "react";

import type { RecoveryData } from "walletkit-web";

type Action = "derive" | "register" | "initialize" | "issue" | "prove";

type WorkerState = {
  runtime?: string;
  recovery?: RecoveryData;
  registered?: boolean;
  authenticatorReady?: boolean;
  credentialIssued?: boolean;
  busy?: boolean;
  status?: string;
};

export default function Home() {
  const worker = useRef<Worker>(null);
  const [runtime, setRuntime] = useState("Loading…");
  const [recovery, setRecovery] = useState<RecoveryData>();
  const [registered, setRegistered] = useState(false);
  const [authenticatorReady, setAuthenticatorReady] = useState(false);
  const [credentialIssued, setCredentialIssued] = useState(false);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("Initializing generated bindings…");

  useEffect(() => {
    const walletKitWorker = new Worker(
      new URL("./walletkit.worker.ts", import.meta.url),
      { type: "module" },
    );
    worker.current = walletKitWorker;
    walletKitWorker.onmessage = (event: MessageEvent<WorkerState>) => {
      const state = event.data;
      if (state.runtime !== undefined) setRuntime(state.runtime);
      if (state.recovery !== undefined) setRecovery(state.recovery);
      if (state.registered !== undefined) setRegistered(state.registered);
      if (state.authenticatorReady !== undefined) {
        setAuthenticatorReady(state.authenticatorReady);
      }
      if (state.credentialIssued !== undefined) {
        setCredentialIssued(state.credentialIssued);
      }
      if (state.busy !== undefined) setBusy(state.busy);
      if (state.status !== undefined) setStatus(state.status);
    };

    return () => {
      worker.current = null;
      walletKitWorker.terminate();
    };
  }, []);

  function perform(action: Action) {
    worker.current?.postMessage(action);
  }

  return (
    <main>
      <div className="card-grid">
        <section className="card">
          <p className="eyebrow">WalletKit web package integration probe</p>
          <h1>WalletKit credential proof in browser WASM</h1>
          <p>
            Derive and register a temporary staging authenticator, issue a faux
            credential, then generate a proof for it entirely in the browser.
          </p>
          <dl>
            <div>
              <dt>WASM runtime</dt>
              <dd>{runtime}</dd>
            </div>
            <div>
              <dt>Authenticator address</dt>
              <dd>{recovery?.authenticatorAddress ?? "—"}</dd>
            </div>
            <div>
              <dt>Authenticator public key</dt>
              <dd>{recovery?.authenticatorPubkey ?? "—"}</dd>
            </div>
            <div>
              <dt>Signer commitment</dt>
              <dd>{recovery?.offchainSignerCommitment ?? "—"}</dd>
            </div>
          </dl>
          <button
            disabled={runtime !== "Ready" || busy}
            onClick={() => perform("derive")}
          >
            Derive another authenticator
          </button>
        </section>

        <section className="card actions-card">
          <h2>Staging credential proof</h2>
          <p>
            This creates a real temporary account and credential in staging. The
            seed and credential store are discarded when this tab reloads.
          </p>
          <ol>
            <li>
              <button
                disabled={busy || registered}
                onClick={() => perform("register")}
              >
                Register authenticator
              </button>
            </li>
            <li>
              <button
                disabled={!registered || busy || authenticatorReady}
                onClick={() => perform("initialize")}
              >
                Initialize authenticator
              </button>
            </li>
            <li>
              <button
                disabled={!authenticatorReady || busy || credentialIssued}
                onClick={() => perform("issue")}
              >
                Issue faux credential
              </button>
            </li>
            <li>
              <button
                disabled={!credentialIssued || busy}
                onClick={() => perform("prove")}
              >
                Generate proof
              </button>
            </li>
          </ol>
          <h3>Action output</h3>
          <pre className="action-output">{status}</pre>
        </section>
      </div>
      <div
        className={`progress-track${busy ? " is-active" : ""}`}
        role="progressbar"
        aria-label="WalletKit action progress"
        aria-busy={busy}
      >
        <span />
      </div>
    </main>
  );
}
