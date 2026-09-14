"use client";

import { useEffect, useRef, useState } from "react";

import type { RecoveryData, WalletKit } from "walletkit-web";
import { createStagingProofRequest, issueFauxCredential } from "./staging";

type Action = "derive" | "register" | "initialize" | "issue" | "prove";

export default function Home() {
  const wallet = useRef<WalletKit | null>(null);
  const seed = useRef(new Uint8Array(32));
  const acting = useRef(false);
  const [runtime, setRuntime] = useState("Loading…");
  const [recovery, setRecovery] = useState<RecoveryData>();
  const [registered, setRegistered] = useState(false);
  const [authenticatorReady, setAuthenticatorReady] = useState(false);
  const [credentialIssued, setCredentialIssued] = useState(false);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("Initializing generated bindings…");

  useEffect(() => {
    const controller = new AbortController();
    const databaseKey = crypto.getRandomValues(new Uint8Array(32));
    seed.current = crypto.getRandomValues(new Uint8Array(32));
    void (async () => {
      try {
        const { initializeWalletKit } = await import("walletkit-web");
        const client = await initializeWalletKit({
          databaseKey,
          storageId: `demo-${crypto.randomUUID()}`,
          environment: "staging",
          region: "us",
          signal: controller.signal,
        });
        if (controller.signal.aborted) {
          client.terminate();
          return;
        }
        wallet.current = client;
        setRecovery(await client.recoveryDataFromSeed(seed.current));
        setRuntime("Ready");
        setStatus("Ready. This demo keeps its database key only in memory.");
      } catch (error) {
        if (!controller.signal.aborted) {
          setRuntime("Failed");
          setStatus(String(error));
        }
      } finally {
        databaseKey.fill(0);
      }
    })();
    return () => {
      controller.abort();
      wallet.current?.terminate();
      wallet.current = null;
      seed.current.fill(0);
    };
  }, []);

  async function perform(action: Action) {
    const client = wallet.current;
    if (!client || acting.current) return;
    acting.current = true;
    setBusy(true);
    try {
      switch (action) {
        case "derive":
          seed.current.fill(0);
          seed.current = crypto.getRandomValues(new Uint8Array(32));
          setRecovery(await client.recoveryDataFromSeed(seed.current));
          break;
        case "register": {
          await client.register(seed.current);
          for (;;) {
            const status = await client.pollRegistration();
            setStatus(JSON.stringify(status));
            if (status.state === "failed") throw new Error(status.error);
            if (status.state === "finalized") break;
            await new Promise((resolve) => setTimeout(resolve, 500));
          }
          setRegistered(true);
          break;
        }
        case "initialize":
          await client.initializeAuthenticator(seed.current);
          setAuthenticatorReady(true);
          setStatus(
            "Authenticator initialized with the supplied database key and OPFS storage.",
          );
          break;
        case "issue": {
          const issued = await issueFauxCredential(client);
          setStatus(
            JSON.stringify(
              issued,
              (_, value) =>
                typeof value === "bigint" ? value.toString() : value,
              2,
            ),
          );
          setCredentialIssued(true);
          break;
        }
        case "prove":
          setStatus(
            await client.generateProof(
              await createStagingProofRequest("walletkit-web-example"),
            ),
          );
          break;
      }
    } catch (error) {
      setStatus(String(error));
    } finally {
      acting.current = false;
      setBusy(false);
    }
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
            disabled={runtime !== "Ready" || busy || registered}
            onClick={() => perform("derive")}
          >
            Derive another authenticator
          </button>
        </section>

        <section className="card actions-card">
          <h2>Staging credential proof</h2>
          <p>
            This creates a real temporary account and credential in staging. The
            seed and database key are discarded when this tab reloads. Encrypted
            data remains in browser storage; this demo cannot reopen it after
            reload.
          </p>
          <ol>
            <li>
              <button
                disabled={runtime !== "Ready" || busy || registered}
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
