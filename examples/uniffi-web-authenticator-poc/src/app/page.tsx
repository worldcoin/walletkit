"use client";

import { useEffect, useRef, useState } from "react";

import type { RecoveryData, WalletKit } from "walletkit-web";
import {
  loadDemoProfile,
  saveDemoProfile,
  type DemoProfile,
} from "./demo-profile";
import { createStagingProofRequest, issueFauxCredential } from "./staging";

type Action = "derive" | "register" | "initialize" | "issue" | "prove";

export default function Home() {
  const wallet = useRef<WalletKit | null>(null);
  const seed = useRef(new Uint8Array(32));
  const profile = useRef<DemoProfile | null>(null);
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
    let databaseKey: Uint8Array | undefined;
    let client: WalletKit | undefined;
    const currentSeed = new Uint8Array(32);
    void (async () => {
      try {
        const saved = loadDemoProfile();
        profile.current = saved;
        databaseKey = new Uint8Array(saved.databaseKey);
        currentSeed.set(saved.seed);
        seed.current = currentSeed;
        const { initializeWalletKit } = await import("walletkit-web");
        if (controller.signal.aborted) return;
        client = await initializeWalletKit({
          databaseKey,
          storageId: saved.storageId,
          environment: "staging",
          region: "us",
          signal: controller.signal,
        });
        if (controller.signal.aborted) {
          client.terminate();
          return;
        }
        const recovery = await client.recoveryDataFromSeed(currentSeed);
        if (controller.signal.aborted) return;
        wallet.current = client;
        setRecovery(recovery);
        setRegistered(saved.registered);
        setCredentialIssued(saved.credentialIssued);
        setRuntime("Ready");
        setStatus(
          saved.registered
            ? "Saved account loaded. Initialize the authenticator to reopen its stored credentials."
            : "Ready. This demo saves its account and database key in this browser.",
        );
      } catch (error) {
        client?.terminate();
        if (!controller.signal.aborted) {
          setRuntime("Failed");
          setStatus(String(error));
        }
      } finally {
        databaseKey?.fill(0);
      }
    })();
    return () => {
      controller.abort();
      client?.terminate();
      if (wallet.current === client) wallet.current = null;
      currentSeed.fill(0);
    };
  }, []);

  async function perform(action: Action) {
    const client = wallet.current;
    const saved = profile.current;
    if (!client || !saved || acting.current) return;
    acting.current = true;
    setBusy(true);
    try {
      switch (action) {
        case "derive": {
          const nextSeed = crypto.getRandomValues(new Uint8Array(32));
          try {
            const nextRecovery = await client.recoveryDataFromSeed(nextSeed);
            const nextProfile = { ...saved, seed: Array.from(nextSeed) };
            saveDemoProfile(nextProfile);
            profile.current = nextProfile;
            seed.current.set(nextSeed);
            setRecovery(nextRecovery);
          } finally {
            nextSeed.fill(0);
          }
          break;
        }
        case "register": {
          await client.register(seed.current);
          for (;;) {
            const status = await client.pollRegistration();
            setStatus(JSON.stringify(status));
            if (status.state === "failed") throw new Error(status.error);
            if (status.state === "finalized") break;
            await new Promise((resolve) => setTimeout(resolve, 500));
          }
          saved.registered = true;
          saveDemoProfile(saved);
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
          saved.credentialIssued = true;
          saveDemoProfile(saved);
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
            Derive and register a staging authenticator, issue a faux
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
            This creates a real account and credential in staging. The demo
            saves its seed and database key in this browser and reopens the same
            encrypted database after reload. These demo keys are readable by
            scripts on this site; production apps should use a protected key
            source such as a passkey. Use one tab at a time. Clearing site data
            removes the saved account.
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
                disabled={!authenticatorReady || !credentialIssued || busy}
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
