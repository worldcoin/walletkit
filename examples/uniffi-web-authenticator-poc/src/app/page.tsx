"use client";

import { useEffect, useRef, useState } from "react";

import type { InitializingAuthenticatorLike, RecoveryData } from "../generated";

type WalletKitBindings = typeof import("../generated");

const WASM_URL = "/wasm/walletkit_web_authenticator_poc.wasm";

function printableState(state: string) {
  return JSON.stringify(
    {
      state,
      environment: "staging",
      region: "eu",
      seed: "32 random bytes held only in memory",
    },
    null,
    2,
  );
}

export default function Home() {
  const bindings = useRef<WalletKitBindings>(null);
  const seed = useRef(new Uint8Array(32));
  const registration = useRef<InitializingAuthenticatorLike>(undefined);
  const initialized = useRef(false);
  const [runtime, setRuntime] = useState("Loading…");
  const [asyncBridge, setAsyncBridge] = useState("Pending…");
  const [recovery, setRecovery] = useState<RecoveryData>();
  const [confirmed, setConfirmed] = useState(false);
  const [registering, setRegistering] = useState(false);
  const [canPoll, setCanPoll] = useState(false);
  const [status, setStatus] = useState("Initializing generated bindings…");

  function deriveAuthenticator(module = bindings.current) {
    if (!module) return;
    seed.current = crypto.getRandomValues(new Uint8Array(32));
    setRecovery(
      module.recoveryDataFromSeed(new Uint8Array(seed.current).buffer),
    );
    registration.current = undefined;
    setCanPoll(false);
    setStatus(printableState("authenticator-derived"));
  }

  useEffect(() => {
    if (initialized.current) return;
    initialized.current = true;

    void (async () => {
      try {
        const module = await import("../generated");
        bindings.current = module;
        await module.uniffiInitAsync(WASM_URL);
        setRuntime("Ready");
        deriveAuthenticator(module);

        try {
          await module.InitializingAuthenticator.register(
            new Uint8Array(seed.current).buffer,
            "invalid config used only to exercise async error lifting",
            undefined,
          );
          setAsyncBridge("Unexpected success");
        } catch {
          setAsyncBridge("Ready (Rust rejected the invalid config)");
        }
      } catch (error) {
        setRuntime("Failed");
        setStatus(String(error));
      }
    })();
  }, []);

  async function registerAuthenticator() {
    const module = bindings.current;
    if (!module) return;
    setRegistering(true);
    setStatus("Sending registration request to the staging gateway…");
    try {
      registration.current =
        await module.InitializingAuthenticator.registerWithDefaults(
          new Uint8Array(seed.current).buffer,
          undefined,
          module.Environment.Staging,
          module.Region.Eu,
          undefined,
        );
      setCanPoll(true);
      setStatus(JSON.stringify({ state: "registration-requested" }, null, 2));
    } catch (error) {
      setStatus(String(error));
    } finally {
      setRegistering(false);
    }
  }

  async function pollRegistration() {
    if (!registration.current) return;
    setCanPoll(false);
    try {
      const result = await registration.current.pollStatus();
      setStatus(
        JSON.stringify({ state: "registration-polled", result }, null, 2),
      );
    } catch (error) {
      setStatus(String(error));
    } finally {
      setCanPoll(true);
    }
  }

  return (
    <main>
      <section className="card">
        <p className="eyebrow">Throwaway Next.js feasibility probe</p>
        <h1>WalletKit authenticator in browser WASM</h1>
        <p>
          This Client Component loads WalletKit&apos;s real UniFFI surface
          through the generator&apos;s WASM player and derives fresh
          authenticator material entirely inside the browser.
        </p>
        <dl>
          <div>
            <dt>WASM runtime</dt>
            <dd>{runtime}</dd>
          </div>
          <div>
            <dt>Async UniFFI bridge</dt>
            <dd>{asyncBridge}</dd>
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
          disabled={runtime !== "Ready"}
          onClick={() => deriveAuthenticator()}
        >
          Derive another authenticator
        </button>
        <details>
          <summary>Optional network proof: register on staging</summary>
          <p>
            This sends a real account-registration request to WalletKit&apos;s
            staging gateway. The seed remains in this tab and is discarded on
            refresh.
          </p>
          <label>
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(event) => setConfirmed(event.target.checked)}
            />{" "}
            I understand this mutates staging state.
          </label>
          <div>
            <button
              disabled={!confirmed || registering}
              onClick={registerAuthenticator}
            >
              Register this authenticator
            </button>
            <button disabled={!canPoll} onClick={pollRegistration}>
              Poll registration status
            </button>
          </div>
        </details>
        <pre>{status}</pre>
      </section>
    </main>
  );
}
