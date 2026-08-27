"use client";

import { useEffect, useRef, useState } from "react";

import type {
  AuthenticatorLike,
  CredentialStoreLike,
  InitializingAuthenticatorLike,
  RecoveryData,
  WalletKit,
} from "@worldcoin/walletkit-web";

import { createStagingProofRequest, issueFauxCredential } from "./staging";

function printableState(state: string, details = {}) {
  return JSON.stringify(
    {
      state,
      environment: "staging",
      region: "eu",
      ...details,
    },
    (_, value) => (typeof value === "bigint" ? value.toString() : value),
    2,
  );
}

export default function Home() {
  const bindings = useRef<WalletKit>(null);
  const seed = useRef(new Uint8Array(32));
  const registration = useRef<InitializingAuthenticatorLike>(undefined);
  const authenticator = useRef<AuthenticatorLike>(undefined);
  const store = useRef<CredentialStoreLike>(undefined);
  const initialized = useRef(false);
  const [runtime, setRuntime] = useState("Loading…");
  const [recovery, setRecovery] = useState<RecoveryData>();
  const [confirmed, setConfirmed] = useState(false);
  const [registered, setRegistered] = useState(false);
  const [authenticatorReady, setAuthenticatorReady] = useState(false);
  const [credentialIssued, setCredentialIssued] = useState(false);
  const [busy, setBusy] = useState(false);
  const [canPoll, setCanPoll] = useState(false);
  const [status, setStatus] = useState("Initializing generated bindings…");

  function deriveAuthenticator(module = bindings.current) {
    if (!module) return;
    seed.current = crypto.getRandomValues(new Uint8Array(32));
    setRecovery(
      module.recoveryDataFromSeed(new Uint8Array(seed.current).buffer),
    );
    registration.current = undefined;
    authenticator.current = undefined;
    store.current = undefined;
    setCanPoll(false);
    setRegistered(false);
    setAuthenticatorReady(false);
    setCredentialIssued(false);
    setStatus(
      printableState("authenticator-derived", {
        seed: "32 random bytes held only in memory",
      }),
    );
  }

  useEffect(() => {
    if (initialized.current) return;
    initialized.current = true;

    void (async () => {
      try {
        const { initializeWalletKit } = await import(
          "@worldcoin/walletkit-web"
        );
        const module = await initializeWalletKit();
        bindings.current = module;
        setRuntime("Ready");
        deriveAuthenticator(module);
      } catch (error) {
        setRuntime("Failed");
        setStatus(String(error));
      }
    })();
  }, []);

  async function registerAuthenticator() {
    const module = bindings.current;
    if (!module) return;
    setBusy(true);
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
      setStatus(printableState("registration-requested"));
    } catch (error) {
      setStatus(String(error));
    } finally {
      setBusy(false);
    }
  }

  async function pollRegistration() {
    const module = bindings.current;
    if (!module || !registration.current) return;
    setBusy(true);
    try {
      const result = await registration.current.pollStatus();
      const finalized = module.RegistrationStatus.Finalized.instanceOf(result);
      setRegistered(finalized);
      setCanPoll(!finalized);
      setStatus(
        printableState(
          finalized ? "registration-finalized" : "registration-pending",
          { status: result.constructor.name },
        ),
      );
    } catch (error) {
      setStatus(String(error));
    } finally {
      setBusy(false);
    }
  }

  async function initializeRegisteredAuthenticator() {
    const module = bindings.current;
    if (!module) return;
    setBusy(true);
    setStatus("Initializing the registered authenticator and ephemeral store…");
    try {
      const ephemeralStore = module.CredentialStore.newEphemeral();
      const artifacts = new module.EmbeddedZkArtifacts().asZkArtifactSource();
      const initializedAuthenticator =
        await module.Authenticator.initWithDefaults(
          new Uint8Array(seed.current).buffer,
          undefined,
          module.Environment.Staging,
          module.Region.Eu,
          artifacts,
          ephemeralStore,
        );
      initializedAuthenticator.initStorage(
        BigInt(Math.floor(Date.now() / 1000)),
      );
      store.current = ephemeralStore;
      authenticator.current = initializedAuthenticator;
      setAuthenticatorReady(true);
      setStatus(printableState("authenticator-initialized"));
    } catch (error) {
      setStatus(String(error));
    } finally {
      setBusy(false);
    }
  }

  async function issueCredential() {
    const module = bindings.current;
    if (!module || !authenticator.current || !store.current) return;
    setBusy(true);
    setStatus("Requesting a credential from the staging faux issuer…");
    try {
      const issued = await issueFauxCredential(
        module,
        authenticator.current,
        store.current,
      );
      setCredentialIssued(true);
      setStatus(printableState("credential-issued", issued));
    } catch (error) {
      setStatus(String(error));
    } finally {
      setBusy(false);
    }
  }

  async function generateProof() {
    const module = bindings.current;
    if (!module || !authenticator.current) return;
    setBusy(true);
    setStatus("Generating a uniqueness proof in browser WASM…");
    try {
      const request = await createStagingProofRequest(
        module,
        "walletkit-web-example",
      );
      const response = await authenticator.current.generateProof(
        request,
        BigInt(Math.floor(Date.now() / 1000)),
      );
      setStatus(response.toJson());
    } catch (error) {
      setStatus(String(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main>
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
          onClick={() => deriveAuthenticator()}
        >
          Derive another authenticator
        </button>
        <details open>
          <summary>Staging credential proof</summary>
          <p>
            This creates a real temporary account and credential in staging. The
            seed and credential store are discarded when this tab reloads.
          </p>
          <label>
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(event) => setConfirmed(event.target.checked)}
            />{" "}
            I understand this mutates staging state.
          </label>
          <ol>
            <li>
              <button
                disabled={!confirmed || busy || canPoll || registered}
                onClick={registerAuthenticator}
              >
                Register authenticator
              </button>
              <button disabled={!canPoll || busy} onClick={pollRegistration}>
                Poll registration
              </button>
            </li>
            <li>
              <button
                disabled={!registered || busy || authenticatorReady}
                onClick={initializeRegisteredAuthenticator}
              >
                Initialize authenticator
              </button>
            </li>
            <li>
              <button
                disabled={!authenticatorReady || busy || credentialIssued}
                onClick={issueCredential}
              >
                Issue faux credential
              </button>
            </li>
            <li>
              <button
                disabled={!credentialIssued || busy}
                onClick={generateProof}
              >
                Generate proof
              </button>
            </li>
          </ol>
        </details>
        <pre>{status}</pre>
      </section>
    </main>
  );
}
