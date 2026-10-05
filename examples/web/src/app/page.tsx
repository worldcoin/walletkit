"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import type {
  Authenticator,
  CredentialStore,
  EmbeddedZkArtifacts,
  InitializingAuthenticator,
  RecoveryData,
  WalletKit,
} from "@worldcoin/walletkit-web";
import {
  loadDemoProfile,
  saveDemoProfile,
  type DemoProfile,
} from "./demo-profile";
import {
  FAUX_ISSUER_SCHEMA_ID,
  createStagingProofRequest,
  issueFauxCredential,
} from "./staging";

type Action = "derive" | "register" | "initialize" | "issue" | "prove";

const ENVIRONMENT = "staging";
const REGION = "us";
const nowSeconds = () => BigInt(Math.floor(Date.now() / 1000));

/**
 * How long each action may take before the demo restarts WalletKit. The worker runs
 * calls in order, so a call that never settles (for example during a staging outage)
 * would otherwise block every later action.
 */
const DEADLINE_MS: Record<Action, number> = {
  derive: 10_000,
  register: 5 * 60_000,
  initialize: 60_000,
  issue: 60_000,
  prove: 2 * 60_000,
};

/** Rust objects the worker keeps for the open account. */
interface Session {
  client: WalletKit;
  store: CredentialStore;
  artifacts: EmbeddedZkArtifacts;
  registration?: InitializingAuthenticator;
  authenticator?: Authenticator;
}

class DeadlineError extends Error {
  override name = "DeadlineError";
}

/** Starts WalletKit and opens the saved account's encrypted storage. */
async function openSession(
  saved: DemoProfile,
  seed: Uint8Array,
  signal: AbortSignal,
): Promise<{ session: Session; recovery: RecoveryData }> {
  const { initializeWalletKit } = await import("@worldcoin/walletkit-web");
  const client = await initializeWalletKit({ signal });
  const databaseKey = new Uint8Array(saved.databaseKey);
  try {
    const keys = await client.StorageKeys.fromBytes(databaseKey);
    const paths = await client.StoragePaths.fromRoot(
      `/walletkit/${saved.storageId}`,
    );
    const store = await client.CredentialStore.new(paths, keys);
    const artifacts = await client.EmbeddedZkArtifacts.new();
    const recovery = await client.recoveryDataFromSeed(seed);
    return { session: { client, store, artifacts }, recovery };
  } catch (error) {
    client.terminate();
    throw error;
  } finally {
    databaseKey.fill(0);
  }
}

/** Whether the store holds an unexpired faux credential. */
async function hasFauxCredential(store: CredentialStore): Promise<boolean> {
  const records = await store.listCredentials(
    FAUX_ISSUER_SCHEMA_ID,
    nowSeconds(),
  );
  return records.some((record) => !record.isExpired);
}

export default function Home() {
  const wallet = useRef<Session | null>(null);
  const seed = useRef(new Uint8Array(32));
  const profile = useRef<DemoProfile | null>(null);
  const opening = useRef<AbortController | null>(null);
  const acting = useRef(false);
  const [runtime, setRuntime] = useState("Loading…");
  const [recovery, setRecovery] = useState<RecoveryData>();
  const [registered, setRegistered] = useState(false);
  const [authenticatorReady, setAuthenticatorReady] = useState(false);
  const [credentialIssued, setCredentialIssued] = useState(false);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("Initializing generated bindings…");

  /** (Re)opens WalletKit for the saved profile, replacing any previous session. */
  const open = useCallback(async (message?: string) => {
    opening.current?.abort();
    const controller = new AbortController();
    opening.current = controller;
    wallet.current?.client.terminate();
    wallet.current = null;
    setRuntime("Loading…");
    setAuthenticatorReady(false);
    setCredentialIssued(false);
    try {
      const saved = profile.current ?? loadDemoProfile();
      profile.current = saved;
      seed.current.set(saved.seed);
      const opened = await openSession(saved, seed.current, controller.signal);
      if (controller.signal.aborted) {
        opened.session.client.terminate();
        return;
      }
      wallet.current = opened.session;
      setRecovery(opened.recovery);
      setRegistered(saved.registered);
      setRuntime("Ready");
      setStatus(
        message ??
          (saved.registered
            ? "Saved account loaded. Initialize the authenticator to reopen its stored credentials."
            : "Ready. This demo saves its account and database key in this browser."),
      );
    } catch (error) {
      if (!controller.signal.aborted) {
        setRuntime("Failed");
        setStatus(String(error));
      }
    }
  }, []);

  useEffect(() => {
    const currentSeed = seed.current;
    void open();
    return () => {
      opening.current?.abort();
      wallet.current?.client.terminate();
      wallet.current = null;
      currentSeed.fill(0);
    };
  }, [open]);

  /**
   * Saves progress that already happened remotely. A failed write must not hide that
   * progress: keep it in memory for this session and say what to do.
   */
  function persist(saved: DemoProfile, what: string): string {
    try {
      saveDemoProfile(saved);
      return "";
    } catch (error) {
      return ` Saving ${what} in this browser failed (${String(error)}); it is kept for this session only.`;
    }
  }

  async function perform(action: Action) {
    const session = wallet.current;
    const saved = profile.current;
    if (!session || !saved || acting.current) return;
    const { client } = session;
    acting.current = true;
    setBusy(true);
    let timer: ReturnType<typeof setTimeout> | undefined;
    // Terminating the worker rejects the pending call, which ends `run` below.
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        client.terminate();
        reject(
          new DeadlineError(
            `${action} did not finish within ${DEADLINE_MS[action] / 1000} s`,
          ),
        );
      }, DEADLINE_MS[action]);
    });
    try {
      await Promise.race([run(action, session, saved), deadline]);
    } catch (error) {
      if (error instanceof DeadlineError) {
        // The worker is gone; reopen the account so the demo stays usable.
        await open(`${error.message}; WalletKit was restarted. Try again.`);
      } else {
        setStatus(String(error));
      }
    } finally {
      clearTimeout(timer);
      acting.current = false;
      setBusy(false);
    }
  }

  async function run(action: Action, session: Session, saved: DemoProfile) {
    const { client } = session;
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
        session.registration =
          await client.InitializingAuthenticator.registerWithDefaults(
            seed.current,
            undefined,
            ENVIRONMENT,
            REGION,
            undefined,
          );
        for (;;) {
          const status = await session.registration.pollStatus();
          setStatus(JSON.stringify(status));
          if (status.state === "failed") throw new Error(status.error);
          if (status.state === "finalized") break;
          await new Promise((resolve) => setTimeout(resolve, 500));
        }
        saved.registered = true;
        setRegistered(true);
        setStatus(
          "Registration finalized. Initialize the authenticator next." +
            persist(saved, "the registration"),
        );
        break;
      }
      case "initialize": {
        // Not gated on the saved `registered` flag: if registration finalized but
        // saving it failed, initializing is how the account is recovered.
        session.authenticator = await client.Authenticator.initWithDefaults(
          seed.current,
          undefined,
          ENVIRONMENT,
          REGION,
          session.artifacts,
          session.store,
        );
        await session.authenticator.initStorage(nowSeconds());
        let saveNote = "";
        if (!saved.registered) {
          saved.registered = true;
          setRegistered(true);
          saveNote = persist(saved, "the registration");
        }
        setAuthenticatorReady(true);
        setCredentialIssued(await hasFauxCredential(session.store));
        setStatus(
          "Authenticator initialized with the supplied database key and OPFS storage." +
            saveNote,
        );
        break;
      }
      case "issue": {
        if (!session.authenticator) {
          throw new Error("Initialize the authenticator first");
        }
        const issued = await issueFauxCredential(
          client,
          session.authenticator,
          session.store,
        );
        setStatus(
          JSON.stringify(
            issued,
            (_, value) =>
              typeof value === "bigint" ? value.toString() : value,
            2,
          ),
        );
        // Derived from storage, so an expired or missing credential can be reissued.
        setCredentialIssued(await hasFauxCredential(session.store));
        break;
      }
      case "prove": {
        if (!session.authenticator) {
          throw new Error("Initialize the authenticator first");
        }
        const request = await client.ProofRequest.fromJson(
          await createStagingProofRequest("walletkit-web-example"),
        );
        try {
          const response = await session.authenticator.generateProof(request);
          try {
            setStatus(await response.toJson());
          } finally {
            response.free();
          }
        } finally {
          request.free();
        }
        break;
      }
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
                disabled={runtime !== "Ready" || busy || authenticatorReady}
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
        {...(busy
          ? { role: "progressbar", "aria-label": "WalletKit action progress" }
          : { "aria-hidden": true })}
      >
        <span />
      </div>
    </main>
  );
}
