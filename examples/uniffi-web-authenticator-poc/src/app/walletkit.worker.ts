import type {
  AuthenticatorLike,
  CredentialStoreLike,
  InitializingAuthenticatorLike,
  WalletKit,
} from "walletkit-web";

import { createStagingProofRequest, issueFauxCredential } from "./staging";

type Action = "derive" | "register" | "initialize" | "issue" | "prove";

type WorkerState = {
  runtime?: string;
  recovery?: {
    authenticatorAddress: string;
    authenticatorPubkey: string;
    offchainSignerCommitment: string;
  };
  registered?: boolean;
  authenticatorReady?: boolean;
  credentialIssued?: boolean;
  busy?: boolean;
  status?: string;
};

let bindings: WalletKit;
let seed = new Uint8Array(32);
let registration: InitializingAuthenticatorLike | undefined;
let authenticator: AuthenticatorLike | undefined;
let store: CredentialStoreLike | undefined;

const REGISTRATION_POLL_INTERVAL_MS = 500;

function wait(milliseconds: number) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function printableState(state: string, details = {}) {
  return JSON.stringify(
    {
      state,
      environment: "staging",
      region: "us",
      ...details,
    },
    (_, value) => (typeof value === "bigint" ? value.toString() : value),
    2,
  );
}

function printableError(error: unknown) {
  if (error instanceof Error && "inner" in error) {
    return `${error.message}: ${JSON.stringify(error.inner)}`;
  }

  return String(error);
}

function update(state: WorkerState) {
  self.postMessage(state);
}

function deriveAuthenticator() {
  seed = crypto.getRandomValues(new Uint8Array(32));
  const recovery = bindings.recoveryDataFromSeed(new Uint8Array(seed).buffer);
  registration = undefined;
  authenticator = undefined;
  store = undefined;
  update({
    recovery: {
      authenticatorAddress: recovery.authenticatorAddress,
      authenticatorPubkey: recovery.authenticatorPubkey,
      offchainSignerCommitment: recovery.offchainSignerCommitment,
    },
    registered: false,
    authenticatorReady: false,
    credentialIssued: false,
    status: printableState("authenticator-derived", {
      seed: "32 random bytes held only in memory",
    }),
  });
}

async function perform(action: Action) {
  update({ busy: true });
  try {
    switch (action) {
      case "derive":
        deriveAuthenticator();
        break;
      case "register":
        update({ status: "Sending registration request to the staging gateway…" });
        registration =
          await bindings.InitializingAuthenticator.registerWithDefaults(
            new Uint8Array(seed).buffer,
            undefined,
            bindings.Environment.Staging,
            bindings.Region.Us,
            undefined,
          );
        update({ status: printableState("registration-requested") });
        while (registration) {
          const result = await registration.pollStatus();
          const finalized =
            bindings.RegistrationStatus.Finalized.instanceOf(result);
          update({
            registered: finalized,
            status: printableState(
              finalized ? "registration-finalized" : "registration-pending",
              { status: result.constructor.name },
            ),
          });
          if (finalized) break;
          await wait(REGISTRATION_POLL_INTERVAL_MS);
        }
        break;
      case "initialize": {
        update({
          status: "Initializing the registered authenticator and ephemeral store…",
        });
        const ephemeralStore = bindings.CredentialStore.newEphemeral();
        const artifacts = new bindings.EmbeddedZkArtifacts().asZkArtifactSource();
        const initializedAuthenticator =
          await bindings.Authenticator.initWithDefaults(
            new Uint8Array(seed).buffer,
            undefined,
            bindings.Environment.Staging,
            bindings.Region.Us,
            artifacts,
            ephemeralStore,
          );
        initializedAuthenticator.initStorage(
          BigInt(Math.floor(Date.now() / 1000)),
        );
        store = ephemeralStore;
        authenticator = initializedAuthenticator;
        update({
          authenticatorReady: true,
          status: printableState("authenticator-initialized"),
        });
        break;
      }
      case "issue": {
        if (!authenticator || !store) return;
        update({ status: "Requesting a credential from the staging faux issuer…" });
        const issued = await issueFauxCredential(bindings, authenticator, store);
        update({
          credentialIssued: true,
          status: printableState("credential-issued", issued),
        });
        break;
      }
      case "prove": {
        if (!authenticator) return;
        update({ status: "Generating a uniqueness proof in browser WASM…" });
        const request = await createStagingProofRequest(
          bindings,
          "walletkit-web-example",
        );
        const response = await authenticator.generateProof(
          request,
          BigInt(Math.floor(Date.now() / 1000)),
        );
        update({ status: response.toJson() });
        break;
      }
    }
  } catch (error) {
    update({ status: printableError(error) });
  } finally {
    update({ busy: false });
  }
}

self.onmessage = (event: MessageEvent<Action>) => {
  void perform(event.data);
};

void (async () => {
  try {
    const { initializeWalletKit } = await import("walletkit-web");
    bindings = await initializeWalletKit();
    update({ runtime: "Ready" });
    deriveAuthenticator();
  } catch (error) {
    update({ runtime: "Failed", status: printableError(error) });
  }
})();
