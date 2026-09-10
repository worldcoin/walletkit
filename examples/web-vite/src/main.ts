import "./style.css";

import {
  initializeWalletKit,
  type RecoveryData,
  type WalletKit,
} from "walletkit-web";

const PROFILE_KEY = "walletkit-vite-example-v1";

interface DemoProfile {
  version: 1;
  storageId: string;
  databaseKey: number[];
}

const runtime = element("runtime");
const address = element("address");
const publicKey = element("public-key");
const commitment = element("commitment");
const status = element("status");
const derive = element<HTMLButtonElement>("derive");

let wallet: WalletKit | undefined;
const controller = new AbortController();

void start();

derive.addEventListener("click", () => void deriveRecoveryData());
window.addEventListener(
  "pagehide",
  (event) => {
    if (event.persisted) return;
    controller.abort();
    wallet?.terminate();
  },
  { once: true },
);

async function start() {
  let databaseKey: Uint8Array | undefined;
  try {
    const profile = loadOrCreateProfile();
    databaseKey = new Uint8Array(profile.databaseKey);
    wallet = await initializeWalletKit({
      databaseKey,
      storageId: profile.storageId,
      signal: controller.signal,
    });
    runtime.textContent = "Ready";
    status.textContent = "WalletKit is ready in its dedicated worker.";
    derive.disabled = false;
  } catch (error) {
    runtime.textContent = "Failed";
    status.textContent = String(error);
  } finally {
    databaseKey?.fill(0);
  }
}

async function deriveRecoveryData() {
  if (!wallet) return;
  derive.disabled = true;
  status.textContent = "Deriving recovery data…";
  const seed = crypto.getRandomValues(new Uint8Array(32));
  try {
    renderRecoveryData(await wallet.recoveryDataFromSeed(seed));
    status.textContent = "Recovery data derived from a fresh random seed.";
  } catch (error) {
    status.textContent = String(error);
  } finally {
    seed.fill(0);
    derive.disabled = false;
  }
}

function renderRecoveryData(recovery: RecoveryData) {
  address.textContent = recovery.authenticatorAddress;
  publicKey.textContent = recovery.authenticatorPubkey;
  commitment.textContent = recovery.offchainSignerCommitment;
}

function loadOrCreateProfile(): DemoProfile {
  const saved = localStorage.getItem(PROFILE_KEY);
  if (saved !== null) {
    const profile = JSON.parse(saved) as Partial<DemoProfile> | null;
    if (
      profile?.version !== 1 ||
      typeof profile.storageId !== "string" ||
      !isDatabaseKey(profile.databaseKey)
    ) {
      throw new Error(
        "The saved Vite example profile is invalid. Clear this site's data to start over.",
      );
    }
    return profile as DemoProfile;
  }

  const profile: DemoProfile = {
    version: 1,
    storageId: `vite-${crypto.randomUUID()}`,
    databaseKey: Array.from(crypto.getRandomValues(new Uint8Array(32))),
  };
  localStorage.setItem(PROFILE_KEY, JSON.stringify(profile));
  return profile;
}

function isDatabaseKey(value: unknown): value is number[] {
  return (
    Array.isArray(value) &&
    value.length === 32 &&
    value.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255)
  );
}

function element<ElementType extends HTMLElement = HTMLElement>(
  id: string,
): ElementType {
  const found = document.querySelector<ElementType>(`#${id}`);
  if (!found) throw new Error(`Missing #${id}`);
  return found;
}
