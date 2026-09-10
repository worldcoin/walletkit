/** Demo-only storage: these keys are readable by scripts on this origin. */
const PROFILE_KEY = "walletkit-staging-demo-v1";

export interface DemoProfile {
  version: 1;
  storageId: string;
  seed: number[];
  databaseKey: number[];
  registered: boolean;
  credentialIssued: boolean;
}

function isKey(value: unknown): value is number[] {
  return (
    Array.isArray(value) &&
    value.length === 32 &&
    value.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255)
  );
}

export function saveDemoProfile(profile: DemoProfile): void {
  localStorage.setItem(PROFILE_KEY, JSON.stringify(profile));
}

export function loadDemoProfile(): DemoProfile {
  const saved = localStorage.getItem(PROFILE_KEY);
  if (saved !== null) {
    const profile = JSON.parse(saved) as Partial<DemoProfile> | null;
    if (
      !profile ||
      profile.version !== 1 ||
      typeof profile.storageId !== "string" ||
      !/^demo-[a-z0-9-]+$/.test(profile.storageId) ||
      !isKey(profile.seed) ||
      !isKey(profile.databaseKey) ||
      typeof profile.registered !== "boolean" ||
      typeof profile.credentialIssued !== "boolean" ||
      (profile.credentialIssued && !profile.registered)
    ) {
      throw new Error(
        "The saved demo profile is invalid. Restore it or clear this site's data to start over.",
      );
    }
    return profile as DemoProfile;
  }
  const profile: DemoProfile = {
    version: 1,
    storageId: `demo-${crypto.randomUUID()}`,
    seed: Array.from(crypto.getRandomValues(new Uint8Array(32))),
    databaseKey: Array.from(crypto.getRandomValues(new Uint8Array(32))),
    registered: false,
    credentialIssued: false,
  };
  // Persist before opening OPFS, so a failed write cannot orphan a new vault.
  saveDemoProfile(profile);
  return profile;
}
