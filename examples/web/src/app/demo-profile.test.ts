import { afterEach, beforeEach, expect, test } from "bun:test";
import { loadDemoProfile, saveDemoProfile } from "./demo-profile";

const original = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
let values: Map<string, string>;
beforeEach(() => {
  values = new Map();
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => values.set(key, value),
    },
  });
});
afterEach(() => {
  if (original) Object.defineProperty(globalThis, "localStorage", original);
  else Reflect.deleteProperty(globalThis, "localStorage");
});

test("reopening retains independent keys, namespace, and completed progress", () => {
  const profile = loadDemoProfile();
  expect(profile.seed).not.toEqual(profile.databaseKey);
  profile.registered = true;
  profile.credentialIssued = true;
  saveDemoProfile(profile);
  expect(loadDemoProfile()).toEqual(profile);
});

test("a malformed key fails without replacing the saved profile", () => {
  const profile = loadDemoProfile();
  profile.databaseKey = [1, 2];
  saveDemoProfile(profile);
  const before = [...values.entries()];
  expect(() => loadDemoProfile()).toThrow("invalid");
  expect([...values.entries()]).toEqual(before);
});

test("an unsupported profile version is never replaced", () => {
  loadDemoProfile();
  const key = [...values.keys()][0];
  values.set(key, '{"version":2}');
  expect(() => loadDemoProfile()).toThrow("invalid");
  expect(values.get(key)).toBe('{"version":2}');
});

test("unavailable browser storage fails instead of starting an ephemeral account", () => {
  localStorage.setItem = () => {
    throw new Error("Quota exceeded");
  };
  expect(() => loadDemoProfile()).toThrow("Quota exceeded");
});
