import type {
  PoseGuardImages,
  PoseGuardPrompt,
  SelfieEnrollmentResult,
} from "../../src/generated/walletkit.js";

let started = 0;
let submitted = 0;

export default function init() {}
export function initializePersistentStorage() {}

export function poseGuardTestCounts() {
  return { started, submitted };
}

export async function runPoseGuardEnrollment(
  scenario: string,
  _sub: string,
  key: Uint8Array,
  capture: (prompt: PoseGuardPrompt) => Promise<PoseGuardImages>,
  signal: AbortSignal,
): Promise<SelfieEnrollmentResult> {
  started++;
  if (key.length !== 32) throw new TypeError("Invalid key");
  let timer: ReturnType<typeof setTimeout> | undefined;
  let onAbort!: () => void;
  const interrupted = new Promise<never>((_, reject) => {
    onAbort = () => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
    if (scenario === "timeout") {
      const timeout = Object.assign(new Error("Capture expired"), {
        name: "SelfieEnrollmentError",
        code: "Timeout",
      });
      timer = setTimeout(() => reject(timeout), 150);
    }
  });
  try {
    const images = await Promise.race([
      capture({
        targets: [
          { targetPitch: 0, targetYaw: -31 },
          { targetPitch: -17, targetYaw: 0 },
          { targetPitch: 0, targetYaw: 34 },
        ],
        expiresAt: 1_800_000_000,
        captureTimeoutMs: scenario === "timeout" ? 150 : 41_000,
      }),
      interrupted,
    ]);
    submitted++;
    if (
      images.centralPng.length !== 8 ||
      images.captures.some(
        (image, index) => image.length !== 1 || image[0] !== index + 1,
      )
    ) {
      throw new Error("Unexpected capture buffers or order");
    }
    if (scenario === "challenge") {
      return {
        status: "failed",
        reason: "challenge",
        index: 1,
        challengeReason: "pose_mismatch",
      };
    }
    return {
      status: "success",
      enrollment: {
        fields: [],
        attestationHeader: "test",
        encryptedCustody: new Uint8Array([1, 2, 3]),
      },
    };
  } finally {
    signal.removeEventListener("abort", onAbort);
    clearTimeout(timer);
  }
}
