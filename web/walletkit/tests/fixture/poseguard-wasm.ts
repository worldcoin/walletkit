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

export async function holdPoseGuardTestRpc(channelName: string): Promise<void> {
  const channel = new BroadcastChannel(channelName);
  try {
    await new Promise<void>((resolve) => {
      channel.onmessage = ({ data }) => {
        if (data === "release") resolve();
      };
      channel.postMessage("started");
    });
  } finally {
    channel.close();
  }
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
  signal.throwIfAborted();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    // The worker must settle the capture promise when the attempt is cancelled.
    let pending = capture({
      targets: [
        { targetPitch: 0, targetYaw: -31 },
        { targetPitch: -17, targetYaw: 0 },
        { targetPitch: 0, targetYaw: 34 },
      ],
      expiresAt: 1_800_000_000,
      captureTimeoutMs: scenario === "timeout" ? 150 : 41_000,
    });
    if (scenario === "timeout") {
      const timeout = Object.assign(new Error("Capture expired"), {
        name: "SelfieEnrollmentError",
        code: "Timeout",
      });
      pending = Promise.race([
        pending,
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(timeout), 150);
        }),
      ]);
    }
    const images = await pending;
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
    clearTimeout(timer);
  }
}
