import { expect, test } from "@playwright/test";
import { clearBytes } from "../src/protocol";
import { encode, type Rpc } from "../src/remote";

test("nested capture bytes are copied, transferred and cleared without changing the caller's bytes", () => {
  const rpc: Rpc = { call: async () => undefined, release: () => {} };
  const backing = new Uint8Array([99, 1, 2, 88]);
  const pose = {
    image: backing.subarray(1, 3),
    targetPitch: 10,
    targetYaw: -20,
  };
  const input = [
    new Uint8Array([137, 80]),
    [pose, pose, pose],
    new Uint8Array([7]),
  ];
  const transfer: ArrayBuffer[] = [];
  const encoded = encode(rpc, input, transfer);
  expect(transfer).toHaveLength(5);
  expect(transfer.map((buffer) => buffer.byteLength)).toEqual([2, 2, 2, 2, 1]);

  const received = structuredClone(encoded, { transfer }) as typeof input;
  expect(transfer.every((buffer) => buffer.byteLength === 0)).toBe(true);
  const poses = received[1] as (typeof pose)[];
  expect(poses[0]).toEqual(pose);
  clearBytes(received);
  expect(poses.map((capture) => Array.from(capture.image))).toEqual([
    [0, 0],
    [0, 0],
    [0, 0],
  ]);
  expect(Array.from(received[0] as Uint8Array)).toEqual([0, 0]);
  expect(Array.from(received[2] as Uint8Array)).toEqual([0]);
  expect(Array.from(backing)).toEqual([99, 1, 2, 88]);
  expect(Array.from(input[0] as Uint8Array)).toEqual([137, 80]);
});
