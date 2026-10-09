// Compile-only check of the published typings, as a consumer sees them. The page API
// is derived from the generated declarations, so this guards the derivation: class
// statics, instance methods, records and free functions must keep their types, and
// worker internals must stay out of reach.
import type {
  Authenticator,
  CredentialRecord,
  RegistrationStatus,
  SelfieEmbedding,
  SelfieEmbeddingResult,
  WalletKit,
} from "../../dist/index.js";

declare const walletkit: WalletKit;

export async function consumer() {
  const enrollment: SelfieEmbeddingResult =
    await walletkit.extractSelfieEmbedding(
      "{}",
      new Uint8Array(),
      "/api/enrollment-admission",
    );
  if (enrollment.status === "success") {
    const embedding: SelfieEmbedding = enrollment.embedding;
    const digest: string = embedding.worker.executableSha384;
    void digest;
  }
  // @ts-expect-error image bytes must be a Uint8Array
  await walletkit.extractSelfieEmbedding("{}", "image", "/api/admission");
  // @ts-expect-error callbacks cannot cross the worker boundary
  await walletkit.extractSelfieEmbedding("{}", new Uint8Array(), () => ({}));
  // @ts-expect-error the standalone client's callback API must not leak into this facade
  void walletkit.extractEmbedding;
  const now = 1n;
  const keys = await walletkit.StorageKeys.fromBytes(new Uint8Array(32));
  const paths = await walletkit.StoragePaths.fromRoot("/walletkit/account");
  const store = await walletkit.CredentialStore.new(paths, keys);
  const added: bigint = await store.mergeVaultFromBackup(new Uint8Array());
  const artifacts = await walletkit.EmbeddedZkArtifacts.new();
  const authenticator: Authenticator =
    await walletkit.Authenticator.initWithDefaults(
      new Uint8Array(32),
      undefined,
      "staging",
      "eu",
      artifacts,
      store,
    );
  const leafIndex: bigint = await authenticator.leafIndex();
  const records: CredentialRecord[] = await store.listCredentials(
    undefined,
    now,
  );
  const factor = await authenticator.generateCredentialBlindingFactorRemote(1n);
  const factorHex: string = await factor.toHexString();
  const credential = await walletkit.Credential.fromBytes(new Uint8Array());
  const claims = await credential.claims();
  const firstClaim: string = await claims[0].toHexString();
  const fetched = await store.fetchCredential(1n, now);
  const expiresAt: bigint | undefined = await fetched?.expiresAt();
  const credentialId: bigint = await store.storeCredential(
    credential,
    factor,
    1n,
    undefined,
    now,
  );
  const query = await (
    await walletkit.ActivityQuery.new()
  ).withIssuerSchemaId(1n);
  const activity = await store.listActivities(query, 10, 0);
  const registration =
    await walletkit.InitializingAuthenticator.registerWithDefaults(
      new Uint8Array(32),
      undefined,
      "staging",
      "us",
      undefined,
    );
  const status: RegistrationStatus = await registration.pollStatus();
  const request = await walletkit.ProofRequest.fromJson("{}");
  const response = await authenticator.generateProof(request);
  const responseJson: string = await response.toJson();
  const recovery = await walletkit.recoveryDataFromSeed(new Uint8Array(32));
  const address: string = recovery.authenticatorAddress;
  const redacted: string = await walletkit.sanitizeHexSecrets("0x00");
  await walletkit.emitLog("warn", "logging works");
  factor.free();
  const stopped: boolean = walletkit.isStopped();
  await walletkit.close();
  walletkit.terminate();

  // @ts-expect-error not an export of the module
  void walletkit.Authenticator.missing;
  // @ts-expect-error not an `Environment`
  await walletkit.pohRecoveryAgentAddress("moon");
  // @ts-expect-error not a `LogLevel`
  await walletkit.emitLog("loud", "message");
  // @ts-expect-error wasm-bindgen internals are not part of the API
  void walletkit.FieldElement.__wrap;
  // @ts-expect-error the worker runs module setup itself
  void walletkit.initializePersistentStorage;
  // @ts-expect-error `free` is synchronous and not a remote call
  await factor.free().then(() => {});
  // @ts-expect-error records are plain data, not proxies
  recovery.free();

  return {
    added,
    leafIndex,
    records,
    factorHex,
    firstClaim,
    expiresAt,
    credentialId,
    activity,
    status,
    responseJson,
    address,
    redacted,
    stopped,
  };
}
