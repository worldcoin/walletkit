# Rust resolves these classes and members by name in JNI_OnLoad and in the JNI exports.
-keep class org.world.walletkit.NativeBridge { *; }
-keep class org.world.walletkit.NativeHandle { long id; }
-keep interface org.world.walletkit.DeviceKeystore { *; }
-keep interface org.world.walletkit.AtomicBlobStore { *; }
-keep interface org.world.walletkit.Logger { *; }
-keep interface org.world.walletkit.VaultChangedListener { *; }
-keep interface org.world.walletkit.ActivityChangedListener { *; }
-keep interface org.world.walletkit.RequestIntegrityProvider { *; }
-keep interface org.world.walletkit.RequestDigestSigner { *; }
