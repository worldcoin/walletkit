# rustls-platform-verifier requires its Android helper classes at runtime.
# https://github.com/rustls/rustls-platform-verifier#android
-keep, includedescriptorclasses class org.rustls.platformverifier.** { *; }
