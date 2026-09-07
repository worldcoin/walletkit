#!/bin/sh
# Host build dependencies must execute on macOS, even during an iOS cross-build.
# Keep the selected Xcode (DEVELOPER_DIR), but remove the target SDK/deployment
# overrides before resolving its native C compiler. Do not disable compiler checks.
unset IPHONEOS_DEPLOYMENT_TARGET SDKROOT
exec xcrun --sdk macosx clang "$@"
