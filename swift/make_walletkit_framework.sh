#!/bin/bash
# Assembles one `walletkit_coreFFI.framework` slice from a static library and
# the UniFFI-generated header/modulemap, as a real framework bundle (Info.plist
# + Modules/module.modulemap) rather than a flat headers dir. Clang's implicit
# subdirectory modulemap search — which `xcodebuild -create-xcframework
# -library/-headers` relies on — was disabled on recent SDKs, breaking module
# lookup for consumers. A proper framework module isn't subject to that search.
#
# Meant to be sourced by build_swift.sh, not run directly.

make_walletkit_framework() {
  local framework_dir="$1"
  local static_lib_path="$2"
  local platform="$3"
  local header_path="$4"
  local modulemap_path="$5"

  rm -rf "$framework_dir"
  mkdir -p "$framework_dir/Headers" "$framework_dir/Modules"

  cp "$static_lib_path" "$framework_dir/walletkit_coreFFI"
  cp "$header_path" "$framework_dir/Headers/"

  sed 's/^module /framework module /' "$modulemap_path" > "$framework_dir/Modules/module.modulemap"

  cat > "$framework_dir/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>en</string>
	<key>CFBundleExecutable</key>
	<string>walletkit_coreFFI</string>
	<key>CFBundleIdentifier</key>
	<string>org.worldcoin.walletkit-coreFFI</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>walletkit_coreFFI</string>
	<key>CFBundlePackageType</key>
	<string>FMWK</string>
	<key>CFBundleShortVersionString</key>
	<string>1.0</string>
	<key>CFBundleVersion</key>
	<string>1</string>
	<key>CFBundleSupportedPlatforms</key>
	<array>
		<string>${platform}</string>
	</array>
	<key>MinimumOSVersion</key>
	<string>13.0</string>
</dict>
</plist>
EOF
}
