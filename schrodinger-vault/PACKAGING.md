# Packaging the secret manager

These are maintainer instructions, not evidence that a signed installer has already been released. The current configuration uses the development identity `com.evolvingcyber.svdev` and the product name `Schrodinger Secrets Dev`.

## Build on macOS

Install the [documented prerequisites](../docs/GETTING_STARTED.md#1-install-the-build-tools). From this application folder:

```sh
npm ci
npm run build:mac
```

If both Homebrew Rust and rustup are installed, Tauri's subprocesses may select a compiler without the cross-compilation targets. For a universal build, select the rustup compiler explicitly. The paths below are resolved from your own rustup installation, not a developer's home folder:

```sh
rustup target add aarch64-apple-darwin x86_64-apple-darwin
RUSTC="$(rustup which rustc)" RUSTDOC="$(rustup which rustdoc)" npm run build:mac:universal
```

For distribution signing, supply `APPLE_SIGNING_IDENTITY` with the installed Developer ID Application identity. Keep notarization credentials in Keychain or an appropriate secret store, never in source files.

Tauri places bundles under `src-tauri/target/release/bundle/`. Building a package does not automatically establish a trusted signature or notarization. Do not tell users to disable macOS security protections.

The optional `build:mac:universal` script targets both Apple Silicon and Intel. It requires the corresponding Rust targets and compatible native dependencies, and must be verified on both architectures before claiming support.

Windows and Linux bundle scripts are present, but the secret-manager IPC workflow has not been implemented and validated equivalently on those platforms. A successful package build alone is not proof of working application access.

## Before a public binary release

- Review the development app identity and decide how releases will avoid conflicts with existing vaults.
- Perform a clean-machine build and first-run test on each supported macOS architecture.
- Test create, unlock, save, lock, and approved-client access using disposable test data.
- Verify release-build capabilities and security settings. The current Tauri configuration has a null content security policy; production hardening remains necessary.
- Sign and notarize the release artifact, then verify the downloaded artifact on another Mac.
- Publish version-specific installation instructions, checksums, and release notes.
- Review licensing, dependency notices, security reporting, and included files before making the repository public.

The repository does not contain signing credentials. Do not add them to source control. See [Tauri's macOS signing documentation](https://v2.tauri.app/distribute/sign/macos/) for the release workflow.

The [Mac installation guide](../docs/MAC_INSTALL.md) is for end users once a package's checks are complete. Keep unverified packages in a draft release and record outstanding checks in its notes.
