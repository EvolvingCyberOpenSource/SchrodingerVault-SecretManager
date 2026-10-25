# Install the Mac preview

This guide is for a packaged preview, not the source-code ZIP. Check the release notes before installing: a draft with notarization or launch testing still pending is not a verified end-user release.

You do not need Terminal, Node.js, Rust, or a weather API key to use a verified packaged app.

## 1. Download the correct file

1. Visit the project's [Releases page](https://github.com/EvolvingCyberOpenSource/SchrodingerVault-SecretManager/releases). While the repository is private, sign in with a GitHub account that has access.
2. Open the release marked as the Mac preview and read its status and limitations.
3. Under **Assets**, download the file ending in **`.dmg`**. A universal Mac package contains both Intel and Apple Silicon code; check the release notes for which machines have actually been tested.
4. Do not select **Source code (zip)** or **Source code (tar.gz)** for installation. Those downloads are for building the app yourself.

## 2. Install

1. If you are running a development copy of this secret manager, lock it and quit it first. Do not run two copies simultaneously.
2. Open **Downloads** in Finder and double-click the downloaded `.dmg` file.
3. Drag **Schrodinger Secrets Dev** onto the **Applications** shortcut in the installer window.
4. If Finder asks to replace an existing application, stop unless you intentionally want to update that same application. Do not replace a different vault application.
5. Wait for the copy to finish. Eject the installer disk using Finder's eject button.
6. Open **Applications**, then double-click **Schrodinger Secrets Dev**.

The “Dev” name and “Test secrets only” label are intentional for this research preview. They do not mean you need developer tools to run the installed app.

If macOS reports that the developer cannot be verified, that the app is damaged, or that it may contain malware, stop and report the exact message. Do not disable Gatekeeper, remove quarantine flags, or follow a bypass command. The release needs investigation.

## 3. Try it with a fake secret

1. On a new installation, create a unique master password. If this Mac already has a development vault, unlock that existing vault instead of resetting it.
2. Follow [Create or unlock your vault](GETTING_STARTED.md#4-create-or-unlock-your-vault).
3. Save `DEMO_API_TOKEN` with the fake value `dummy-token-for-testing-only` in namespace `demo-app`.
4. Select **Lock Vault**, unlock again, and confirm that the test record remains available.

The illustrated [Getting Started guide](GETTING_STARTED.md) explains the remaining controls and how application approval works. Skip its build-tool and source-installation steps when using a verified packaged app.

## Important data and security limits

- The package uses the existing development identifier `com.evolvingcyber.svdev`. It shares data with source builds using that identifier. It does not automatically migrate data from another product.
- Do not delete files from `~/Library/Application Support/com.evolvingcyber.svdev/`. Losing the device key material or master password can make records inaccessible. There is no account-recovery service.
- Start with synthetic secrets. This prototype has not completed an independent security audit.
- Signing identifies the distributor and notarization is Apple's distribution check. Neither is a security audit of the vault's cryptographic design.
- Approving a client allows it to receive plaintext secrets from its assigned namespace while the vault is unlocked. Locking cannot erase copies already delivered.

## What to send when asking for help

Provide the release name, your macOS version, whether your Mac uses Intel or Apple Silicon, and the error message. Do not include your master password, API keys, private client identity, or vault files. Keep secret values hidden in screenshots.
