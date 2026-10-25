# Schrödinger’s Vault: application source

This folder contains the desktop secret-manager application.

- [Project overview](../README.md)
- [Illustrated beginner setup guide](../docs/GETTING_STARTED.md)
- [Application integration and protocol](docs/LOCAL_IPC.md)
- [Security policy](SECURITY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Packaging notes](PACKAGING.md)

After installing the prerequisites in the setup guide, run these commands from this folder:

```sh
npm ci
npm run dev
```

This is a macOS research prototype. Use test secrets. No verified installer for this secret-manager snapshot is provided by these instructions, and no independent security audit or FIPS validation is claimed.
