# Local application interface

The macOS MVP exposes a newline-delimited JSON protocol over an owner-only
Unix domain socket. The socket is created inside the application's data
directory under `ipc/schrodinger-vault.sock`; its parent directory is mode
`0700` and the socket is mode `0600`.

The development app uses `~/Library/Application Support/com.evolvingcyber.svdev/`
on macOS, separate from the installed password manager's database and keystore.
Use dummy secrets during development.

The desktop application must be running and the vault must be unlocked before
a client can register or retrieve a secret. Client access is read-only.

## Registration

1. Generate an independent ML-DSA-65 key pair in the client.
2. Connect to the socket and send one JSON object followed by a newline:

```json
{"type":"register","application_name":"Example App","public_key":"BASE64","namespace":"default"}
```

3. The request appears under **Applications** in the desktop interface. Verify
   the application name, namespace, and SHA-256 public-key fingerprint before
   approval.
4. Approval returns a client identifier in the desktop interface. The client
   must retain this identifier and its private key.

Authorization records are encrypted and authenticated with the active vault
key. Changing the master password or key-derivation mode re-encrypts these
records in the same transaction as the stored secrets.

## Authentication

Send:

```json
{"type":"begin_auth","client_id":"CLIENT_ID"}
```

The server returns a fresh 32-byte Base64 challenge. Sign this canonical byte
sequence with the registered ML-DSA-65 private key:

```text
"SV-CLIENT-AUTH-v1"
|| uint32_be(length(client_id_utf8))
|| client_id_utf8
|| challenge_bytes
```

Then send:

```json
{"type":"authenticate","client_id":"CLIENT_ID","signature":"BASE64"}
```

The challenge is single-use, expires after 30 seconds, and is invalidated by
vault lifecycle changes. A successful authentication creates a five-minute
session bound to that socket connection. Locking the vault, rotating the vault
key, or revoking a client invalidates authenticated sessions and shuts down
existing IPC connections. Revocation conservatively disconnects all clients;
non-revoked clients can reconnect and authenticate again. At most 64 connections
are tracked concurrently.

## Read-only operations

List metadata in the assigned namespace:

```json
{"type":"list_metadata"}
```

Retrieve one secret from the assigned namespace:

```json
{"type":"get_secret","id":1}
```

The IPC protocol has no create, update, delete, registration-approval, or
permission-management operations. Those actions remain desktop-only.

Frames larger than 64 KiB and malformed JSON are rejected. Secret values are
never written to application logs by the IPC server.

## Development client

The repository includes `src-tauri/examples/sv_ipc_client.rs` for manual
end-to-end validation. Run it from `src-tauri`:

```sh
cargo run --example sv_ipc_client -- generate ./demo-client
cargo run --example sv_ipc_client -- register SOCKET "Demo App" default ./demo-client.pk
cargo run --example sv_ipc_client -- list SOCKET CLIENT_ID ./demo-client.sk
cargo run --example sv_ipc_client -- get SOCKET CLIENT_ID ./demo-client.sk RECORD_ID
```

The generated private key is written with mode `0600`. The example client is a
development tool; applications integrating with the vault should protect their
private key using controls appropriate to their platform and threat model.

## Automated validation

Run from the repository root:

```sh
cargo test --manifest-path src-tauri/Cargo.toml --all-targets -- --test-threads=1
cargo test --manifest-path src-tauri/Cargo.toml isolated_client_retrieval_and_revocation -- --ignored --test-threads=1
```

The integration test is opt-in because it changes the test process's global
vault key. It uses in-memory SQLite and a Unix socket pair, not either saved
vault. It checks real ML-DSA authentication, scoped listing/retrieval, namespace
denial, consumed-challenge replay rejection, revocation, and security-state
locking. Separate unit tests check challenge deadlines/generations and socket
shutdown. This does not yet validate desktop approval, filesystem listener
permissions, or end-to-end user-interface behavior.

## Record integrity and lifecycle changes

Newly saved records have an additional AES-256-GCM authentication tag over
length-prefixed name, namespace, type, record ID, nonce, ciphertext, and data
tag. The binding key is derived using HKDF-SHA-256 and a separate context.
Bindings are stored in `record_bindings` and verified before IPC listing or
retrieval. Missing/invalid bindings are excluded from listings and denied on
retrieval. Existing development records are NOT silently re-signed: explicitly
save each record in the desktop editor to enable its IPC access. This does not
provide rollback prevention or protect a compromised host.

IPC requests hold a shared lifecycle gate through response delivery. Locking,
revocation, and key rotation take the exclusive gate. A response already being
written may finish before the lifecycle operation completes; an operation can
wait for the bounded socket write timeout. This is not retroactive removal of
plaintext already delivered or queued in operating-system buffers.

The serialized secret-response buffer is overwritten after successful writes,
partial-write errors, and flush errors, with a zeroizing owner as a fallback.
Tests inspect the still-allocated buffer, not freed memory or kernel buffers.

Prior record-binding run: 29 regular tests passed; the opt-in integration test passed
separately. Added coverage includes altered authorization nonce/ciphertext/tag
and client ID; altered record metadata/ciphertext and missing bindings; new-key
rebinding; buffer clearing; and retrieval concurrent with locking/revocation.
This is bounded regression coverage, not exhaustive concurrency testing.

Live development checks also passed registration/approval/retrieval, lock and
revocation denial, cross-namespace isolation, invalid signatures, consumed and
fresh-connection replay, malformed requests, challenge expiry, five-minute
session expiry, and active-connection closure. These live checks preceded the
record-binding change. A subsequent live rerun with an explicitly re-saved
dummy record and a newly approved client passed authorized list/retrieval,
cross-namespace denial, the protocol audit, manual-lock connection closure,
and revocation connection closure and reauthentication denial. A non-revoked
client authenticated after revocation, confirming the vault remained unlocked.
The expiry checks were not repeated in that round.

## Combined-key password verification

New vaults use verifier format 2: a fixed version-specific plaintext encrypted
with the final vault key, never K1 alone. Unlocking reconstructs that key from
the password and device-held ML-KEM material before checking the verifier.
The manifest includes the version-2 context. Password and KDF changes also
create the combined-key verifier; reset verification recognizes both formats.

Legacy format 1 is accepted only for compatibility. After legacy password and
manifest verification and reconstruction of the device-dependent key, existing
record payloads are authenticated before migration. The verifier and manifest
are replaced in one transaction without changing the record encryption key,
record bindings, or client authorizations. Secure deletion, WAL truncation, and
VACUUM remove the legacy verifier from the active logical database files; a
persistent cleanup marker allows retry if cleanup cannot finish. This does not
guarantee physical erasure on SSDs or remove old backups, snapshots, or copies.

The new verifier regression tests use synthetic data and disposable files;
they do not migrate the user's installed password-manager vault. A live
development-vault migration still requires a successful desktop unlock.

Combined-verifier validation: 35 regular tests passed, zero failed, with the
opt-in IPC integration test passing separately. Six added tests cover combined
password/device verification, tampering and key replacement, version/nonce
rejection, migration rollback, on-disk migration/reopening, and ML-KEM device
key recovery. The on-disk check found no old Base64 verifier ciphertext in the
compacted database; it is not a physical-storage erasure guarantee.
