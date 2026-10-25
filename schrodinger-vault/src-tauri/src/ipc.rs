//! Owner-local, read-only IPC for registered applications.
//!
//! The wire format is newline-delimited JSON with a 64 KiB frame limit. A
//! client first requests a fresh challenge, then signs the canonical message
//! produced by `authentication_message` with its ML-DSA-65 private key.

#![cfg(unix)]

use crate::commands;
use crate::state::AppDb;
use crate::vault_core::db;
use aes_gcm::{
    aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD},
    Engine as _,
};
use oqs::sig::{Algorithm as SigAlgorithm, Sig};
use rand::{rng, RngCore};
use rusqlite::{params, OptionalExtension, Transaction};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::Shutdown;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tauri::{command, AppHandle, Manager, State};
use zeroize::{Zeroize, Zeroizing};

const SOCKET_FILE: &str = "schrodinger-vault.sock";
const AUTH_CONTEXT: &[u8] = b"SV-CLIENT-AUTH-v1";
const MAX_FRAME_BYTES: usize = 64 * 1024;
const MAX_PENDING_REGISTRATIONS: usize = 64;
const SESSION_LIFETIME: Duration = Duration::from_secs(5 * 60);
const CHALLENGE_LIFETIME: Duration = Duration::from_secs(30);
const MAX_CONNECTIONS: usize = 64;

#[derive(Default)]
struct Connections(Mutex<HashMap<u64, UnixStream>>);

impl Connections {
    fn register(&self, stream: &UnixStream) -> io::Result<u64> {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let mut connections = self.0.lock().map_err(|_| io::ErrorKind::Other)?;
        if connections.len() >= MAX_CONNECTIONS {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "connection limit",
            ));
        }
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        connections.insert(id, stream.try_clone()?);
        Ok(id)
    }

    fn shutdown_all(&self) {
        let mut connections = self.0.lock().unwrap_or_else(|error| error.into_inner());
        for (_, stream) in connections.drain() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

static CONNECTIONS: OnceLock<Connections> = OnceLock::new();

struct ConnectionGuard(u64);
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Some(connections) = CONNECTIONS.get() {
            if let Ok(mut connections) = connections.0.lock() {
                connections.remove(&self.0);
            }
        }
    }
}

static SESSION_GENERATION: AtomicU64 = AtomicU64::new(1);
// A lifecycle change waits for a currently authorized response to finish;
// once it returns, no request from the old session can begin delivery.
pub(crate) static SECURITY_GATE: RwLock<()> = RwLock::new(());
static ACTIVE_SOCKET_PATH: OnceLock<PathBuf> = OnceLock::new();

#[derive(Clone)]
pub struct IpcState {
    inner: Arc<IpcRuntime>,
}

struct IpcRuntime {
    pending: Mutex<HashMap<String, PendingRegistrationRecord>>,
    socket_path: PathBuf,
}

pub struct IpcServerGuard {
    stop: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
    socket_path: PathBuf,
}

impl Drop for IpcServerGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(mut thread) = self.thread.lock() {
            if let Some(thread) = thread.take() {
                let _ = thread.join();
            }
        }
        let _ = fs::remove_file(&self.socket_path);
    }
}

#[derive(Clone)]
struct PendingRegistrationRecord {
    pending_id: String,
    application_name: String,
    public_key: Vec<u8>,
    public_key_fingerprint: String,
    namespace: String,
}

#[derive(Clone, Serialize)]
pub struct PendingRegistrationView {
    pub pending_id: String,
    pub application_name: String,
    pub public_key_fingerprint: String,
    pub namespace: String,
}

impl From<&PendingRegistrationRecord> for PendingRegistrationView {
    fn from(value: &PendingRegistrationRecord) -> Self {
        Self {
            pending_id: value.pending_id.clone(),
            application_name: value.application_name.clone(),
            public_key_fingerprint: value.public_key_fingerprint.clone(),
            namespace: value.namespace.clone(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct AuthorizationRecord {
    application_name: String,
    public_key_b64: String,
    namespace: String,
    revoked: bool,
}

struct SealedAuthorization {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: Vec<u8>,
}

#[derive(Serialize)]
pub struct ClientAuthorizationView {
    pub client_id: String,
    pub application_name: String,
    pub public_key_fingerprint: String,
    pub namespace: String,
    pub revoked: bool,
}

struct ChallengeState {
    client_id: String,
    bytes: Zeroizing<[u8; 32]>,
    generation: u64,
    expires_at: Instant,
}

impl ChallengeState {
    fn is_valid(&self, client_id: &str, generation: u64, now: Instant) -> bool {
        self.client_id == client_id && self.generation == generation && now < self.expires_at
    }
}

struct AuthenticatedSession {
    namespace: String,
    generation: u64,
    expires_at: Instant,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Request {
    Ping,
    Register {
        application_name: String,
        public_key: String,
        namespace: String,
    },
    BeginAuth {
        client_id: String,
    },
    Authenticate {
        client_id: String,
        signature: String,
    },
    ListMetadata,
    GetSecret {
        id: i64,
    },
}

#[derive(Serialize)]
struct SecretResponse<'a> {
    status: &'static str,
    secret: &'a str,
}

pub fn start(app: &AppHandle, db: AppDb) -> Result<(IpcState, IpcServerGuard), String> {
    let ipc_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("resolve application data directory: {e}"))?
        .join("ipc");
    fs::create_dir_all(&ipc_dir).map_err(|e| format!("create IPC directory: {e}"))?;
    fs::set_permissions(&ipc_dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("secure IPC directory: {e}"))?;

    let socket_path = ipc_dir.join(SOCKET_FILE);
    let _ = ACTIVE_SOCKET_PATH.set(socket_path.clone());
    remove_stale_socket(&socket_path)?;
    let listener = UnixListener::bind(&socket_path).map_err(|e| format!("bind IPC socket: {e}"))?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("secure IPC socket: {e}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("configure IPC socket: {e}"))?;

    let state = IpcState {
        inner: Arc::new(IpcRuntime {
            pending: Mutex::new(HashMap::new()),
            socket_path: socket_path.clone(),
        }),
    };
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread_state = state.clone();
    let thread_path = socket_path.clone();
    let handle = thread::Builder::new()
        .name("sv-local-ipc".into())
        .spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let Ok(id) = CONNECTIONS
                            .get_or_init(Connections::default)
                            .register(&stream)
                        else {
                            let _ = stream.shutdown(Shutdown::Both);
                            continue;
                        };
                        let guard = ConnectionGuard(id);
                        let db = db.clone();
                        let state = thread_state.clone();
                        let _ = thread::Builder::new()
                            .name("sv-local-ipc-client".into())
                            .spawn(move || {
                                let _guard = guard;
                                let _ = handle_connection(stream, db, state);
                            });
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(50));
                    }
                    Err(_) => break,
                }
            }
            let _ = fs::remove_file(thread_path);
        })
        .map_err(|e| format!("start IPC server: {e}"))?;

    Ok((
        state,
        IpcServerGuard {
            stop,
            thread: Mutex::new(Some(handle)),
            socket_path,
        },
    ))
}

fn remove_stale_socket(path: &PathBuf) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("inspect existing IPC path: {error}")),
    };
    if !metadata.file_type().is_socket() {
        return Err("Refusing to replace a non-socket IPC path".into());
    }
    fs::remove_file(path).map_err(|e| format!("remove stale IPC socket: {e}"))
}

pub fn invalidate_sessions() {
    SESSION_GENERATION.fetch_add(1, Ordering::SeqCst);
    if let Some(connections) = CONNECTIONS.get() {
        connections.shutdown_all();
    }
}

pub fn cleanup_socket() {
    if let Some(path) = ACTIVE_SOCKET_PATH.get() {
        let _ = fs::remove_file(path);
    }
}

pub fn validate_namespace(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 64 {
        return Err("Namespace must contain between 1 and 64 characters".into());
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("Namespace may contain only letters, numbers, '.', '-', and '_'".into());
    }
    Ok(value.to_string())
}

pub fn validate_record_type(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 64 {
        return Err("Record type must contain between 1 and 64 characters".into());
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("Record type may contain only letters, numbers, '.', '-', and '_'".into());
    }
    Ok(value.to_string())
}

fn validate_application_name(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 100 || value.chars().any(char::is_control) {
        return Err("Application name must contain between 1 and 100 printable characters".into());
    }
    Ok(value.to_string())
}

fn handle_connection(mut stream: UnixStream, db: AppDb, state: IpcState) -> io::Result<()> {
    // Darwin can inherit O_NONBLOCK from the listener. Each worker uses
    // blocking, timeout-bounded I/O, unlike the nonblocking accept loop.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(SESSION_LIFETIME))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let reader_stream = stream.try_clone()?;
    let mut reader = BufReader::new(reader_stream);
    let mut challenge: Option<ChallengeState> = None;
    let mut session: Option<AuthenticatedSession> = None;

    while let Some(frame) = read_frame(&mut reader)? {
        let _security = SECURITY_GATE.read().map_err(|_| io::ErrorKind::Other)?;
        let request: Request = match serde_json::from_slice(&frame) {
            Ok(request) => request,
            Err(_) => {
                write_json(&mut stream, &error_response("malformed request"))?;
                break;
            }
        };

        match request {
            Request::Ping => {
                write_json(&mut stream, &json!({"status": "ok", "version": 1}))?;
            }
            Request::Register {
                application_name,
                public_key,
                namespace,
            } => {
                if !commands::vault_is_unlocked() {
                    write_json(&mut stream, &error_response("vault is locked"))?;
                    continue;
                }
                match queue_registration(&state, application_name, public_key, namespace) {
                    Ok(view) => write_json(
                        &mut stream,
                        &json!({"status": "pending_approval", "registration": view}),
                    )?,
                    Err(error) => write_json(&mut stream, &error_response(&error))?,
                }
            }
            Request::BeginAuth { client_id } => {
                let generation = SESSION_GENERATION.load(Ordering::SeqCst);
                challenge = None;
                session = None;
                let auth = load_authorization(&db, &client_id);
                if !commands::vault_is_unlocked()
                    || !matches!(auth, Ok(Some(ref record)) if !record.revoked)
                {
                    write_json(&mut stream, &error_response("authentication failed"))?;
                    continue;
                }
                let mut bytes = Zeroizing::new([0u8; 32]);
                rng().fill_bytes(bytes.as_mut());
                let encoded = B64.encode(bytes.as_ref());
                challenge = Some(ChallengeState {
                    client_id: client_id.clone(),
                    bytes,
                    generation,
                    expires_at: Instant::now() + CHALLENGE_LIFETIME,
                });
                write_json(
                    &mut stream,
                    &json!({
                        "status": "challenge",
                        "client_id": client_id,
                        "challenge": encoded,
                        "context": "SV-CLIENT-AUTH-v1",
                        "format": "context || uint32_be(client_id_length) || client_id_utf8 || challenge"
                    }),
                )?;
            }
            Request::Authenticate {
                client_id,
                signature,
            } => {
                let generation = challenge
                    .as_ref()
                    .map(|value| value.generation)
                    .unwrap_or(0);
                let result = authenticate(&db, challenge.take(), &client_id, &signature);
                match result {
                    Ok(auth) => {
                        session = Some(AuthenticatedSession {
                            namespace: auth.namespace,
                            generation,
                            expires_at: Instant::now() + SESSION_LIFETIME,
                        });
                        write_json(&mut stream, &json!({"status": "authenticated"}))?;
                    }
                    Err(_) => {
                        session = None;
                        write_json(&mut stream, &error_response("authentication failed"))?;
                    }
                }
            }
            Request::ListMetadata => {
                let Some(active) = valid_session(&session) else {
                    session = None;
                    write_json(&mut stream, &error_response("authentication required"))?;
                    continue;
                };
                let entries = {
                    let conn = db.0.lock().map_err(|_| io::ErrorKind::Other)?;
                    let guard = commands::get_aes_key_ref().map_err(|_| io::ErrorKind::Other)?;
                    let key = guard.as_ref().ok_or(io::ErrorKind::PermissionDenied)?;
                    let candidates = db::list_entries_in_namespace(&conn, &active.namespace)
                        .map_err(|_| io::ErrorKind::Other)?;
                    let mut verified = Vec::new();
                    for item in candidates {
                        let entry = db::get_entry_encrypted(&conn, item.id)
                            .map_err(|_| io::ErrorKind::Other)?;
                        if let Some(entry) = entry {
                            if crate::vault_core::binding::verify(&conn, item.id, &entry, key)
                                .is_ok()
                            {
                                verified.push(item);
                            }
                        }
                    }
                    verified
                };
                write_json(&mut stream, &json!({"status": "ok", "records": entries}))?;
            }
            Request::GetSecret { id } => {
                let Some(active) = valid_session(&session) else {
                    session = None;
                    write_json(&mut stream, &error_response("authentication required"))?;
                    continue;
                };
                match commands::ipc_get_secret(&db, id, &active.namespace) {
                    Ok(secret) => write_secret(&mut stream, &secret)?,
                    Err(_) => write_json(&mut stream, &error_response("request denied"))?,
                }
            }
        }
    }

    if let Some(mut challenge) = challenge {
        challenge.bytes.zeroize();
    }
    Ok(())
}

fn valid_session(session: &Option<AuthenticatedSession>) -> Option<&AuthenticatedSession> {
    let session = session.as_ref()?;
    if !commands::vault_is_unlocked()
        || session.generation != SESSION_GENERATION.load(Ordering::SeqCst)
        || Instant::now() >= session.expires_at
    {
        return None;
    }
    Some(session)
}

fn queue_registration(
    state: &IpcState,
    application_name: String,
    public_key_b64: String,
    namespace: String,
) -> Result<PendingRegistrationView, String> {
    let application_name = validate_application_name(&application_name)?;
    let namespace = validate_namespace(&namespace)?;
    let public_key = B64
        .decode(public_key_b64.as_bytes())
        .map_err(|_| "Invalid ML-DSA public key encoding")?;
    oqs::init();
    let dsa = Sig::new(SigAlgorithm::MlDsa65).map_err(|_| "ML-DSA unavailable")?;
    if dsa.public_key_from_bytes(&public_key).is_none() {
        return Err("Invalid ML-DSA-65 public key".into());
    }

    let record = PendingRegistrationRecord {
        pending_id: random_identifier(18),
        application_name,
        public_key_fingerprint: fingerprint(&public_key),
        public_key,
        namespace,
    };
    let view = PendingRegistrationView::from(&record);
    let mut pending = state
        .inner
        .pending
        .lock()
        .map_err(|_| "Pending registration state unavailable")?;
    if pending.len() >= MAX_PENDING_REGISTRATIONS {
        return Err("Too many pending registration requests".into());
    }
    pending.insert(record.pending_id.clone(), record);
    Ok(view)
}

fn authenticate(
    db: &AppDb,
    challenge: Option<ChallengeState>,
    client_id: &str,
    signature_b64: &str,
) -> Result<AuthorizationRecord, String> {
    let challenge = challenge.ok_or("No active challenge")?;
    if !challenge.is_valid(
        client_id,
        SESSION_GENERATION.load(Ordering::SeqCst),
        Instant::now(),
    ) {
        return Err("Challenge expired or invalidated".into());
    }
    let auth = load_authorization(db, client_id)?
        .filter(|record| !record.revoked)
        .ok_or("Unknown or revoked client")?;
    let public_key = B64
        .decode(auth.public_key_b64.as_bytes())
        .map_err(|_| "Invalid registered public key")?;
    let signature = B64
        .decode(signature_b64.as_bytes())
        .map_err(|_| "Invalid signature encoding")?;
    let message = Zeroizing::new(authentication_message(client_id, &challenge.bytes));

    oqs::init();
    let dsa = Sig::new(SigAlgorithm::MlDsa65).map_err(|_| "ML-DSA unavailable")?;
    let public_key = dsa
        .public_key_from_bytes(&public_key)
        .ok_or("Invalid registered public key")?;
    let signature = dsa
        .signature_from_bytes(&signature)
        .ok_or("Invalid ML-DSA signature")?;
    dsa.verify(message.as_ref(), signature, public_key)
        .map_err(|_| "Invalid ML-DSA signature")?;
    Ok(auth)
}

fn authentication_message(client_id: &str, challenge: &[u8; 32]) -> Vec<u8> {
    let id = client_id.as_bytes();
    let mut message = Vec::with_capacity(AUTH_CONTEXT.len() + 4 + id.len() + challenge.len());
    message.extend_from_slice(AUTH_CONTEXT);
    message.extend_from_slice(&(id.len() as u32).to_be_bytes());
    message.extend_from_slice(id);
    message.extend_from_slice(challenge);
    message
}

fn random_identifier(bytes: usize) -> String {
    let mut value = vec![0u8; bytes];
    rng().fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn fingerprint(public_key: &[u8]) -> String {
    let digest = Sha256::digest(public_key);
    digest
        .chunks(2)
        .map(|chunk| {
            chunk
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(":")
}

fn seal_authorization(
    client_id: &str,
    record: &AuthorizationRecord,
) -> Result<SealedAuthorization, String> {
    let guard = commands::get_aes_key_ref().map_err(|_| "Vault is locked")?;
    let key = guard.as_ref().ok_or("Vault is locked")?;
    seal_authorization_with_key(client_id, record, key)
}

fn seal_authorization_with_key(
    client_id: &str,
    record: &AuthorizationRecord,
    key: &[u8; 32],
) -> Result<SealedAuthorization, String> {
    let mut plaintext = Zeroizing::new(serde_json::to_vec(record).map_err(|e| e.to_string())?);
    let mut nonce = [0u8; 12];
    rng().fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let tag = cipher
        .encrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            client_id.as_bytes(),
            plaintext.as_mut(),
        )
        .map_err(|_| "Authorization encryption failed")?;
    Ok(SealedAuthorization {
        nonce: nonce.to_vec(),
        ciphertext: plaintext.to_vec(),
        tag: tag.to_vec(),
    })
}

fn store_authorization(
    db: &AppDb,
    client_id: &str,
    record: &AuthorizationRecord,
) -> Result<(), String> {
    let conn = db.0.lock().map_err(|_| "DB lock poisoned")?;
    let sealed = seal_authorization(client_id, record)?;
    conn.execute(
        "INSERT INTO client_authorizations
             (client_id, nonce, ciphertext, tag)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(client_id) DO UPDATE SET
             nonce = excluded.nonce,
             ciphertext = excluded.ciphertext,
             tag = excluded.tag,
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
        params![client_id, sealed.nonce, sealed.ciphertext, sealed.tag],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn load_authorization(db: &AppDb, client_id: &str) -> Result<Option<AuthorizationRecord>, String> {
    let sealed: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = {
        let conn = db.0.lock().map_err(|_| "DB lock poisoned")?;
        conn.query_row(
            "SELECT nonce, ciphertext, tag
             FROM client_authorizations WHERE client_id = ?1",
            [client_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|e| e.to_string())?
    };
    let Some((nonce, ciphertext, tag)) = sealed else {
        return Ok(None);
    };
    if nonce.len() != 12 || tag.len() != 16 {
        return Err("Invalid authorization record".into());
    }
    let guard = commands::get_aes_key_ref().map_err(|_| "Vault is locked")?;
    let key = guard.as_ref().ok_or("Vault is locked")?;
    open_authorization_with_key(client_id, nonce, ciphertext, tag, key).map(Some)
}

fn open_authorization_with_key(
    client_id: &str,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: Vec<u8>,
    key: &[u8; 32],
) -> Result<AuthorizationRecord, String> {
    if nonce.len() != 12 || tag.len() != 16 {
        return Err("Invalid authorization record".into());
    }
    let mut plaintext = Zeroizing::new(ciphertext);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            client_id.as_bytes(),
            plaintext.as_mut(),
            GenericArray::from_slice(&tag),
        )
        .map_err(|_| "Invalid authorization record")?;
    serde_json::from_slice(plaintext.as_ref()).map_err(|_| "Invalid authorization record".into())
}

pub(crate) fn reencrypt_authorizations(
    tx: &Transaction<'_>,
    old_key: &[u8; 32],
    new_key: &[u8; 32],
) -> Result<(), String> {
    let rows = {
        let mut stmt = tx
            .prepare(
                "SELECT client_id, nonce, ciphertext, tag
                 FROM client_authorizations ORDER BY client_id",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row.map_err(|e| e.to_string())?);
        }
        records
    };

    for (client_id, nonce, ciphertext, tag) in rows {
        let record = open_authorization_with_key(&client_id, nonce, ciphertext, tag, old_key)?;
        let sealed = seal_authorization_with_key(&client_id, &record, new_key)?;
        tx.execute(
            "UPDATE client_authorizations
             SET nonce = ?1, ciphertext = ?2, tag = ?3,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
             WHERE client_id = ?4",
            params![sealed.nonce, sealed.ciphertext, sealed.tag, client_id],
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn read_frame<R: BufRead>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut frame = Vec::with_capacity(1024);
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "partial IPC frame",
                ))
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map(|index| index + 1).unwrap_or(available.len());
        if frame.len() + take > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IPC frame too large",
            ));
        }
        frame.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            frame.pop();
            if frame.last() == Some(&b'\r') {
                frame.pop();
            }
            return Ok(Some(frame));
        }
    }
}

fn write_json(stream: &mut UnixStream, value: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *stream, value)?;
    stream.write_all(b"\n")?;
    stream.flush()
}

fn write_secret(stream: &mut UnixStream, secret: &SecretString) -> io::Result<()> {
    let response = SecretResponse {
        status: "ok",
        secret: secret.expose_secret(),
    };
    let mut buffer = Zeroizing::new(serde_json::to_vec(&response)?);
    buffer.push(b'\n');
    write_and_wipe(stream, buffer.as_mut_slice())
}

fn write_and_wipe<W: Write>(writer: &mut W, buffer: &mut [u8]) -> io::Result<()> {
    let result = writer.write_all(buffer).and_then(|_| writer.flush());
    buffer.zeroize();
    result
}

fn error_response(message: &str) -> Value {
    json!({"status": "error", "message": message})
}

#[command]
pub fn ipc_socket_path(state: State<IpcState>) -> String {
    state.inner.socket_path.to_string_lossy().into_owned()
}

#[command]
pub fn ipc_list_pending_registrations(
    state: State<IpcState>,
) -> Result<Vec<PendingRegistrationView>, String> {
    let pending = state
        .inner
        .pending
        .lock()
        .map_err(|_| "Pending registration state unavailable")?;
    Ok(pending
        .values()
        .map(PendingRegistrationView::from)
        .collect())
}

#[command]
pub fn ipc_approve_registration(
    state: State<IpcState>,
    db: State<AppDb>,
    pending_id: String,
) -> Result<ClientAuthorizationView, String> {
    let _security = SECURITY_GATE
        .write()
        .map_err(|_| "Security state unavailable")?;
    if !commands::vault_is_unlocked() {
        return Err("Vault is locked".into());
    }
    let pending = {
        let pending = state
            .inner
            .pending
            .lock()
            .map_err(|_| "Pending registration state unavailable")?;
        pending
            .get(&pending_id)
            .cloned()
            .ok_or("Registration request not found")?
    };
    let client_id = random_identifier(18);
    let record = AuthorizationRecord {
        application_name: pending.application_name.clone(),
        public_key_b64: B64.encode(&pending.public_key),
        namespace: pending.namespace.clone(),
        revoked: false,
    };
    store_authorization(db.inner(), &client_id, &record)?;
    state
        .inner
        .pending
        .lock()
        .map_err(|_| "Pending registration state unavailable")?
        .remove(&pending_id);
    Ok(ClientAuthorizationView {
        client_id,
        application_name: record.application_name,
        public_key_fingerprint: pending.public_key_fingerprint,
        namespace: record.namespace,
        revoked: false,
    })
}

#[command]
pub fn ipc_reject_registration(state: State<IpcState>, pending_id: String) -> Result<(), String> {
    let removed = state
        .inner
        .pending
        .lock()
        .map_err(|_| "Pending registration state unavailable")?
        .remove(&pending_id);
    if removed.is_none() {
        return Err("Registration request not found".into());
    }
    Ok(())
}

#[command]
pub fn ipc_list_clients(db: State<AppDb>) -> Result<Vec<ClientAuthorizationView>, String> {
    if !commands::vault_is_unlocked() {
        return Err("Vault is locked".into());
    }
    let ids = {
        let conn = db.inner().0.lock().map_err(|_| "DB lock poisoned")?;
        let mut stmt = conn
            .prepare("SELECT client_id FROM client_authorizations ORDER BY created_at")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        let mut ids = Vec::new();
        for row in rows {
            ids.push(row.map_err(|e| e.to_string())?);
        }
        ids
    };
    let mut clients = Vec::new();
    for client_id in ids {
        if let Some(record) = load_authorization(db.inner(), &client_id)? {
            let public_key = B64
                .decode(record.public_key_b64.as_bytes())
                .map_err(|_| "Invalid authorization record")?;
            clients.push(ClientAuthorizationView {
                client_id,
                application_name: record.application_name,
                public_key_fingerprint: fingerprint(&public_key),
                namespace: record.namespace,
                revoked: record.revoked,
            });
        }
    }
    Ok(clients)
}

#[command]
pub fn ipc_revoke_client(db: State<AppDb>, client_id: String) -> Result<(), String> {
    revoke_client(db.inner(), &client_id)
}

fn revoke_client(db: &AppDb, client_id: &str) -> Result<(), String> {
    let _security = SECURITY_GATE
        .write()
        .map_err(|_| "Security state unavailable")?;
    if !commands::vault_is_unlocked() {
        return Err("Vault is locked".into());
    }
    let mut record = load_authorization(db, client_id)?.ok_or("Client authorization not found")?;
    record.revoked = true;
    store_authorization(db, client_id, &record)?;
    // Invalidating every authenticated connection is conservative and ensures
    // the revoked client's session cannot survive revocation.
    invalidate_sessions();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn response_buffer_is_overwritten_after_success() {
        let mut buffer = b"synthetic-response-token".to_vec();
        let mut writer = Vec::new();
        write_and_wipe(&mut writer, &mut buffer).unwrap();
        assert_eq!(writer, b"synthetic-response-token");
        assert_eq!(buffer.len(), 24);
        assert!(buffer.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn response_buffer_is_overwritten_after_partial_write_failure() {
        struct FailingWriter(bool);
        impl Write for FailingWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.0 {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
                self.0 = true;
                Ok(bytes.len().min(3))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut buffer = b"synthetic-response-token".to_vec();
        assert!(write_and_wipe(&mut FailingWriter(false), &mut buffer).is_err());
        assert!(buffer.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn response_buffer_is_overwritten_after_flush_failure() {
        struct FailingFlush;
        impl Write for FailingFlush {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
        }
        let mut buffer = b"synthetic-response-token".to_vec();
        assert!(write_and_wipe(&mut FailingFlush, &mut buffer).is_err());
        assert!(buffer.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn challenge_rejects_expiry_wrong_client_and_old_generation() {
        let now = Instant::now();
        let challenge = ChallengeState {
            client_id: "demo".into(),
            bytes: Zeroizing::new([1; 32]),
            generation: 7,
            expires_at: now + CHALLENGE_LIFETIME,
        };
        assert!(challenge.is_valid("demo", 7, now));
        assert!(!challenge.is_valid("other", 7, now));
        assert!(!challenge.is_valid("demo", 8, now));
        assert!(!challenge.is_valid("demo", 7, challenge.expires_at));
    }

    #[test]
    fn connection_shutdown_disconnects_peer() {
        let connections = Connections::default();
        let (server, mut client) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        connections.register(&server).unwrap();
        connections.shutdown_all();
        let mut byte = [0];
        assert_eq!(std::io::Read::read(&mut client, &mut byte).unwrap(), 0);
        assert!(connections.0.lock().unwrap().is_empty());
    }

    // Uses the production process-global key. Run explicitly, with one test
    // thread, so unrelated key-zeroization tests cannot alter this fixture.
    #[test]
    #[ignore = "isolated IPC integration test; run with --ignored --test-threads=1"]
    fn isolated_client_retrieval_and_revocation() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE client_authorizations (
            client_id TEXT PRIMARY KEY, nonce BLOB, ciphertext BLOB, tag BLOB,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE entries (id INTEGER PRIMARY KEY, label TEXT, username TEXT, notes TEXT,
            namespace TEXT, record_type TEXT, nonce BLOB, ciphertext BLOB, tag BLOB,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP);",
        )
        .unwrap();
        let key = [0x42; 32];
        crate::vault_core::binding::init(&conn).unwrap();
        commands::install_aes_key(&key).unwrap();
        let db = AppDb(Arc::new(Mutex::new(conn)));
        let state = IpcState {
            inner: Arc::new(IpcRuntime {
                pending: Mutex::new(HashMap::new()),
                socket_path: PathBuf::new(),
            }),
        };
        oqs::init();
        let dsa = Sig::new(SigAlgorithm::MlDsa65).unwrap();
        let (pk, sk) = dsa.keypair().unwrap();
        let mut record = AuthorizationRecord {
            application_name: "Dummy client".into(),
            public_key_b64: B64.encode(pk.as_ref()),
            namespace: "demo-app".into(),
            revoked: false,
        };
        store_authorization(&db, "demo-client", &record).unwrap();
        for (id, namespace) in [(1, "demo-app"), (2, "other-app")] {
            let nonce = [id as u8; 12];
            let mut payload = b"dummy-token-not-a-real-secret".to_vec();
            let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
            let tag = cipher
                .encrypt_in_place_detached(Nonce::from_slice(&nonce), b"", &mut payload)
                .unwrap();
            db.0.lock()
                .unwrap()
                .execute(
                    "INSERT INTO entries
                (id,label,username,namespace,record_type,nonce,ciphertext,tag)
                VALUES (?1,?2,'',?3,'api-token',?4,?5,?6)",
                    params![
                        id,
                        format!("DEMO_{id}"),
                        namespace,
                        nonce.as_slice(),
                        payload,
                        tag.as_slice()
                    ],
                )
                .unwrap();
        }
        for id in [1, 2] {
            crate::vault_core::binding::seal(&db.0.lock().unwrap(), id, &key).unwrap();
        }
        fn connect(db: AppDb, state: IpcState) -> (BufReader<UnixStream>, JoinHandle<()>) {
            let (server, client) = UnixStream::pair().unwrap();
            // Model an accepted Darwin socket inherited from our listener.
            server.set_nonblocking(true).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let id = CONNECTIONS
                .get_or_init(Connections::default)
                .register(&server)
                .unwrap();
            let handle = thread::spawn(move || {
                let _guard = ConnectionGuard(id);
                let _ = handle_connection(server, db, state);
            });
            (BufReader::new(client), handle)
        }
        fn request(client: &mut BufReader<UnixStream>, value: Value) -> Value {
            write_json(client.get_mut(), &value).unwrap();
            serde_json::from_slice(&read_frame(client).unwrap().unwrap()).unwrap()
        }
        let authenticate_client = |client: &mut BufReader<UnixStream>| {
            let response = request(
                client,
                json!({"type":"begin_auth", "client_id":"demo-client"}),
            );
            let bytes: [u8; 32] = B64
                .decode(response["challenge"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let signature = dsa
                .sign(&authentication_message("demo-client", &bytes), &sk)
                .unwrap();
            assert_eq!(
                request(
                    client,
                    json!({"type":"authenticate", "client_id":"demo-client", "signature":B64.encode(signature.as_ref())})
                )["status"],
                "authenticated"
            );
        };
        let (mut client, handle) = connect(db.clone(), state.clone());
        let challenge = request(
            &mut client,
            json!({"type":"begin_auth", "client_id":"demo-client"}),
        );
        let bytes: [u8; 32] = B64
            .decode(challenge["challenge"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let signature = dsa
            .sign(&authentication_message("demo-client", &bytes), &sk)
            .unwrap();
        let auth_request = json!({"type":"authenticate", "client_id":"demo-client", "signature":B64.encode(signature.as_ref())});
        assert_eq!(
            request(&mut client, auth_request.clone())["status"],
            "authenticated"
        );
        let listed = request(&mut client, json!({"type":"list_metadata"}));
        assert_eq!(listed["records"].as_array().unwrap().len(), 1);
        assert_eq!(
            request(&mut client, json!({"type":"get_secret","id":1}))["secret"],
            "dummy-token-not-a-real-secret"
        );
        assert_ne!(
            request(&mut client, json!({"type":"get_secret","id":2}))["status"],
            "ok"
        );
        // A consumed challenge cannot be reused on the same connection.
        // Database tampering must not allow relabeling another application's
        // ciphertext into the authenticated client's namespace.
        db.0.lock()
            .unwrap()
            .execute("UPDATE entries SET namespace = 'demo-app' WHERE id = 2", [])
            .unwrap();
        let relabeled = request(&mut client, json!({"type":"get_secret", "id":2}));
        assert_eq!(
            relabeled["status"], "error",
            "namespace relabeling bypassed authorization"
        );
        assert_eq!(
            request(&mut client, json!({"type":"list_metadata"}))["records"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        db.0.lock()
            .unwrap()
            .execute(
                "UPDATE entries SET namespace = 'other-app' WHERE id = 2",
                [],
            )
            .unwrap();
        assert_ne!(
            request(&mut client, auth_request)["status"],
            "authenticated"
        );
        authenticate_client(&mut client);
        revoke_client(&db, "demo-client").unwrap();
        assert!(read_frame(&mut client).unwrap().is_none());
        handle.join().unwrap();
        let (mut client, handle) = connect(db.clone(), state.clone());
        assert_ne!(
            request(
                &mut client,
                json!({"type":"begin_auth", "client_id":"demo-client"})
            )["status"],
            "challenge"
        );
        record.revoked = false;
        store_authorization(&db, "demo-client", &record).unwrap();
        authenticate_client(&mut client);
        // Exercise the key-wipe and session-invalidation portions of locking,
        // without clearing the user's system clipboard from a test process.
        commands::lock_vault_security_state();
        assert!(read_frame(&mut client).unwrap().is_none());
        handle.join().unwrap();
        let (mut client, handle) = connect(db.clone(), state.clone());
        assert_ne!(
            request(
                &mut client,
                json!({"type":"begin_auth", "client_id":"demo-client"})
            )["status"],
            "challenge"
        );
        client.get_mut().shutdown(Shutdown::Both).unwrap();
        handle.join().unwrap();

        // Exercise actual retrieval concurrently with each lifecycle action.
        // Responses already written before the action are allowed; the socket
        // must close and cannot remain usable after the action completes.
        for revoke in [false, true] {
            commands::install_aes_key(&key).unwrap();
            record.revoked = false;
            store_authorization(&db, "demo-client", &record).unwrap();
            let (mut client, server) = connect(db.clone(), state.clone());
            authenticate_client(&mut client);
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let client_barrier = barrier.clone();
            let worker = thread::spawn(move || {
                client_barrier.wait();
                for _ in 0..1000 {
                    if write_json(client.get_mut(), &json!({"type":"get_secret", "id":1})).is_err()
                    {
                        return;
                    }
                    match read_frame(&mut client) {
                        Ok(Some(frame)) => {
                            let value: Value = serde_json::from_slice(&frame).unwrap();
                            if value["status"] == "ok" {
                                assert_eq!(value["secret"], "dummy-token-not-a-real-secret");
                            } else {
                                assert!(value.get("secret").is_none());
                            }
                        }
                        Ok(None) => return,
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof
                            ) =>
                        {
                            return
                        }
                        Err(error) => panic!("Unexpected read failure: {error}"),
                    }
                }
                panic!("Lifecycle action did not disconnect client");
            });
            barrier.wait();
            if revoke {
                revoke_client(&db, "demo-client").unwrap();
            } else {
                commands::lock_vault_security_state();
            }
            worker.join().unwrap();
            server.join().unwrap();
        }
        commands::lock_vault_security_state();
    }

    #[test]
    fn namespace_validation_accepts_safe_values() {
        assert_eq!(validate_namespace("team.api-v1").unwrap(), "team.api-v1");
    }

    #[test]
    fn authorization_tampering_and_identity_substitution_are_rejected() {
        let key = [0x42; 32];
        let record = AuthorizationRecord {
            application_name: "Tamper fixture".into(),
            public_key_b64: "synthetic".into(),
            namespace: "test".into(),
            revoked: false,
        };
        for field in 0..4 {
            let mut sealed = seal_authorization_with_key("client-a", &record, &key).unwrap();
            let id = match field {
                0 => {
                    sealed.nonce[0] ^= 1;
                    "client-a"
                }
                1 => {
                    sealed.ciphertext[0] ^= 1;
                    "client-a"
                }
                2 => {
                    sealed.tag[0] ^= 1;
                    "client-a"
                }
                _ => "client-b",
            };
            assert!(open_authorization_with_key(
                id,
                sealed.nonce,
                sealed.ciphertext,
                sealed.tag,
                &key
            )
            .is_err());
        }
    }

    #[test]
    fn namespace_validation_rejects_paths_and_whitespace() {
        assert!(validate_namespace("../team").is_err());
        assert!(validate_namespace("team secrets").is_err());
        assert!(validate_namespace("").is_err());
    }

    #[test]
    fn authentication_message_is_unambiguous() {
        let challenge = [0xA5; 32];
        let message = authentication_message("client-1", &challenge);
        assert!(message.starts_with(AUTH_CONTEXT));
        let length_offset = AUTH_CONTEXT.len();
        assert_eq!(
            &message[length_offset..length_offset + 4],
            &8u32.to_be_bytes()
        );
        assert_eq!(&message[length_offset + 4..length_offset + 12], b"client-1");
        assert_eq!(&message[length_offset + 12..], &challenge);
    }

    #[test]
    fn frame_reader_enforces_newline_framing() {
        let mut reader = Cursor::new(b"{\"type\":\"ping\"}\n".to_vec());
        assert_eq!(
            read_frame(&mut reader).unwrap().unwrap(),
            b"{\"type\":\"ping\"}"
        );
        assert!(read_frame(&mut reader).unwrap().is_none());
    }

    #[test]
    fn authentication_message_verifies_with_ml_dsa_65() {
        oqs::init();
        let dsa = Sig::new(SigAlgorithm::MlDsa65).unwrap();
        let (public_key, secret_key) = dsa.keypair().unwrap();
        let challenge = [0x5A; 32];
        let message = authentication_message("client-1", &challenge);
        let signature = dsa.sign(&message, &secret_key).unwrap();

        assert!(dsa.verify(&message, &signature, &public_key).is_ok());

        let different_message = authentication_message("client-1", &[0x5B; 32]);
        assert!(dsa
            .verify(&different_message, &signature, &public_key)
            .is_err());
    }

    #[test]
    fn frame_reader_rejects_oversized_frames() {
        let mut bytes = vec![b'a'; MAX_FRAME_BYTES];
        bytes.push(b'\n');
        let mut reader = Cursor::new(bytes);
        assert_eq!(
            read_frame(&mut reader).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn authorization_records_reencrypt_during_vault_key_rotation() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE client_authorizations (
                client_id TEXT PRIMARY KEY,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                tag BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )
        .unwrap();

        let client_id = "client-test";
        let old_key = [0x31; 32];
        let new_key = [0x73; 32];
        let record = AuthorizationRecord {
            application_name: "Test Client".into(),
            public_key_b64: B64.encode([0x44; 32]),
            namespace: "testing".into(),
            revoked: false,
        };
        let sealed = seal_authorization_with_key(client_id, &record, &old_key).unwrap();
        conn.execute(
            "INSERT INTO client_authorizations (client_id, nonce, ciphertext, tag)
             VALUES (?1, ?2, ?3, ?4)",
            params![client_id, sealed.nonce, sealed.ciphertext, sealed.tag],
        )
        .unwrap();

        let tx = conn.transaction().unwrap();
        reencrypt_authorizations(&tx, &old_key, &new_key).unwrap();
        tx.commit().unwrap();

        let (nonce, ciphertext, tag) = conn
            .query_row(
                "SELECT nonce, ciphertext, tag FROM client_authorizations
                 WHERE client_id = ?1",
                [client_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .unwrap();

        let opened = open_authorization_with_key(
            client_id,
            nonce.clone(),
            ciphertext.clone(),
            tag.clone(),
            &new_key,
        )
        .unwrap();
        assert_eq!(opened.application_name, "Test Client");
        assert_eq!(opened.namespace, "testing");
        assert!(!opened.revoked);
        assert!(open_authorization_with_key(client_id, nonce, ciphertext, tag, &old_key).is_err());
    }
}
