//! Minimal development client for the Schrödinger's Vault local IPC protocol.
//!
//! Examples:
//!   cargo run --example sv_ipc_client -- generate ./demo-client
//!   cargo run --example sv_ipc_client -- register SOCKET "Demo App" default ./demo-client.pk
//!   cargo run --example sv_ipc_client -- list SOCKET CLIENT_ID ./demo-client.sk
//!   cargo run --example sv_ipc_client -- get SOCKET CLIENT_ID ./demo-client.sk RECORD_ID

#[cfg(not(unix))]
fn main() {
    eprintln!("The development IPC client currently supports Unix platforms only.");
}

#[cfg(unix)]
mod unix_client {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use oqs::sig::{Algorithm, Sig};
    use serde_json::{json, Value};
    use std::env;
    use std::fs::{self, OpenOptions};
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use zeroize::{Zeroize, Zeroizing};

    const AUTH_CONTEXT: &[u8] = b"SV-CLIENT-AUTH-v1";

    pub fn run() -> Result<(), String> {
        oqs::init();
        let args: Vec<String> = env::args().collect();
        match args.get(1).map(String::as_str) {
            Some("generate") if args.len() == 3 => generate_keys(&args[2]),
            Some("audit") if args.len() == 5 => audit(&args[2], &args[3], &args[4]),
            Some("lifecycle") if args.len() == 6 => {
                lifecycle(&args[2], &args[3], &args[4], &args[5])
            }
            Some("register") if args.len() == 6 => register(&args[2], &args[3], &args[4], &args[5]),
            Some("list") if args.len() == 5 => authenticated_request(
                &args[2],
                &args[3],
                &args[4],
                json!({"type": "list_metadata"}),
            ),
            Some("get") if args.len() == 6 => {
                let id = args[5]
                    .parse::<i64>()
                    .map_err(|_| "Record id must be an integer".to_string())?;
                authenticated_request(
                    &args[2],
                    &args[3],
                    &args[4],
                    json!({"type": "get_secret", "id": id}),
                )
            }
            _ => Err(usage()),
        }
    }

    fn usage() -> String {
        "Usage:\n  sv_ipc_client generate KEY_PREFIX\n  sv_ipc_client register SOCKET APP_NAME NAMESPACE PUBLIC_KEY\n  sv_ipc_client list SOCKET CLIENT_ID SECRET_KEY\n  sv_ipc_client get SOCKET CLIENT_ID SECRET_KEY RECORD_ID".into()
    }

    // Non-mutating live checks. Print only test outcomes, never payloads/keys.
    fn lifecycle(socket: &str, client_id: &str, key_path: &str, mode: &str) -> Result<(), String> {
        use std::time::{Duration, Instant};
        if !matches!(mode, "challenge-expiry" | "session-expiry" | "hold") {
            return Err("Lifecycle mode must be challenge-expiry, session-expiry, or hold".into());
        }
        let mut connection = Connection::open(socket)?;
        let challenge = connection.request(json!({"type":"begin_auth", "client_id":client_id}))?;
        ensure_status(&challenge, "challenge")?;
        let bytes: [u8; 32] = B64
            .decode(challenge["challenge"].as_str().ok_or("Missing challenge")?)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "Invalid challenge length")?;
        let key_bytes = Zeroizing::new(fs::read(key_path).map_err(|e| e.to_string())?);
        let dsa = Sig::new(Algorithm::MlDsa65).map_err(|e| e.to_string())?;
        let key = dsa
            .secret_key_from_bytes(&key_bytes)
            .ok_or("Invalid client key")?;
        let signature = dsa
            .sign(&authentication_message(client_id, &bytes), key)
            .map_err(|e| e.to_string())?;
        let auth = json!({"type":"authenticate", "client_id":client_id, "signature":B64.encode(signature.as_ref())});
        if mode == "challenge-expiry" {
            println!(
                "READY: challenge received; waiting 31 seconds before signing response delivery"
            );
            std::thread::sleep(Duration::from_secs(31));
            let response = connection.request(auth)?;
            ensure_status(&response, "error")?;
            if response.get("secret").is_some() || response.get("records").is_some() {
                return Err("Error response exposed vault contents".into());
            }
            // Prove rejection wasn't merely caused by a locked vault.
            ensure_status(
                &connection.request(json!({"type":"begin_auth", "client_id":client_id}))?,
                "challenge",
            )?;
            println!("PASS: expired challenge rejected while a fresh challenge is still available");
            return Ok(());
        }
        ensure_status(&connection.request(auth)?, "authenticated")?;
        ensure_status(&connection.request(json!({"type":"list_metadata"}))?, "ok")?;
        if mode == "hold" {
            connection
                .reader
                .get_ref()
                .set_read_timeout(Some(Duration::from_secs(120)))
                .map_err(|e| e.to_string())?;
            println!("READY: authenticated connection open; click Lock Vault or revoke this client within 120 seconds");
            let mut response = String::new();
            let count = connection
                .reader
                .read_line(&mut response)
                .map_err(|e| format!("No verified disconnect: {e}"))?;
            if count != 0 {
                return Err("Unexpected data instead of connection closure".into());
            }
            println!("PASS: previously authenticated connection received EOF from server");
            return Ok(());
        }
        println!(
            "READY: five-minute session test; keep desktop active without locking or revoking"
        );
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(305) {
            std::thread::sleep(Duration::from_secs(10));
            ensure_status(&connection.request(json!({"type":"ping"}))?, "ok")?;
        }
        let response = connection.request(json!({"type":"list_metadata"}))?;
        ensure_status(&response, "error")?;
        if response.get("records").is_some() || response.get("secret").is_some() {
            return Err("Expired session response exposed contents".into());
        }
        ensure_status(
            &connection.request(json!({"type":"begin_auth", "client_id":client_id}))?,
            "challenge",
        )?;
        println!("PASS: expired session denied metadata while vault still accepts fresh authentication challenges");
        Ok(())
    }

    fn audit(socket: &str, client_id: &str, key_path: &str) -> Result<(), String> {
        fn denied(response: &Value) -> Result<(), String> {
            ensure_status(response, "error")?;
            if response.get("secret").is_some() || response.get("records").is_some() {
                return Err("Denial response included vault contents".into());
            }
            Ok(())
        }
        let dsa = Sig::new(Algorithm::MlDsa65).map_err(|e| e.to_string())?;
        let key_bytes = Zeroizing::new(fs::read(key_path).map_err(|e| e.to_string())?);
        let key = dsa
            .secret_key_from_bytes(&key_bytes)
            .ok_or("Invalid client key")?;
        let begin = json!({"type":"begin_auth", "client_id":client_id});
        let sign = |response: &Value| -> Result<String, String> {
            ensure_status(response, "challenge")?;
            let bytes: [u8; 32] = B64
                .decode(response["challenge"].as_str().ok_or("Missing challenge")?)
                .map_err(|e| e.to_string())?
                .try_into()
                .map_err(|_| "Invalid challenge length")?;
            let signature = dsa
                .sign(&authentication_message(client_id, &bytes), key)
                .map_err(|e| e.to_string())?;
            Ok(B64.encode(signature.as_ref()))
        };
        let mut first = Connection::open(socket)?;
        let signature = sign(&first.request(begin.clone())?)?;
        let auth = json!({"type":"authenticate", "client_id":client_id, "signature":signature});
        ensure_status(&first.request(auth.clone())?, "authenticated")?;
        println!("PASS: valid authentication baseline");
        denied(&first.request(auth.clone())?)?;
        println!("PASS: consumed challenge replay rejected");

        let mut second = Connection::open(socket)?;
        ensure_status(&second.request(begin.clone())?, "challenge")?;
        denied(&second.request(auth)?)?;
        println!("PASS: signature replay on a fresh connection rejected");

        let valid = sign(&second.request(begin)?)?;
        let mut altered = B64.decode(valid).map_err(|e| e.to_string())?;
        altered[0] ^= 1;
        denied(&second.request(
            json!({"type":"authenticate", "client_id":client_id, "signature":B64.encode(altered)}),
        )?)?;
        println!("PASS: altered ML-DSA signature rejected");
        denied(&second.request(json!({"type":"list_metadata"}))?)?;
        denied(&second.request(json!({"type":"get_secret", "id":1}))?)?;
        println!("PASS: unauthenticated metadata and secret requests rejected");
        denied(
            &second
                .request(json!({"type":"begin_auth", "client_id":"nonexistent-audit-client"}))?,
        )?;
        println!("PASS: unknown client rejected");

        for frame in [
            b"{not-json}\n".as_slice(),
            b"{\"type\":\"get_secret\",\"id\":\"invalid\"}\n".as_slice(),
        ] {
            let mut connection = Connection::open(socket)?;
            connection
                .writer
                .write_all(frame)
                .map_err(|e| e.to_string())?;
            denied(&connection.response()?)?;
            let mut trailing = String::new();
            if connection
                .reader
                .read_line(&mut trailing)
                .map_err(|e| e.to_string())?
                != 0
            {
                return Err("Malformed request did not close connection".into());
            }
        }
        println!("PASS: malformed JSON and invalid field type rejected; connections closed");
        let mut connection = Connection::open(socket)?;
        ensure_status(&connection.request(json!({"type":"ping"}))?, "ok")?;
        println!("PASS: server remains responsive");
        Ok(())
    }

    fn generate_keys(prefix: &str) -> Result<(), String> {
        let dsa = Sig::new(Algorithm::MlDsa65).map_err(|e| e.to_string())?;
        let (public_key, secret_key) = dsa.keypair().map_err(|e| e.to_string())?;
        let public_path = format!("{prefix}.pk");
        let secret_path = format!("{prefix}.sk");
        fs::write(&public_path, public_key.as_ref()).map_err(|e| e.to_string())?;
        let mut secret_file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&secret_path)
            .map_err(|e| e.to_string())?;
        secret_file
            .write_all(secret_key.as_ref())
            .map_err(|e| e.to_string())?;
        println!("Public key: {public_path}");
        println!("Private key: {secret_path} (mode 0600)");
        Ok(())
    }

    fn register(
        socket: &str,
        application_name: &str,
        namespace: &str,
        public_key_path: &str,
    ) -> Result<(), String> {
        let public_key = fs::read(public_key_path).map_err(|e| e.to_string())?;
        let mut connection = Connection::open(socket)?;
        let response = connection.request(json!({
            "type": "register",
            "application_name": application_name,
            "public_key": B64.encode(public_key),
            "namespace": namespace
        }))?;
        println!("{}", serde_json::to_string_pretty(&response).unwrap());
        Ok(())
    }

    fn authenticated_request(
        socket: &str,
        client_id: &str,
        secret_key_path: &str,
        request: Value,
    ) -> Result<(), String> {
        let mut connection = Connection::open(socket)?;
        let challenge_response = connection.request(json!({
            "type": "begin_auth",
            "client_id": client_id
        }))?;
        ensure_status(&challenge_response, "challenge")?;
        let challenge_b64 = challenge_response
            .get("challenge")
            .and_then(Value::as_str)
            .ok_or("Challenge response is missing challenge bytes")?;
        let challenge = B64.decode(challenge_b64).map_err(|e| e.to_string())?;
        let challenge: [u8; 32] = challenge
            .try_into()
            .map_err(|_| "Challenge must be 32 bytes")?;

        let mut secret_key_bytes =
            Zeroizing::new(fs::read(Path::new(secret_key_path)).map_err(|e| e.to_string())?);
        let dsa = Sig::new(Algorithm::MlDsa65).map_err(|e| e.to_string())?;
        let secret_key = dsa
            .secret_key_from_bytes(secret_key_bytes.as_ref())
            .ok_or("Invalid ML-DSA-65 private key")?;
        let mut message = Zeroizing::new(authentication_message(client_id, &challenge));
        let signature = dsa
            .sign(message.as_ref(), secret_key)
            .map_err(|e| e.to_string())?;
        message.zeroize();
        secret_key_bytes.zeroize();

        let auth_response = connection.request(json!({
            "type": "authenticate",
            "client_id": client_id,
            "signature": B64.encode(signature.as_ref())
        }))?;
        ensure_status(&auth_response, "authenticated")?;

        let response = connection.request(request)?;
        ensure_status(&response, "ok")?;
        println!("{}", serde_json::to_string_pretty(&response).unwrap());
        Ok(())
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

    fn ensure_status(response: &Value, expected: &str) -> Result<(), String> {
        if response.get("status").and_then(Value::as_str) == Some(expected) {
            return Ok(());
        }
        Err(response
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("Unexpected IPC response")
            .to_string())
    }

    struct Connection {
        writer: UnixStream,
        reader: BufReader<UnixStream>,
    }

    impl Connection {
        fn open(path: &str) -> Result<Self, String> {
            let writer = UnixStream::connect(path).map_err(|e| e.to_string())?;
            writer
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .map_err(|e| e.to_string())?;
            writer
                .set_write_timeout(Some(std::time::Duration::from_secs(5)))
                .map_err(|e| e.to_string())?;
            let reader = BufReader::new(writer.try_clone().map_err(|e| e.to_string())?);
            Ok(Self { writer, reader })
        }

        fn request(&mut self, request: Value) -> Result<Value, String> {
            serde_json::to_writer(&mut self.writer, &request).map_err(|e| e.to_string())?;
            self.writer.write_all(b"\n").map_err(|e| e.to_string())?;
            self.writer.flush().map_err(|e| e.to_string())?;
            self.response()
        }

        fn response(&mut self) -> Result<Value, String> {
            let mut response = String::new();
            self.reader
                .read_line(&mut response)
                .map_err(|e| e.to_string())?;
            if response.is_empty() {
                return Err("IPC server closed the connection".into());
            }
            serde_json::from_str(&response).map_err(|e| e.to_string())
        }
    }
}

#[cfg(unix)]
fn main() {
    if let Err(error) = unix_client::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
