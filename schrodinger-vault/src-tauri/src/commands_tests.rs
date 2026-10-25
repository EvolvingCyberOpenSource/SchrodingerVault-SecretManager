use super::*;
use std::{thread, time::Duration};
use zeroize::Zeroize;

fn combined_fixture() -> (Connection, SecretString, [u8; 32], [u8; 32]) {
    let (conn, password) = verifier_conn("synthetic combined verifier password");
    let salt: String = conn
        .query_row("SELECT value FROM meta WHERE key='salt_pw'", [], |r| {
            r.get(0)
        })
        .unwrap();
    let k1 = derive_k1_with_kdf(
        &password,
        &B64.decode(salt).unwrap(),
        "pbkdf2-hmac-sha256",
        Some(default_kdf_params("pbkdf2-hmac-sha256")),
    )
    .unwrap();
    let ss = [0x78; 32];
    let salt_kdf = [0x56; 32];
    let key = derive_vault_key(&k1, &salt_kdf, &ss).unwrap();
    conn.execute(
        "INSERT INTO meta VALUES ('salt_kdf',?1)",
        [B64.encode(salt_kdf)],
    )
    .unwrap();
    let (nonce, ct) = new_verifier(&key).unwrap();
    store_verifier(&conn, &nonce, &ct).unwrap();
    (conn, password, ss, k1)
}

#[test]
fn combined_verifier_requires_password_and_device_secret() {
    let (conn, password, ss, k1) = combined_fixture();
    assert!(verify_master_password(&conn, &password, &ss).is_ok());
    assert!(verify_master_password(
        &conn,
        &SecretString::from("wrong synthetic password".to_string()),
        &ss
    )
    .is_err());
    assert!(verify_master_password(&conn, &password, &[0x79; 32]).is_err());
    assert!(verify_verifier(&conn, &k1, 2).is_err());
}

#[test]
fn combined_verifier_rejects_downgrade_unknown_version_and_bad_nonce() {
    let (conn, password, ss, _) = combined_fixture();
    conn.execute("UPDATE meta SET value='1' WHERE key='verifier_version'", [])
        .unwrap();
    assert!(verify_master_password(&conn, &password, &ss).is_err());
    conn.execute("DELETE FROM meta WHERE key='verifier_version'", [])
        .unwrap();
    assert!(verify_master_password(&conn, &password, &ss).is_err());
    conn.execute("INSERT INTO meta VALUES ('verifier_version','99')", [])
        .unwrap();
    assert!(verifier_version(&conn).is_err());
    conn.execute("UPDATE meta SET value='2' WHERE key='verifier_version'", [])
        .unwrap();
    conn.execute(
        "UPDATE meta SET value='AA==' WHERE key='verifier_nonce'",
        [],
    )
    .unwrap();
    assert!(verify_master_password(&conn, &password, &ss).is_err());
}

#[test]
fn combined_verifier_rejects_ciphertext_tampering_and_old_key_after_replacement() {
    let (conn, password, ss, k1) = combined_fixture();
    let old_key = derive_vault_key(&k1, &[0x56; 32], &ss).unwrap();
    let ct: String = conn
        .query_row("SELECT value FROM meta WHERE key='verifier_ct'", [], |r| {
            r.get(0)
        })
        .unwrap();
    let mut bytes = B64.decode(ct).unwrap();
    bytes[0] ^= 1;
    conn.execute(
        "UPDATE meta SET value=?1 WHERE key='verifier_ct'",
        [B64.encode(bytes)],
    )
    .unwrap();
    assert!(verify_master_password(&conn, &password, &ss).is_err());
    let new_key = [0xAB; 32];
    let (nonce, ct) = new_verifier(&new_key).unwrap();
    store_verifier(&conn, &nonce, &ct).unwrap();
    assert!(verify_verifier(&conn, &new_key, 2).is_ok());
    assert!(verify_verifier(&conn, &old_key, 2).is_err());
}

#[test]
fn legacy_verifier_migration_rolls_back_on_signing_failure() {
    let (mut conn, password) = verifier_conn("migration synthetic password");
    for name in ["salt_kdf", "pk_kem", "ct_kem"] {
        conn.execute("INSERT INTO meta VALUES (?1,'synthetic')", [name])
            .unwrap();
    }
    assert!(migrate_legacy_verifier(&mut conn, &[0x55; 32], |_| Err(
        "injected signing failure".into()
    ))
    .is_err());
    assert_eq!(verifier_version(&conn).unwrap(), 1);
    assert!(verify_master_password(&conn, &password, &[0u8; 32]).is_ok());
}

#[test]
fn legacy_verifier_migration_persists_and_replaces_password_only_check() {
    let (source, password) = verifier_conn("migration synthetic password");
    let path = std::env::temp_dir().join(format!(
        "sv-verifier-test-{}-{}.sqlite",
        std::process::id(),
        rand::random::<u64>()
    ));
    let mut conn = Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL); CREATE TABLE test_records(value BLOB);").unwrap();
    let rows: Vec<(String, String)> = source
        .prepare("SELECT key,value FROM meta")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for (k, v) in rows {
        conn.execute("INSERT INTO meta VALUES (?1,?2)", params![k, v])
            .unwrap();
    }
    let old_ct: String = conn
        .query_row("SELECT value FROM meta WHERE key='verifier_ct'", [], |r| {
            r.get(0)
        })
        .unwrap();
    let salt: String = conn
        .query_row("SELECT value FROM meta WHERE key='salt_pw'", [], |r| {
            r.get(0)
        })
        .unwrap();
    let k1 = derive_k1_with_kdf(
        &password,
        &B64.decode(salt).unwrap(),
        "pbkdf2-hmac-sha256",
        Some(default_kdf_params("pbkdf2-hmac-sha256")),
    )
    .unwrap();
    let ss = [0x71; 32];
    let key = derive_vault_key(&k1, &[0x56; 32], &ss).unwrap();
    conn.execute(
        "INSERT INTO meta VALUES ('salt_kdf',?1)",
        [B64.encode([0x56; 32])],
    )
    .unwrap();
    for name in ["pk_kem", "ct_kem"] {
        conn.execute("INSERT INTO meta VALUES (?1,'synthetic')", [name])
            .unwrap();
    }
    conn.execute(
        "INSERT INTO test_records VALUES (?1)",
        [b"unchanged synthetic encrypted record".as_slice()],
    )
    .unwrap();
    oqs::init();
    let dsa = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65).unwrap();
    let (pk, sk) = dsa.keypair().unwrap();
    migrate_legacy_verifier(&mut conn, &key, |input| {
        use sha2::Digest;
        assert!(input.ends_with(VERIFIER_MANIFEST_CONTEXT));
        let hash = Sha256::digest(input.as_bytes());
        let sig = dsa.sign(&hash, &sk).unwrap();
        dsa.verify(&hash, &sig, &pk).unwrap();
        Ok((B64.encode(hash), B64.encode(sig.as_ref())))
    })
    .unwrap();
    drop(conn);
    let conn = Connection::open(&path).unwrap();
    assert_eq!(verifier_version(&conn).unwrap(), 2);
    assert!(verify_master_password(&conn, &password, &ss).is_ok());
    assert!(verify_verifier(&conn, &k1, 1).is_err());
    let record: Vec<u8> = conn
        .query_row("SELECT value FROM test_records", [], |r| r.get(0))
        .unwrap();
    assert_eq!(record, b"unchanged synthetic encrypted record");
    assert!(!fs::read(&path)
        .unwrap()
        .windows(old_ct.len())
        .any(|w| w == old_ct.as_bytes()));
    drop(conn);
    fs::remove_file(path).unwrap();
}

#[test]
fn device_recovery_requires_keystore_and_matching_kem_key() {
    oqs::init();
    let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem768).unwrap();
    let (pk, sk) = kem.keypair().unwrap();
    let (ct, ss) = kem.encapsulate(&pk).unwrap();
    let path = std::env::temp_dir().join(format!(
        "sv-device-test-{}-{}.key",
        std::process::id(),
        rand::random::<u64>()
    ));
    assert!(decapsulate_device_secret(ct.as_ref(), &path).is_err());
    write_secret_key_secure(&path, sk.as_ref()).unwrap();
    let recovered = decapsulate_device_secret(ct.as_ref(), &path).unwrap();
    assert_eq!(recovered.as_slice(), ss.as_ref());
    let (_, wrong_sk) = kem.keypair().unwrap();
    write_secret_key_secure(&path, wrong_sk.as_ref()).unwrap();
    let wrong_ss = decapsulate_device_secret(ct.as_ref(), &path).unwrap();
    assert_ne!(recovered, wrong_ss);
    fs::remove_file(path).unwrap();
}

fn verifier_conn_with_kdf(
    password: &str,
    kdf: &str,
    kdf_params: &'static str,
) -> (Connection, SecretString) {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    conn.execute(
        "CREATE TABLE meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )",
        [],
    )
    .expect("create meta table");

    let mut salt_pw = [0u8; 32];
    rng().fill_bytes(&mut salt_pw);
    let password = SecretString::from(password.to_string());
    let k1 = derive_k1_with_kdf(&password, &salt_pw, kdf, Some(kdf_params)).expect("derive k1");

    let cipher = Aes256Gcm::new_from_slice(&k1).expect("cipher init");
    let mut verifier_nonce = [0u8; 12];
    rng().fill_bytes(&mut verifier_nonce);
    let verifier_ct = cipher
        .encrypt(&verifier_nonce.into(), b"vault-ok".as_ref())
        .expect("encrypt verifier");

    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('salt_pw', ?1)",
        [B64.encode(salt_pw)],
    )
    .expect("insert salt_pw");
    conn.execute("INSERT INTO meta (key, value) VALUES ('kdf', ?1)", [kdf])
        .expect("insert kdf");
    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('kdf_params', ?1)",
        [kdf_params],
    )
    .expect("insert kdf_params");
    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('verifier_nonce', ?1)",
        [B64.encode(verifier_nonce)],
    )
    .expect("insert verifier_nonce");
    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('verifier_ct', ?1)",
        [B64.encode(verifier_ct)],
    )
    .expect("insert verifier_ct");

    (conn, password)
}

fn verifier_conn(password: &str) -> (Connection, SecretString) {
    verifier_conn_with_kdf(
        password,
        "pbkdf2-hmac-sha256",
        r#"{"iterations":310000,"out":32,"algo":"sha256"}"#,
    )
}

#[test]
fn wipe_secret_overwrites_buffer() {
    let mut buf = [0xAAu8; 16];
    wipe_secret(&mut buf);
    assert!(buf.iter().all(|&b| b == 0));
}

#[test]
fn aes_key_install_and_zeroize() {
    let key = [0xABu8; 32];
    install_aes_key(&key).expect("install key");

    {
        let guard = VAULT_AES_KEY.read().unwrap();
        assert!(guard.is_some());
    }

    zeroize_aes_key().expect("wipe key");

    {
        let guard = VAULT_AES_KEY.read().unwrap();
        assert!(guard.is_none());
    }
}

#[test]
fn k1_and_ss_zeroized_after_use() {
    let mut k1 = [0x11u8; 32];
    let mut ss = [0x22u8; 32];

    k1.zeroize();
    ss.zeroize();

    assert!(k1.iter().all(|&b| b == 0));
    assert!(ss.iter().all(|&b| b == 0));
}

#[test]
fn password_string_zeroized_after_use() {
    let password = String::from("Tr0ub4dor&3");
    let mut pw_bytes = password.into_bytes();
    assert!(pw_bytes.iter().any(|&b| b != 0));

    wipe_secret(&mut pw_bytes);
    assert!(pw_bytes.iter().all(|&b| b == 0));
}

#[test]
fn clipboard_auto_clear_mock() {
    use std::sync::{Arc, Mutex};

    let clip = Arc::new(Mutex::new(String::new()));
    *clip.lock().unwrap() = "secret123".into();

    let clip_ref = clip.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        *clip_ref.lock().unwrap() = String::new();
    });

    assert_eq!(&*clip.lock().unwrap(), "secret123");

    thread::sleep(Duration::from_millis(60));
    assert_eq!(&*clip.lock().unwrap(), "");
}

#[test]
fn repeated_aes_key_wipe_safe() {
    let key = [0xCDu8; 32];
    install_aes_key(&key).expect("install");
    zeroize_aes_key().expect("wipe #1");
    zeroize_aes_key().expect("wipe #2");
    let guard = VAULT_AES_KEY.read().unwrap();
    assert!(guard.is_none());
}

#[test]
fn master_password_verifier_accepts_correct_password() {
    let (conn, password) = verifier_conn("correct horse battery staple");
    assert!(verify_master_password(&conn, &password, &[0u8; 32]).is_ok());
}

#[test]
fn master_password_verifier_rejects_wrong_password() {
    let (conn, _) = verifier_conn("correct horse battery staple");
    let wrong_password = SecretString::from("wrong horse battery staple".to_string());
    assert!(verify_master_password(&conn, &wrong_password, &[0u8; 32]).is_err());
}

#[test]
fn argon2id_master_password_verifier_accepts_correct_password() {
    let (conn, password) = verifier_conn_with_kdf(
        "correct horse battery staple",
        "argon2id",
        r#"{"memory_kib":64,"iterations":2,"parallelism":1,"out":32,"algo":"argon2id","version":19}"#,
    );

    assert!(verify_master_password(&conn, &password, &[0u8; 32]).is_ok());
}

#[test]
fn argon2id_and_pbkdf2_derive_different_keys() {
    let password = SecretString::from("correct horse battery staple".to_string());
    let salt = [0xA5u8; 32];
    let argon2_key = derive_k1_with_kdf(
        &password,
        &salt,
        "argon2id",
        Some(r#"{"memory_kib":64,"iterations":2,"parallelism":1,"out":32,"algo":"argon2id","version":19}"#),
    )
    .expect("derive argon2id key");
    let pbkdf2_key = derive_k1_with_kdf(
        &password,
        &salt,
        "pbkdf2-hmac-sha256",
        Some(r#"{"iterations":310000,"out":32,"algo":"sha256"}"#),
    )
    .expect("derive pbkdf2 key");

    assert_ne!(argon2_key, pbkdf2_key);
}

#[test]
fn encrypted_entry_roundtrips_with_same_key() {
    let key = [0x42u8; 32];
    let sealed = encrypt_password(&key, "stored password").expect("encrypt password");

    let plaintext = decrypt_password(&key, &sealed.nonce, sealed.ciphertext, &sealed.tag)
        .expect("decrypt password");

    assert_eq!(plaintext.expose_secret(), "stored password");
}

#[test]
fn encrypted_entry_rejects_wrong_key() {
    let key = [0x42u8; 32];
    let wrong_key = [0x24u8; 32];
    let sealed = encrypt_password(&key, "stored password").expect("encrypt password");

    let result = decrypt_password(&wrong_key, &sealed.nonce, sealed.ciphertext, &sealed.tag);

    assert!(result.is_err());
}
