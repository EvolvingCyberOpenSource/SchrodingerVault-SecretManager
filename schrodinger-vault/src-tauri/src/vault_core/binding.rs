//! Authenticated binding between a record's routing metadata and ciphertext.
//! Older records without bindings remain desktop-readable but are IPC-ineligible
//! until explicitly saved by the user. Never silently trust/migrate their scope.
use super::db::{self, EncEntry};
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce, Tag,
};
use hkdf::Hkdf;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::Sha256;
use zeroize::Zeroizing;

pub fn init(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS record_bindings (
        record_id INTEGER PRIMARY KEY, nonce BLOB NOT NULL, tag BLOB NOT NULL);",
    )
}

fn cipher(key: &[u8; 32]) -> Result<Aes256Gcm, String> {
    let mut subkey = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, key)
        .expand(b"SV-RECORD-BINDING-KEY-v1", subkey.as_mut())
        .map_err(|_| "binding derivation failed")?;
    Aes256Gcm::new_from_slice(subkey.as_ref()).map_err(|_| "binding cipher failed".into())
}

fn aad(id: i64, entry: &EncEntry) -> Vec<u8> {
    let mut value = b"SV-RECORD-BINDING-v1".to_vec();
    value.extend_from_slice(&id.to_be_bytes());
    for field in [
        entry.label.as_bytes(),
        entry.namespace.as_bytes(),
        entry.record_type.as_bytes(),
        entry.nonce.as_slice(),
        entry.ciphertext.as_slice(),
        entry.tag.as_slice(),
    ] {
        value.extend_from_slice(&(field.len() as u64).to_be_bytes());
        value.extend_from_slice(field);
    }
    value
}

pub fn seal(conn: &Connection, id: i64, key: &[u8; 32]) -> Result<(), String> {
    let entry = db::get_entry_encrypted(conn, id)
        .map_err(|e| e.to_string())?
        .ok_or("Missing record")?;
    let mut nonce = [0; 12];
    rand::rng().fill_bytes(&mut nonce);
    let tag = cipher(key)?
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad(id, &entry), &mut [])
        .map_err(|_| "binding authentication failed")?;
    conn.execute(
        "INSERT OR REPLACE INTO record_bindings(record_id,nonce,tag) VALUES (?1,?2,?3)",
        params![id, nonce.as_slice(), tag.as_slice()],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn verify(conn: &Connection, id: i64, entry: &EncEntry, key: &[u8; 32]) -> Result<(), String> {
    let binding: Option<(Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT nonce,tag FROM record_bindings WHERE record_id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let (nonce, tag) = binding.ok_or("Record requires explicit desktop save before IPC access")?;
    if nonce.len() != 12 || tag.len() != 16 {
        return Err("Invalid record binding".into());
    }
    cipher(key)?
        .decrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            &aad(id, entry),
            &mut [],
            Tag::from_slice(&tag),
        )
        .map_err(|_| "Record metadata or ciphertext was modified".into())
}

pub fn bound_ids(conn: &Connection, key: &[u8; 32]) -> Result<Vec<i64>, String> {
    let mut stmt = conn
        .prepare("SELECT record_id FROM record_bindings")
        .map_err(|e| e.to_string())?;
    let ids = stmt
        .query_map([], |r| r.get::<_, i64>(0))
        .map_err(|e| e.to_string())?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())?;
    for id in &ids {
        if let Some(entry) = db::get_entry_encrypted(conn, *id).map_err(|e| e.to_string())? {
            verify(conn, *id, &entry, key)?;
        }
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE entries(id INTEGER PRIMARY KEY,label TEXT,username TEXT,
            namespace TEXT,record_type TEXT,nonce BLOB,ciphertext BLOB,tag BLOB);
            INSERT INTO entries VALUES(1,'TOKEN','','app-a','api-token',X'01',X'0203',X'04');",
        )
        .unwrap();
        init(&conn).unwrap();
        conn
    }
    #[test]
    fn missing_binding_is_denied() {
        let conn = fixture();
        let entry = db::get_entry_encrypted(&conn, 1).unwrap().unwrap();
        assert!(verify(&conn, 1, &entry, &[7; 32]).is_err());
    }
    #[test]
    fn metadata_and_ciphertext_edits_are_denied() {
        for sql in [
            "UPDATE entries SET label='RENAMED'",
            "UPDATE entries SET namespace='app-b'",
            "UPDATE entries SET record_type='other'",
            "UPDATE entries SET nonce=X'05'",
            "UPDATE entries SET ciphertext=X'0607'",
            "UPDATE entries SET tag=X'08'",
            "UPDATE record_bindings SET tag=zeroblob(16)",
            "UPDATE record_bindings SET nonce=zeroblob(12)",
            "DELETE FROM record_bindings",
        ] {
            let conn = fixture();
            seal(&conn, 1, &[7; 32]).unwrap();
            verify(
                &conn,
                1,
                &db::get_entry_encrypted(&conn, 1).unwrap().unwrap(),
                &[7; 32],
            )
            .unwrap();
            conn.execute(sql, []).unwrap();
            assert!(
                verify(
                    &conn,
                    1,
                    &db::get_entry_encrypted(&conn, 1).unwrap().unwrap(),
                    &[7; 32]
                )
                .is_err(),
                "{sql}"
            );
        }
    }
    #[test]
    fn record_identity_and_key_are_bound() {
        let conn = fixture();
        seal(&conn, 1, &[7; 32]).unwrap();
        let entry = db::get_entry_encrypted(&conn, 1).unwrap().unwrap();
        assert!(verify(&conn, 1, &entry, &[8; 32]).is_err());
        conn.execute("UPDATE record_bindings SET record_id=2", [])
            .unwrap();
        assert!(verify(&conn, 2, &entry, &[7; 32]).is_err());
    }
    #[test]
    fn rebinding_after_key_rotation_accepts_only_new_key() {
        let conn = fixture();
        seal(&conn, 1, &[7; 32]).unwrap();
        assert_eq!(bound_ids(&conn, &[7; 32]).unwrap(), vec![1]);
        seal(&conn, 1, &[8; 32]).unwrap();
        let entry = db::get_entry_encrypted(&conn, 1).unwrap().unwrap();
        verify(&conn, 1, &entry, &[8; 32]).unwrap();
        assert!(verify(&conn, 1, &entry, &[7; 32]).is_err());
    }
}
