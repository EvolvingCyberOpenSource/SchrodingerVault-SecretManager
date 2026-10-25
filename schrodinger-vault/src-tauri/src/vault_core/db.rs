use rusqlite::{params, Connection, Result, Row};
use std::path::PathBuf;
use tauri::{path::BaseDirectory, Manager};

/// Resolves the full path to the `vault.sqlite` database file.
///
/// # Arguments
/// * `app` - a handle to the running Tauri application
///
/// # Returns
/// The path to where the database file will be located on the system
pub fn db_path(app: &tauri::AppHandle) -> PathBuf {
    app.path()
        .resolve("vault.sqlite", BaseDirectory::AppData)
        .expect("failed to resolve AppData path")
}

/// Return structs for query functions
// TODO: move into separate file in utils folder
#[derive(serde::Serialize)]
pub struct EntryListItem {
    pub id: i64,
    pub label: String,
    pub username: String,
    pub notes: Option<String>,
    pub namespace: String,
    pub record_type: String,
    pub created_at: String,
    pub updated_at: String,
}

pub struct NewEntry<'a> {
    pub label: &'a str,
    pub username: &'a str,
    pub notes: Option<&'a str>,
    pub namespace: &'a str,
    pub record_type: &'a str,
    pub nonce: &'a [u8],
    pub ciphertext: &'a [u8],
    pub tag: &'a [u8],
}

#[derive(serde::Serialize)]
pub struct EncEntry {
    pub label: String,
    pub username: String,
    pub namespace: String,
    pub record_type: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

#[derive(serde::Serialize)]
pub struct IpcEntryMetadata {
    pub id: i64,
    pub name: String,
    pub record_type: String,
    pub namespace: String,
}

/// open the database and create schema if needed returning a connection object
pub fn open_and_init(app: &tauri::AppHandle) -> Result<Connection> {
    let path = db_path(app);

    // TODO: can get rid of this debug in the future
    println!("SQLite DB located at: {}", path.display());

    // saftey check to ensure the directory where the db will be exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    // creates the database file (if it doesn't exist)
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "secure_delete", "ON")?;

    // Good defaults for desktop apps (requires rusqlite >= 0.29)
    let _ = conn.pragma_update(None, "journal_mode", &"WAL");
    let _ = conn.pragma_update(None, "synchronous", &"FULL");

    // Needed by create_vault()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )",
        [],
    )?;

    // TODO: remove later and replace with correct schema in another function and call that here instead
    conn.execute(
        "CREATE TABLE IF NOT EXISTS entries (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            label       TEXT NOT NULL UNIQUE,
            username    TEXT NOT NULL,
            notes       TEXT,
            nonce       BLOB NOT NULL,
            ciphertext  BLOB NOT NULL,
            tag         BLOB NOT NULL,
            created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        )",
        [],
    )?;

    // Migrate existing vaults without discarding their encrypted records.
    ensure_column(
        &conn,
        "entries",
        "namespace",
        "TEXT NOT NULL DEFAULT 'default'",
    )?;
    ensure_column(
        &conn,
        "entries",
        "record_type",
        "TEXT NOT NULL DEFAULT 'generic'",
    )?;

    // The client identifier is the lookup key. The authorization payload
    // (application name, ML-DSA public key, namespace, and revocation flag)
    // is encrypted and authenticated with the active vault key.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS client_authorizations (
            client_id   TEXT PRIMARY KEY,
            nonce       BLOB NOT NULL,
            ciphertext  BLOB NOT NULL,
            tag         BLOB NOT NULL,
            created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        )",
        [],
    )?;

    // Helpful index for listing/search
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_entries_label ON entries(label)",
        [],
    )?;

    super::binding::init(&conn)?;
    Ok(conn)
}

fn ensure_column(conn: &Connection, table: &str, column: &str, definition: &str) -> Result<()> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for name in names {
        if name? == column {
            return Ok(());
        }
    }

    conn.execute(
        &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
        [],
    )?;
    Ok(())
}

/// Query functions for entries table.
///
/// # Arguments
/// * `conn` - connection to the SQLite database
///
/// # Returns
/// A vector of `EntryListItem` structs representing all entries in the entry table
pub fn list_entries(conn: &Connection) -> Result<Vec<EntryListItem>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT id, label, username, notes, namespace, record_type, created_at, updated_at
        FROM entries
        ORDER BY label COLLATE NOCASE
        "#,
    )?;
    let rows = stmt.query_map([], |row| row_to_list_item(row))?;

    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

// Helper, converts db row into EntryListItem
fn row_to_list_item(row: &Row) -> rusqlite::Result<EntryListItem> {
    Ok(EntryListItem {
        id: row.get(0)?,
        label: row.get(1)?,
        username: row.get(2)?,
        notes: row.get(3)?,
        namespace: row.get(4)?,
        record_type: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
    })
}

pub fn add_entry(conn: &Connection, e: NewEntry) -> Result<EntryListItem> {
    conn.execute(
        r#"
        INSERT INTO entries
            (label, username, notes, namespace, record_type, nonce, ciphertext, tag)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
        params![
            e.label,
            e.username,
            e.notes,
            e.namespace,
            e.record_type,
            e.nonce,
            e.ciphertext,
            e.tag
        ],
    )?;

    // Prepare to return added entry so it can be displayed in UI immediately
    let id = conn.last_insert_rowid();
    let mut stmt = conn.prepare(
        r#"
        SELECT id, label, username, notes, namespace, record_type, created_at, updated_at
        FROM entries
        WHERE id = ?1
        "#,
    )?;

    let item = stmt.query_row(params![id], |row| row_to_list_item(row))?;
    Ok(item)
}

pub fn update_entry(conn: &Connection, id: i64, e: NewEntry) -> Result<Option<EntryListItem>> {
    let changed = conn.execute(
        r#"
        UPDATE entries
        SET label = ?1,
            username = ?2,
            notes = ?3,
            namespace = ?4,
            record_type = ?5,
            nonce = ?6,
            ciphertext = ?7,
            tag = ?8,
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
        WHERE id = ?9
        "#,
        params![
            e.label,
            e.username,
            e.notes,
            e.namespace,
            e.record_type,
            e.nonce,
            e.ciphertext,
            e.tag,
            id
        ],
    )?;

    if changed == 0 {
        return Ok(None);
    }

    let mut stmt = conn.prepare(
        r#"
        SELECT id, label, username, notes, namespace, record_type, created_at, updated_at
        FROM entries
        WHERE id = ?1
        "#,
    )?;
    let item = stmt.query_row(params![id], |row| row_to_list_item(row))?;
    Ok(Some(item))
}

pub fn delete_entry(conn: &Connection, id: i64) -> Result<usize> {
    conn.execute("DELETE FROM entries WHERE id = ?1", params![id])
}

pub fn get_entry_encrypted(conn: &Connection, id: i64) -> Result<Option<EncEntry>> {
    let mut stmt = conn.prepare(
        "SELECT label, username, namespace, record_type, nonce, ciphertext, tag
         FROM entries WHERE id = ?1",
    )?;
    let mut rows = stmt.query(params![id])?;
    if let Some(row) = rows.next()? {
        Ok(Some(EncEntry {
            label: row.get(0)?,
            username: row.get(1)?,
            namespace: row.get(2)?,
            record_type: row.get(3)?,
            nonce: row.get(4)?,
            ciphertext: row.get(5)?,
            tag: row.get(6)?,
        }))
    } else {
        Ok(None)
    }
}

pub fn list_entries_in_namespace(
    conn: &Connection,
    namespace: &str,
) -> Result<Vec<IpcEntryMetadata>> {
    let mut stmt = conn.prepare(
        "SELECT id, label, record_type, namespace
         FROM entries
         WHERE namespace = ?1
         ORDER BY label COLLATE NOCASE",
    )?;
    let rows = stmt.query_map([namespace], |row| {
        Ok(IpcEntryMetadata {
            id: row.get(0)?,
            name: row.get(1)?,
            record_type: row.get(2)?,
            namespace: row.get(3)?,
        })
    })?;

    let mut entries = Vec::new();
    for row in rows {
        entries.push(row?);
    }
    Ok(entries)
}

pub fn set_entry_scope(
    conn: &Connection,
    id: i64,
    namespace: &str,
    record_type: &str,
) -> Result<usize> {
    conn.execute(
        "UPDATE entries
         SET namespace = ?1, record_type = ?2,
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE id = ?3",
        params![namespace, record_type, id],
    )
}
