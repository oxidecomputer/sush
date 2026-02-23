//! Simple SQLite schema migrations.
//!
//! Migrations need not be idempotent.

use std::ops::Range;
use std::path::Path;

use chrono::Utc;
use rusqlite::config::DbConfig;
use rusqlite::{Connection, OptionalExtension as _, Transaction};
use thiserror::Error;

pub type SchemaVersion = usize;
pub const SCHEMA_VERSION: SchemaVersion = SCHEMA.len();
pub const SCHEMA: &[&str] = &[
    include_str!("../schema/0_migrations.sql"),
    include_str!("../schema/1_certs.sql"),
    include_str!("../schema/2_jobs.sql"),
    include_str!("../schema/3_hashes.sql"),
    include_str!("../schema/4_index_time_started.sql"),
    // Add new migrations here.
];

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("schema is newer than latest known version: {0} > {SCHEMA_VERSION}")]
    FutureSchemaVersion(SchemaVersion),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
}

pub fn open_database<P>(path: P) -> Result<Connection, DatabaseError>
where
    P: AsRef<Path>,
{
    let mut db = Connection::open(path)?;
    init_database(&mut db)?;
    Ok(db)
}

pub fn open_database_in_memory() -> Result<Connection, DatabaseError> {
    let mut db = Connection::open_in_memory()?;
    init_database(&mut db)?;
    Ok(db)
}

pub fn init_database(db: &mut Connection) -> Result<SchemaVersion, DatabaseError> {
    db.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY, true)?;
    let txn = db.transaction()?;
    let version = init_schema(&txn)?;
    txn.commit()?;
    Ok(version)
}

pub fn init_schema(txn: &Transaction) -> Result<SchemaVersion, DatabaseError> {
    if let Some(schema_version) = schema_version(txn) {
        if schema_version > SCHEMA_VERSION {
            Err(DatabaseError::FutureSchemaVersion(schema_version))
        } else if schema_version == SCHEMA_VERSION {
            Ok(SCHEMA_VERSION)
        } else {
            apply_migrations(txn, schema_version + 1..SCHEMA_VERSION)?;
            Ok(SCHEMA_VERSION)
        }
    } else {
        apply_migrations(txn, 0..SCHEMA_VERSION)?;
        Ok(SCHEMA_VERSION)
    }
}

pub fn schema_version(txn: &Transaction) -> Option<SchemaVersion> {
    txn.query_one(
        "SELECT MAX(version) FROM migrations",
        (),
        |row| -> Result<SchemaVersion, _> { row.get(0) },
    )
    .optional()
    .unwrap_or(None)
}

fn apply_migrations(
    txn: &Transaction,
    versions: Range<SchemaVersion>,
) -> Result<(), DatabaseError> {
    for v in versions {
        apply_migration(txn, v)?;
    }
    Ok(())
}

fn apply_migration(txn: &Transaction, version: SchemaVersion) -> Result<(), DatabaseError> {
    txn.execute_batch(SCHEMA[version])?;
    txn.execute(
        "INSERT INTO migrations(version, applied) \
         VALUES(?1, ?2) \
         ON CONFLICT DO NOTHING",
        (version, Utc::now()),
    )?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn init() {
        let mut db = Connection::open_in_memory().unwrap();
        assert_eq!(init_database(&mut db).unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn migrations() {
        let mut db = Connection::open_in_memory().unwrap();
        let txn = db.transaction().unwrap();
        assert!(schema_version(&txn).is_none());
        for v in 0..SCHEMA_VERSION {
            apply_migration(&txn, v).unwrap();
            assert_eq!(schema_version(&txn), Some(v));
        }
    }
}
