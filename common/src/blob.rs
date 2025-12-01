//! SQLite BLOB I/O.

use std::fs::File;
use std::io::{Seek as _, copy};
use std::ops::Range;

use rusqlite::blob::{Blob, ZeroBlob};
use rusqlite::limits::Limit;
use rusqlite::{Connection, Name, ToSql};
use thiserror::Error;

/// What went wrong reading from or writing to a BLOB.
#[derive(Debug, Error)]
pub enum BlobError {
    #[error("file is too large for a BLOB")]
    FileTooLarge,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

/// Look up a BLOB by (single-column) key and open it for reading.
pub fn get_blob<'c, N, T>(
    db: &'c Connection,
    table: N,
    blob_column: N,
    key_column: N,
    key: T,
) -> Result<Blob<'c>, BlobError>
where
    N: Name,
    T: ToSql,
{
    let db_name = db.db_name(0)?;
    let row_id = db.query_one(
        &format!(
            "SELECT rowid FROM {} WHERE {} = ?1",
            table.as_cstr()?.to_string_lossy(),
            key_column.as_cstr()?.to_string_lossy(),
        ),
        [key],
        |row| -> Result<i64, _> { row.get(0) },
    )?;
    Ok(db.blob_open(db_name.as_str(), table, blob_column, row_id, true)?)
}

/// Update a BLOB size by (single-column) key and open it for writing.
pub fn set_blob_size<'c, N, T>(
    db: &'c Connection,
    table: N,
    blob_column: N,
    key_column: N,
    key: T,
    size: i32,
) -> Result<Blob<'c>, BlobError>
where
    N: Name,
    T: ToSql,
{
    let db_name = db.db_name(0)?;
    let row_id = db.query_one(
        &format!(
            "UPDATE {} SET {} = ?2 WHERE {} = ?1 RETURNING rowid",
            table.as_cstr()?.to_string_lossy(),
            blob_column.as_cstr()?.to_string_lossy(),
            key_column.as_cstr()?.to_string_lossy(),
        ),
        (key, ZeroBlob(size)),
        |row| -> Result<i64, _> { row.get(0) },
    )?;
    Ok(db.blob_open(db_name.as_str(), table, blob_column, row_id, false)?)
}

/// Read a chunk of a BLOB. May return a vector shorter than the requested
/// `range` if it falls partly outside the extent of `blob`.
pub fn read_blob_chunk(blob: &Blob, range: Range<i32>) -> Result<Vec<u8>, BlobError> {
    let start = range.start as usize;
    let len = range.len().min(blob.len().saturating_sub(start));
    let mut buf = vec![0; len];
    blob.read_at_exact(&mut buf, start)?;
    Ok(buf)
}

/// Copy the contents of `file` to a blob looked up by `key`.
pub fn read_blob_from_file<'c, N, T>(
    file: &mut File,
    db: &'c Connection,
    table: N,
    blob_column: N,
    key_column: N,
    key: T,
) -> Result<Blob<'c>, BlobError>
where
    N: Name,
    T: ToSql,
{
    let limit = blob_limit(db)?;
    let len = file_len(file, limit)?;
    let mut blob = set_blob_size(db, table, blob_column, key_column, key, len)?;
    file.rewind()?;
    copy(file, &mut blob)?;
    Ok(blob)
}

/// Copy the contents of `blob` to `file`.
pub fn write_blob_to_file(blob: &mut Blob, file: &mut File) -> Result<u64, BlobError> {
    blob.rewind()?;
    Ok(copy(blob, file)?)
}

/// Return the current maximum size of a string or BLOB.
pub fn blob_limit(db: &Connection) -> Result<i32, BlobError> {
    Ok(db.limit(Limit::SQLITE_LIMIT_LENGTH)?)
}

/// Return the length in bytes of `file`, or an error if it is too
/// big to fit in a BLOB.
pub fn file_len(file: &File, limit: i32) -> Result<i32, BlobError> {
    let len = file.metadata()?.len();
    if len < limit as u64 {
        Ok(len as i32)
    } else {
        Err(BlobError::FileTooLarge)
    }
}

#[cfg(test)]
mod test {
    use std::io::{Write as _, read_to_string};

    use rusqlite::Connection;
    use tempfile::tempfile;

    use super::*;

    #[test]
    fn blob() {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz";

        let mut db = Connection::open_in_memory().unwrap();
        let txn = db.transaction().unwrap();
        txn.execute_batch(
            "CREATE TABLE test(key INTEGER, content BLOB); \
             INSERT INTO test VALUES(0, ZEROBLOB(0));",
        )
        .unwrap();

        let mut input = tempfile().unwrap();
        input.write_all(ALPHABET).unwrap();
        input.flush().unwrap();

        let mut blob =
            read_blob_from_file(&mut input, &txn, c"test", c"content", c"key", 0).unwrap();
        assert_eq!(blob.len(), 26);
        blob.rewind().unwrap();
        assert_eq!(read_to_string(&mut blob).unwrap().as_bytes(), ALPHABET);

        let mut output = tempfile().unwrap();
        assert_eq!(write_blob_to_file(&mut blob, &mut output).unwrap(), 26);
        output.rewind().unwrap();
        assert_eq!(read_to_string(output).unwrap().as_bytes(), ALPHABET);

        let blob = get_blob(&txn, c"test", c"content", c"key", 0).unwrap();
        assert_eq!(read_blob_chunk(&blob, 0..100).unwrap(), ALPHABET);
        assert_eq!(read_blob_chunk(&blob, 0..26).unwrap(), ALPHABET);
        assert_eq!(read_blob_chunk(&blob, 0..6).unwrap(), b"abcdef");
        assert_eq!(read_blob_chunk(&blob, 0..3).unwrap(), b"abc");
        assert_eq!(read_blob_chunk(&blob, 3..6).unwrap(), b"def");
        assert_eq!(read_blob_chunk(&blob, 24..26).unwrap(), b"yz");
        assert_eq!(read_blob_chunk(&blob, 25..26).unwrap(), b"z");
        assert_eq!(read_blob_chunk(&blob, 26..26).unwrap(), b"");
        assert_eq!(read_blob_chunk(&blob, 26..100).unwrap(), b"");
        assert_eq!(read_blob_chunk(&blob, -100..0).unwrap(), b"");
    }
}
