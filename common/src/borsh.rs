//! Borsh ser/de helpers.

use blake3::Hash;
use borsh::io::{Error, ErrorKind, Read, Result, Write};
use borsh::{BorshDeserialize as _, BorshSerialize as _};
use chrono::{DateTime, Utc};
use sled_hardware_types::BaseboardId;

/// Borsh-encode a [`Hash`] as its 32 raw bytes.
///
/// `blake3::Hash` has no native Borsh impl; the wire form is the fixed-width
/// digest with no length prefix.
pub fn borsh_ser_hash<W: Write>(hash: &Hash, writer: &mut W) -> Result<()> {
    writer.write_all(hash.as_bytes())
}

pub fn borsh_de_hash<R: Read>(reader: &mut R) -> Result<Hash> {
    let mut bytes = [0u8; blake3::OUT_LEN];
    reader.read_exact(&mut bytes)?;
    Ok(Hash::from(bytes))
}

/// Borsh-encode a [`DateTime<Utc>`] as `(timestamp_seconds, subsec_nanos)`.
///
/// `chrono` exposes no Borsh feature, so we encode the two integer components
/// directly. The nanosecond part may reach 1_999_999_999 during a leap second;
/// [`DateTime::from_timestamp`] accepts that range, so the pair round-trips.
pub fn borsh_ser_datetime<W: Write>(time: &DateTime<Utc>, writer: &mut W) -> Result<()> {
    time.timestamp().serialize(writer)?;
    time.timestamp_subsec_nanos().serialize(writer)
}

pub fn borsh_de_datetime<R: Read>(reader: &mut R) -> Result<DateTime<Utc>> {
    let secs = i64::deserialize_reader(reader)?;
    let nanos = u32::deserialize_reader(reader)?;
    DateTime::from_timestamp(secs, nanos).ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            "timestamp out of representable range",
        )
    })
}

pub fn borsh_ser_baseboard_id<W: Write>(value: &BaseboardId, writer: &mut W) -> Result<()> {
    value.part_number.serialize(writer)?;
    value.serial_number.serialize(writer)
}

pub fn borsh_de_baseboard_id<R: Read>(reader: &mut R) -> Result<BaseboardId> {
    Ok(BaseboardId {
        part_number: String::deserialize_reader(reader)?,
        serial_number: String::deserialize_reader(reader)?,
    })
}
