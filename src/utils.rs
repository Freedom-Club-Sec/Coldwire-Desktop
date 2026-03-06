use std::collections::HashMap;

use crate::error::Error;
use crate::consts;



#[derive(Debug)]
pub struct Message {
    pub sender: String,
    pub blob: Vec<u8>,
    pub ack_id: [u8; 32],
}

pub fn decode_blob_stream(data: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let mut messages = Vec::new();
    let mut offset: usize = 0;
    let total = data.len();

    while offset < total {
        // ensure we can read ack_id + length field
        if offset
            .checked_add(32)
            .and_then(|o| o.checked_add(consts::COLDWIRE_LEN_OFFSET))
            .map_or(true, |end| end > total)
        {
            return Err(Error::MalformedData);
        }

        // safe slice access
        let ack_slice = &data[offset..offset + 32];
        let ack_id: [u8; 32] = ack_slice
            .try_into()
            .map_err(|_| Error::MalformedData)?;
        offset += 32;

        // read length bytes safely (support variable COLDWIRE_LEN_OFFSET)
        let len_slice = &data[offset..offset + consts::COLDWIRE_LEN_OFFSET];
        let msg_len = {
            // interpret as big-endian integer into usize
            let mut v: usize = 0;
            for &b in len_slice {
                v = (v << 8) | (b as usize);
            }
            v
        };
        offset += consts::COLDWIRE_LEN_OFFSET;

        if offset.checked_add(msg_len).map_or(true, |end| end > total) {
            return Err(Error::MalformedData);
        }

        // build message exactly like Python: ack_id concatenated with message bytes
        let mut message = Vec::with_capacity(32 + msg_len);
        message.extend_from_slice(&ack_id);
        message.extend_from_slice(&data[offset..offset + msg_len]);

        messages.push(message);
        offset += msg_len;
    }

    Ok(messages)
}

pub fn parse_blobs(blobs: Vec<Vec<u8>>) -> Result<Vec<Message>, Error> {
    let mut parsed = Vec::with_capacity(blobs.len());

    for raw in blobs {
        if raw.len() < 32 {
            return Err(Error::InvalidDataBlob);
        }

        let ack_id: [u8; 32] = raw[..32]
            .try_into()
            .map_err(|_| Error::InvalidDataBlob)?;
        let rest = &raw[32..];

        // split on first null byte (like Python's split(b"\0", 1))
        let parts: Vec<&[u8]> = rest.splitn(2, |&b| b == 0).collect();
        if parts.len() != 2 {
            return Err(Error::InvalidDataBlob);
        }

        let sender_bytes = parts[0];
        let blob = parts[1];

        let sender = std::str::from_utf8(sender_bytes).map_err(|_| Error::InvalidDataBlob)?;
        parsed.push(Message {
            sender: sender.to_string(),
            blob: blob.to_vec(),
            ack_id,
        });
    }

    Ok(parsed)
}



pub fn validate_identifier(identifier: &str) -> bool {
    // Check if it's exactly 16 digits
    if identifier.chars().all(|c| c.is_ascii_digit()) && identifier.len() == 16 {
        return true;
    }

    // Split by '@'
    let parts: Vec<&str> = identifier.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    // Check that the first part is all digits
    if !parts[0].chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    // Check max domain length
    if parts[1].len() > 253 {
        return false;
    }

    true
}

