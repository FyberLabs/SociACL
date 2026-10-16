//! Writer authentication for one inbox append.
//!
//! The writer id is an [`AuthenticatedWriterChannel`] or a signature
//! over the length-prefixed fields `s3rch-writer-append-v1` and
//! `entryId`. A bare accessor is not a writer. The brand matches the
//! presenter channel: only [`AuthenticatedWriterChannel::open`]
//! constructs the value. The TypeScript contract uses an ECMAScript
//! private field and a module `WeakSet`.
//!
//! `InboxEnvelope.writerSignature` covers those same bytes. The relay
//! recomputes `entryId` and does not open the grant. A verified
//! envelope is not a grant and is not an admitted append.

use crate::account::AccountSeaSecret;
use crate::canonical::{self, inbox_entry_id, writer_append_bytes, InboxEntryBody};
use crate::error::EncDiscError;
use crate::sea;

/// Private brand. Not a reflectable property and not `Copy` for callers.
struct ChannelBrand {
    _private: (),
}

/// Transport-minted capability for an append. `open` is the only constructor.
pub struct AuthenticatedWriterChannel {
    writer: String,
    writer_pub: String,
    brand: ChannelBrand,
}

impl AuthenticatedWriterChannel {
    /// Mint a channel for one writer and that writer's SEA pub.
    pub fn open(writer: &str, writer_pub: &str) -> Result<Self, EncDiscError> {
        if writer.is_empty() || crate::see::hop_forbidden(writer) {
            return Err(EncDiscError::ChannelRejected);
        }
        sea::parse_sea_point(writer_pub)?;
        Ok(Self {
            writer: writer.to_string(),
            writer_pub: writer_pub.to_string(),
            brand: ChannelBrand { _private: () },
        })
    }

    pub fn writer(&self) -> &str {
        &self.writer
    }

    pub fn writer_pub(&self) -> &str {
        &self.writer_pub
    }

    /// True only for a value `open` minted. The brand is not a public field.
    pub fn has_transport_brand(&self) -> bool {
        let _ = &self.brand;
        true
    }
}

impl std::fmt::Debug for AuthenticatedWriterChannel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedWriterChannel")
            .field("writer", &self.writer)
            .field("writer_pub", &self.writer_pub)
            .field("brand", &"transport")
            .finish()
    }
}

/// Signature by the writer's enrolled SEA pub. Not stored on the row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriterAppendProof {
    pub writer: String,
    pub writer_pub: String,
    pub signature: String,
}

/// How the relay learns the writer. A bare accessor is not a member.
pub enum WriterAppendAuth {
    Channel(AuthenticatedWriterChannel),
    Signature(WriterAppendProof),
}

/// Optional outer envelope for `named-writers`. Not a grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxEnvelope {
    pub body: InboxEntryBody,
    pub entry_id: String,
    pub writer_pub: String,
    pub writer_signature: String,
}

impl AccountSeaSecret {
    pub fn sign_writer_append(&self, entry_id: &str) -> Result<String, EncDiscError> {
        let message = writer_append_bytes(entry_id)?;
        sea::sign_sea(self.local_priv(), &message)
    }

    pub fn sign_inbox_stamp(&self, entry_id: &str) -> Result<String, EncDiscError> {
        let message = canonical::inbox_stamp_bytes(entry_id)?;
        sea::sign_sea(self.local_priv(), &message)
    }

    pub fn writer_append_proof(&self, entry_id: &str) -> Result<WriterAppendProof, EncDiscError> {
        Ok(WriterAppendProof {
            writer: self.account().to_string(),
            writer_pub: self.sea_pub().to_string(),
            signature: self.sign_writer_append(entry_id)?,
        })
    }
}

/// Recompute `entryId` and verify the writer signature.
///
/// A body that does not hash to `entryId` is rejected even when the
/// signature would verify over the claimed id. The returned id is not
/// an admission and not a grant.
pub fn verify_inbox_envelope(
    envelope: &InboxEnvelope,
    enrolled_writer_pub: &str,
) -> Result<String, EncDiscError> {
    let computed = inbox_entry_id(&envelope.body)?;
    if computed != envelope.entry_id {
        return Err(EncDiscError::RowRejected);
    }
    if envelope.writer_pub != enrolled_writer_pub {
        return Err(EncDiscError::PubMismatch);
    }
    let message = writer_append_bytes(&computed)?;
    sea::verify_sea(enrolled_writer_pub, &message, &envelope.writer_signature)?;
    Ok(computed)
}

/// True when `signature` verifies over the claimed id.
///
/// Used to show a matching signature still loses to a body that does
/// not hash to that id. This check does not admit the row.
pub fn signature_covers_claimed_id(claimed_id: &str, writer_pub: &str, signature: &str) -> bool {
    let Ok(message) = writer_append_bytes(claimed_id) else {
        return false;
    };
    sea::verify_sea(writer_pub, &message, signature).is_ok()
}
