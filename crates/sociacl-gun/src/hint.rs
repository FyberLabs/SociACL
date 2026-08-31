use sociacl_core::{Action, NodeId};

use crate::{map_action, GunError, GunSoul};

/// Handoff frame magic. Distinct from Social Light `SLHP` and Case C
/// `SACL`. Decode does not verify. Decode does not mint.
pub const MAGIC: &[u8; 4] = b"SGH1";
pub const VERSION: u16 = 1;

const HEADER_LEN: usize = 4 + 2 + 4;
const MAX_STR: u32 = 4096;

/// Untrusted edge handoff. User/agent id as we name them, claimed
/// target, optional verb/context. The hop cannot mint a grant.
///
/// TypeScript surface (reimplement; do not import this crate):
///
/// ```text
/// {
///   principal: string,  // wallet / agent id
///   target: string,     // claimed soul or claim object id
///   verb?: string,      // see | execute | write | …
///   context?: string
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffHint {
    pub principal: NodeId,
    pub target: NodeId,
    pub verb: Option<String>,
    pub context: Option<String>,
}

impl HandoffHint {
    pub fn new(
        principal: impl Into<NodeId>,
        target: impl Into<NodeId>,
        verb: Option<impl AsRef<str>>,
        context: Option<impl AsRef<str>>,
    ) -> Result<Self, GunError> {
        let principal = principal.into();
        let target = target.into();
        if principal.as_str().is_empty() {
            return Err(GunError::EmptyPrincipal);
        }
        if target.as_str().is_empty() {
            return Err(GunError::EmptyTarget);
        }
        Ok(Self {
            principal,
            target,
            verb: verb
                .map(|v| v.as_ref().to_string())
                .filter(|v| !v.is_empty()),
            context: context
                .map(|c| c.as_ref().to_string())
                .filter(|c| !c.is_empty()),
        })
    }

    /// Named fields. Does not verify. Does not mint.
    pub fn parse(
        principal: impl AsRef<str>,
        target: impl AsRef<str>,
        verb: Option<&str>,
        context: Option<&str>,
    ) -> Result<Self, GunError> {
        let principal = parse_id(principal.as_ref())?;
        let target = parse_id(target.as_ref())?;
        if principal.as_str().is_empty() {
            return Err(GunError::EmptyPrincipal);
        }
        if target.as_str().is_empty() {
            return Err(GunError::EmptyTarget);
        }
        Self::new(principal, target, verb, context)
    }

    pub fn action(&self) -> Action {
        match self.verb.as_deref() {
            Some(v) => map_action(v),
            None => map_action(crate::SEE),
        }
    }

    /// Report string for C / Python. Not a grant.
    pub fn as_reason(&self) -> String {
        format!("hint {} {}", self.principal, self.target)
    }

    pub fn encode(&self) -> Result<Vec<u8>, GunError> {
        let mut payload = Vec::new();
        write_str(&mut payload, self.principal.as_str())?;
        write_str(&mut payload, self.target.as_str())?;
        match &self.verb {
            Some(v) => {
                payload.push(1);
                write_str(&mut payload, v)?;
            }
            None => payload.push(0),
        }
        match &self.context {
            Some(c) => {
                payload.push(1);
                write_str(&mut payload, c)?;
            }
            None => payload.push(0),
        }
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&payload);
        Ok(out)
    }

    /// Consume a versioned hint. Does not verify. Does not mint.
    pub fn decode(bytes: &[u8]) -> Result<Self, GunError> {
        if bytes.len() < HEADER_LEN {
            return Err(GunError::HintCorrupt);
        }
        if &bytes[..4] != MAGIC {
            return Err(GunError::HintCorrupt);
        }
        let version = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
        if version != VERSION {
            return Err(GunError::UnsupportedHintVersion(version));
        }
        let payload_len = u32::from_le_bytes(bytes[6..10].try_into().unwrap()) as usize;
        let end = HEADER_LEN
            .checked_add(payload_len)
            .ok_or(GunError::HintCorrupt)?;
        if bytes.len() != end {
            return Err(GunError::HintCorrupt);
        }
        let mut r = Reader::new(&bytes[HEADER_LEN..end]);
        let principal = r.str()?;
        let target = r.str()?;
        let verb = if r.flag()? {
            Some(r.str()?.to_string())
        } else {
            None
        };
        let context = if r.flag()? {
            Some(r.str()?.to_string())
        } else {
            None
        };
        r.finish()?;
        Self::parse(principal, target, verb.as_deref(), context.as_deref())
    }
}

fn parse_id(s: &str) -> Result<NodeId, GunError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(GunError::HintCorrupt);
    }
    if s.contains(".get(") || s.contains('/') {
        Ok(GunSoul::parse(s)?.as_node_id())
    } else {
        Ok(NodeId::new(s))
    }
}

fn write_str(out: &mut Vec<u8>, s: &str) -> Result<(), GunError> {
    if s.len() > MAX_STR as usize {
        return Err(GunError::HintCorrupt);
    }
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

struct Reader<'a> {
    buf: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, i: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], GunError> {
        let end = self.i.checked_add(n).ok_or(GunError::HintCorrupt)?;
        if end > self.buf.len() {
            return Err(GunError::HintCorrupt);
        }
        let slice = &self.buf[self.i..end];
        self.i = end;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<u32, GunError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes(b.try_into().unwrap()))
    }

    fn flag(&mut self) -> Result<bool, GunError> {
        match self.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(GunError::HintCorrupt),
        }
    }

    fn str(&mut self) -> Result<&'a str, GunError> {
        let len = self.u32()?;
        if len > MAX_STR {
            return Err(GunError::HintCorrupt);
        }
        let bytes = self.take(len as usize)?;
        std::str::from_utf8(bytes).map_err(|_| GunError::HintCorrupt)
    }

    fn finish(&self) -> Result<(), GunError> {
        if self.i == self.buf.len() {
            Ok(())
        } else {
            Err(GunError::HintCorrupt)
        }
    }
}
