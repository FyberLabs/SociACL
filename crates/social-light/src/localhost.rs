//! First out-of-process hop: two localhost UDP sockets.
//!
//! Not a daemon mesh. Not cloud. Hearing a frame does not mint a
//! friend. FyberLabs/socialight owns later BT / Wi-Fi / Meshtastic
//! delivery. This crate only proves the hop frame leaves one process
//! and enters SociACL verbs in another.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use sociacl_core::{AttestationError, SocialLightStatement};

const MAX_DATAGRAM: usize = 65_536;

/// One end of a localhost hop. Bind two of these. Send a frame.
/// The other side feeds bytes into Check, Remint, or Discover.
#[derive(Debug)]
pub struct LocalHop {
    socket: UdpSocket,
}

impl LocalHop {
    pub fn bind() -> std::io::Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        socket.set_write_timeout(Some(Duration::from_secs(2)))?;
        Ok(Self { socket })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Deliver encoded bytes. Delivery is not a grant.
    pub fn send(
        &self,
        statement: &SocialLightStatement,
        dest: SocketAddr,
    ) -> Result<usize, HopIoError> {
        let bytes = statement.encode().map_err(HopIoError::Frame)?;
        Ok(self.socket.send_to(&bytes, dest)?)
    }

    pub fn send_bytes(&self, bytes: &[u8], dest: SocketAddr) -> Result<usize, HopIoError> {
        SocialLightStatement::decode(bytes).map_err(HopIoError::Frame)?;
        Ok(self.socket.send_to(bytes, dest)?)
    }

    pub fn recv(&self) -> Result<(SocialLightStatement, SocketAddr), HopIoError> {
        let (bytes, from) = self.recv_bytes()?;
        let statement = SocialLightStatement::decode(&bytes).map_err(HopIoError::Frame)?;
        Ok((statement, from))
    }

    pub fn recv_bytes(&self) -> Result<(Vec<u8>, SocketAddr), HopIoError> {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let (n, from) = self.socket.recv_from(&mut buf)?;
        buf.truncate(n);
        Ok((buf, from))
    }
}

#[derive(Debug)]
pub enum HopIoError {
    Frame(AttestationError),
    Io(std::io::Error),
}

impl From<std::io::Error> for HopIoError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl std::fmt::Display for HopIoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Frame(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for HopIoError {}
