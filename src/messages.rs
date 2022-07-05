use std::{net::Ipv6Addr, io::{Write, Read}};

use sha2::Digest;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, AsyncReadExt};

use crate::protocol::{Header, Command, Piece};

/// The Bitcoin message header contains length and checksum of the payload that
/// follows. Because of that, it's not possible to encode it in a single pass
/// and some intermediate form is needed.
#[derive(Debug, PartialEq)]
pub(crate) struct BitcoinMessage {
    header: Header,
    version: Version,
}

impl BitcoinMessage {
    fn calculate_payload_hash(data: &[u8]) -> [u8; 4] {
        // First pass.
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        let first = hasher.finalize();

        // Second pass.
        let mut hasher = sha2::Sha256::new();
        hasher.update(first);

        let mut hash: [u8; 4] = Default::default();
        hash.copy_from_slice(&hasher.finalize()[..4]);
        hash
    }

    pub async fn write(mut self, sink: &mut (impl AsyncWrite + Unpin)) {
        let mut encoded_payload = Vec::new();
        self.version.encode(&mut encoded_payload).unwrap();

        // Finalize the message.
        self.header.payload_length = encoded_payload.len() as u32;
        self.header.payload_hash =
            u32::from_le_bytes(Self::calculate_payload_hash(&encoded_payload));

        let mut encoded_header = Vec::new();
        self.header.encode(&mut encoded_header).unwrap();

        // Flush.
        sink.write_all(&encoded_header).await.unwrap();
        sink.write_all(&encoded_payload).await.unwrap();
    }

    pub async fn read(stream: &mut (impl AsyncRead + Unpin)) -> BitcoinMessage {
        let mut buf: [u8; 24] = Default::default();
        stream.read_exact(&mut buf).await.unwrap();
        let header = Header::decode(&mut buf.as_slice()).unwrap();

        let mut buf = vec![0; header.payload_length as usize];
        stream.read_exact(&mut buf).await.unwrap();

        let version = if header.command == Version::command() {
            println!("got version");
            Version::decode(&mut buf.as_slice()).unwrap()
        } else {
            panic!("{:?}", std::str::from_utf8(&header.command.command));
        };

        BitcoinMessage { header, version }
    }
}

pub(crate) fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub(crate) fn build_version(timestamp: u64) -> BitcoinMessage {
    BitcoinMessage {
        header: Header::new(b"version"),
        version: Version {
            version: 70015u32,
            services: 0,
            timestamp,
            addr_recv_services: 0,
            addr_recv_ip_address: Ipv6Addr::LOCALHOST,
            addr_recv_port: 0,
            addr_trans_services: 0,
            addr_trans_ip_address: Ipv6Addr::LOCALHOST,
            addr_trans_port: 0,
            nonce: 0,
            user_agent_bytes: 0,
            // user_agent_string,
            start_height: 0,
        },
    }
}

/// The “version” message provides information about the transmitting node to
/// the receiving node at the beginning of a connection. Until both peers have
/// exchanged “version” messages, no other messages will be accepted.
/// https://developer.bitcoin.org/reference/p2p_networking.html#version
#[derive(PartialEq, Debug, Clone)]
pub struct Version {
    version: u32,
    services: u64,
    timestamp: u64,
    addr_recv_services: u64,
    addr_recv_ip_address: Ipv6Addr,
    addr_recv_port: u16,
    addr_trans_services: u64,
    addr_trans_ip_address: Ipv6Addr,
    addr_trans_port: u16,
    nonce: u64,
    user_agent_bytes: u8,
    // user_agent_string,
    start_height: u32,
}

impl Version {
    pub fn command() -> Command {
        Command::new(b"version")
    }
}

impl Piece for Version {
    fn encode(&self, sink: &mut impl Write) -> std::io::Result<()> {
        self.version.encode(sink)?;
        self.services.encode(sink)?;
        self.timestamp.encode(sink)?;
        self.addr_recv_services.encode(sink)?;
        self.addr_recv_ip_address.encode(sink)?;
        self.addr_recv_port.encode(sink)?;
        self.addr_trans_services.encode(sink)?;
        self.addr_trans_ip_address.encode(sink)?;
        self.addr_trans_port.encode(sink)?;
        self.nonce.encode(sink)?;
        self.user_agent_bytes.encode(sink)?;
        // user_agent_string,
        self.start_height.encode(sink)
    }

    fn decode(stream: &mut impl Read) -> std::io::Result<Self> {
        Ok(Self {
            version: Piece::decode(stream)?,
            services: Piece::decode(stream)?,
            timestamp: Piece::decode(stream)?,
            addr_recv_services: Piece::decode(stream)?,
            addr_recv_ip_address: Piece::decode(stream)?,
            addr_recv_port: Piece::decode(stream)?,
            addr_trans_services: Piece::decode(stream)?,
            addr_trans_ip_address: Piece::decode(stream)?,
            addr_trans_port: Piece::decode(stream)?,
            nonce: Piece::decode(stream)?,
            user_agent_bytes: Piece::decode(stream)?,
            start_height: Piece::decode(stream)?,
        })
    }
}
