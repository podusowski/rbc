use sha2::Digest;
use std::{
    io::{Read, Write},
    net::Ipv6Addr,
};

use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Something that can be coded and decoded according to the Bitcoin protocol rules.
pub(crate) trait Piece: Sized {
    fn encode(&self, _: &mut impl Write) -> std::io::Result<()>;
    fn decode(_: &mut impl Read) -> std::io::Result<Self>;
}

impl Piece for u8 {
    fn encode(&self, sink: &mut impl Write) -> std::io::Result<()> {
        sink.write_all(&self.to_le_bytes())
    }

    fn decode(_: &mut impl Read) -> std::io::Result<Self> {
        todo!()
    }
}

impl Piece for u16 {
    fn encode(&self, sink: &mut impl Write) -> std::io::Result<()> {
        sink.write_all(&self.to_le_bytes())
    }

    fn decode(_: &mut impl Read) -> std::io::Result<Self> {
        todo!()
    }
}

impl Piece for u32 {
    fn encode(&self, sink: &mut impl Write) -> std::io::Result<()> {
        sink.write_all(&self.to_le_bytes())
    }

    fn decode(stream: &mut impl Read) -> std::io::Result<Self> {
        let mut buf: [u8; std::mem::size_of::<Self>()] = Default::default();
        stream.read_exact(&mut buf)?;
        Ok(Self::from_le_bytes(buf))
    }
}

impl Piece for u64 {
    fn encode(&self, sink: &mut impl Write) -> std::io::Result<()> {
        sink.write_all(&self.to_le_bytes())
    }

    fn decode(_: &mut impl Read) -> std::io::Result<Self> {
        todo!()
    }
}

/// Part of every Bitcoin message.
#[derive(Default, Debug)]
pub(crate) struct Header {
    pub magic: Magic,
    pub command: Command,
    pub payload_length: u32,
    pub payload_hash: u32,
}

impl Header {
    fn new(command: &'static [u8]) -> Self {
        Header {
            magic: Default::default(),
            command: Command::new(command),
            payload_length: 0,
            payload_hash: 0,
        }
    }
}

impl Piece for Header {
    fn encode(&self, sink: &mut impl Write) -> std::io::Result<()> {
        self.magic.encode(sink)?;
        self.command.encode(sink)?;
        self.payload_length.encode(sink)?;
        self.payload_hash.encode(sink)?;
        Ok(())
    }

    fn decode(stream: &mut impl Read) -> std::io::Result<Self> {
        Ok(Header {
            magic: Piece::decode(stream)?,
            command: Piece::decode(stream)?,
            payload_length: Piece::decode(stream)?,
            payload_hash: Piece::decode(stream)?,
        })
    }
}

#[derive(Default, Debug)]
pub struct Magic;

impl Piece for Magic {
    fn encode(&self, sink: &mut impl Write) -> std::io::Result<()> {
        sink.write_all(&0xf9beb4d9u32.to_be_bytes())
    }

    fn decode(stream: &mut impl Read) -> std::io::Result<Self> {
        let mut buf: [u8; 4] = Default::default();
        stream.read_exact(&mut buf)?;
        let magic = u32::from_be_bytes(buf);
        // FIXME: Be more graceful.
        assert_eq!(0xf9beb4d9u32, magic);
        Ok(Magic)
    }
}

#[derive(Default, Debug, PartialEq)]
pub struct Command {
    pub command: [u8; 12],
}

impl Command {
    fn new(command: &'static [u8]) -> Self {
        const MAX_LENGTH: usize = 12;
        assert!(command.len() <= MAX_LENGTH, "command string is too long");
        let mut cmd: [u8; 12] = Default::default();
        cmd[..command.len()].copy_from_slice(command);
        Self { command: cmd }
    }
}

impl Piece for Command {
    fn encode(&self, sink: &mut impl Write) -> std::io::Result<()> {
        const MAX_LENGTH: usize = 12;
        sink.write_all(&self.command)?;
        assert!(
            self.command.len() <= MAX_LENGTH,
            "command string is too long"
        );
        for _ in 0..MAX_LENGTH - self.command.len() {
            sink.write_all(&[0])?;
        }
        Ok(())
    }

    fn decode(stream: &mut impl Read) -> std::io::Result<Self> {
        let mut command: [u8; 12] = Default::default();
        stream.read_exact(&mut command)?;
        Ok(Command { command })
    }
}

impl Piece for Ipv6Addr {
    fn encode(&self, sink: &mut impl Write) -> std::io::Result<()> {
        sink.write_all(&self.octets())
    }

    fn decode(_: &mut impl Read) -> std::io::Result<Self> {
        todo!()
    }
}

/// The “version” message provides information about the transmitting node to
/// the receiving node at the beginning of a connection. Until both peers have
/// exchanged “version” messages, no other messages will be accepted.
/// https://developer.bitcoin.org/reference/p2p_networking.html#version
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

    fn decode(_: &mut impl Read) -> std::io::Result<Self> {
        todo!()
    }
}

/// The Bitcoin message header contains length and checksum of the payload that
/// follows. Because of that, it's not possible to encode it in a single pass
/// and some intermediate form is needed.
pub(crate) struct BitcoinMessage {
    header: Header,
    // TODO: Optimize this!
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn when_writing_padded_bytes_smaller_data_gets_additional_padding() {
        let mut sink = Vec::new();
        Command::new(b"version").encode(&mut sink).unwrap();
        assert_eq!(vec![118, 101, 114, 115, 105, 111, 110, 0, 0, 0, 0, 0], sink);
    }

    #[test]
    #[should_panic = "command string is too long"]
    fn panic_when_data_does_not_fit() {
        Command::new(b"this text is too long to fit");
    }

    #[tokio::test]
    async fn building_version_works_fine() {
        let version = build_version(0);
        let mut encoded = Vec::new();
        version.write(&mut encoded).await;
        let expected = [
            249, 190, 180, 217, // Magic.
            118, 101, 114, 115, 105, 111, 110, 0, 0, 0, 0, 0, // Command.
            85, 0, 0, 0, // Payload length.
            154, 32, 106, 193, // Checksum.
            // Payload starts here.
            127, 17, 1, 0, // Protocol version.
            0, 0, 0, 0, 0, 0, 0, 0, // Services.
            0, 0, 0, 0, 0, 0, 0, 0, // Timestamp
            0, 0, 0, 0, 0, 0, 0, 0, // Services of other node.
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // Ip
            0, 0, // Port.
            0, 0, 0, 0, 0, 0, 0, 0, // Services. Again?
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // Ip again
            0, 0, // Port.
            0, 0, 0, 0, 0, 0, 0, 0, // Nonce.
            0, // Length of the User Agent.
            0, 0, 0, 0, // height
        ];
        assert_eq!(expected, encoded.as_slice());
    }
}
