use sha2::Digest;
use std::io::Write;

use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Something that can be serialized according to the Bitcoin protocol rules.
trait BitcoinSerializable {
    fn write_to(&self, _: &mut impl Write) -> std::io::Result<()>;
}

/// Serialization for fixed-sized ints. Note: LE only.
impl BitcoinSerializable for u32 {
    fn write_to(&self, sink: &mut impl Write) -> std::io::Result<()> {
        sink.write_all(&self.to_le_bytes())
    }
}

#[derive(Default)]
pub(crate) struct BitcoinHeader {
    magic: Magic,
    command: Command,
    payload_length: u32,
    payload_hash: u32,
}

impl BitcoinHeader {
    fn new(command: &'static [u8]) -> Self {
        BitcoinHeader {
            magic: Default::default(),
            command: Command { command },
            payload_length: 0,
            payload_hash: 0,
        }
    }
}

impl BitcoinSerializable for BitcoinHeader {
    fn write_to(&self, sink: &mut impl Write) -> std::io::Result<()> {
        self.magic.write_to(sink)?;
        self.command.write_to(sink)?;
        self.payload_length.write_to(sink)?;
        self.payload_hash.write_to(sink)?;
        Ok(())
    }
}

#[derive(Default)]
struct Magic;

impl BitcoinSerializable for Magic {
    fn write_to(&self, sink: &mut impl Write) -> std::io::Result<()> {
        sink.write_all(&0xf9beb4d9u32.to_be_bytes())
    }
}

#[derive(Default)]
struct Command {
    command: &'static [u8],
}

impl Command {
    fn write_to(&self, sink: &mut impl Write) -> std::io::Result<()> {
        const MAX_LENGTH: usize = 12;
        sink.write_all(self.command)?;
        assert!(
            self.command.len() <= MAX_LENGTH,
            "command string is too long"
        );
        for _ in 0..MAX_LENGTH - self.command.len() {
            sink.write(&[0])?;
        }
        Ok(())
    }
}

/// The Bitcoin message header contains length and checksum of the payload that
/// follows. Because of that, it's not possible to encode it in a single pass
/// and some intermediate form is needed.
pub(crate) struct BitcoinMessage {
    header: BitcoinHeader,
    // TODO: Optimize this!
    payload: Vec<u8>,
}

impl BitcoinMessage {
    pub fn new() -> Self {
        Self {
            header: BitcoinHeader::new(b"version"),
            payload: Vec::new(),
        }
    }

    fn calculate_payload_hash(&self) -> [u8; 4] {
        // First pass.
        let mut hasher = sha2::Sha256::new();
        hasher.update(&self.payload);
        let first = hasher.finalize();

        // Second pass.
        let mut hasher = sha2::Sha256::new();
        hasher.update(first);

        let mut hash: [u8; 4] = Default::default();
        hash.copy_from_slice(&hasher.finalize()[..4]);
        hash
    }

    pub async fn write(mut self, sink: &mut (impl AsyncWrite + Unpin)) {
        // Finalize the message.
        self.header.payload_length = self.payload.len() as u32;
        self.header.payload_hash = u32::from_le_bytes(self.calculate_payload_hash());

        let mut encoded = Vec::new();
        self.header.write_to(&mut encoded).unwrap();

        // Flush.
        sink.write_all(&encoded).await.unwrap();
        sink.write_all(&self.payload).await.unwrap();
    }

    pub fn payload_writer(&mut self) -> &mut impl Write {
        &mut self.payload
    }
}

pub(crate) fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub(crate) fn build_version(timestamp: u64) -> BitcoinMessage {
    let mut version = BitcoinMessage::new();

    // Protocol version. 70015 was the highest by the time this was written.
    version
        .payload_writer()
        .write_all(&70015u32.to_le_bytes())
        .unwrap();

    // Services. We support none.
    version
        .payload_writer()
        .write_all(&0u64.to_le_bytes())
        .unwrap();

    // Current timestamp.
    version
        .payload_writer()
        .write_all(&timestamp.to_le_bytes())
        .unwrap();

    // Services of the other node. We support none.
    version
        .payload_writer()
        .write_all(&0u64.to_le_bytes())
        .unwrap();

    // "The IPv6 address of the receiving node as perceived by the transmitting node"
    version
        .payload_writer()
        .write_all(&std::net::Ipv6Addr::LOCALHOST.octets())
        .unwrap();

    // Port. Note the Big Endian.
    version
        .payload_writer()
        .write_all(&0u16.to_be_bytes())
        .unwrap();

    // Services. Again?
    version
        .payload_writer()
        .write_all(&0u64.to_le_bytes())
        .unwrap();

    // The IPv6 address of the transmitting node.
    version
        .payload_writer()
        .write_all(&std::net::Ipv6Addr::LOCALHOST.octets())
        .unwrap();

    // Port. Note the Big Endian.
    version
        .payload_writer()
        .write_all(&0u16.to_be_bytes())
        .unwrap();

    // Nonce. Not important for now.
    version
        .payload_writer()
        .write_all(&0u64.to_le_bytes())
        .unwrap();

    // Length of the user agent.
    version.payload_writer().write_all(&[0]).unwrap();

    // Height.
    version
        .payload_writer()
        .write_all(&0u32.to_le_bytes())
        .unwrap();

    version
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn when_writing_padded_bytes_smaller_data_gets_additional_padding() {
        let mut sink = Vec::new();
        Command {
            command: b"version",
        }
        .write_to(&mut sink)
        .unwrap();
        assert_eq!(vec![118, 101, 114, 115, 105, 111, 110, 0, 0, 0, 0, 0], sink);
    }

    #[test]
    #[should_panic = "command string is too long"]
    fn panic_when_data_does_not_fit() {
        let mut sink = Vec::new();
        Command {
            command: b"this text is too long to fit",
        }
        .write_to(&mut sink)
        .unwrap();
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
