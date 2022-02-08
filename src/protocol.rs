use sha2::Digest;
use std::io::Write;

use tokio::io::{AsyncWrite, AsyncWriteExt};

/// The Bitcoin message header contains length and checksum of the payload that
/// follows. Because of that, it's not possible to encode it in a single pass
/// and some intermediate form is needed.
pub(crate) struct BitcoinMessage {
    header: [u8; 4 + 12 + 4 + 4],
    // TODO: Optimize this!
    payload: Vec<u8>,
}

impl BitcoinMessage {
    pub fn new() -> Self {
        let mut message = Self {
            header: Default::default(),
            payload: Vec::new(),
        };

        let mut header = message.header.as_mut_slice();

        // https://developer.bitcoin.org/reference/p2p_networking.html#message-headers

        // Magic start string. Common for all messages.
        header.write_all(&0xf9beb4d9u32.to_be_bytes()).unwrap();

        // Command, or type of the message.
        crate::utils::write_padded_bytes(&mut header, b"version", 12);

        // Length of the payload that follows the header. Set to zero, can be
        // changed later.
        header.write_all(&0u32.to_le_bytes()).unwrap();

        // Checksum of the payload. Set to the empty string, can be changed
        // later.
        header.write_all(&0x5df6e0e2u32.to_le_bytes()).unwrap();

        message
    }

    fn content_length(&mut self) -> &mut [u8] {
        &mut self.header[16..20]
    }

    fn payload_hash(&mut self) -> &mut [u8] {
        &mut self.header[20..24]
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
        let payload_len = self.payload.len() as u32;
        self.content_length()
            .copy_from_slice(&payload_len.to_le_bytes());

        let hash = self.calculate_payload_hash();
        self.payload_hash().copy_from_slice(&hash);

        // Flush.
        sink.write_all(&self.header).await.unwrap();
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
    use super::build_version;

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
