use std::io::Write;
use sha2::Digest;

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
