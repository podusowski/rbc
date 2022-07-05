use sha2::Digest;
use std::{
    io::{Read, Write},
    net::Ipv6Addr,
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Something that can be coded and decoded according to the Bitcoin protocol rules.
pub(crate) trait Piece: Sized {
    fn encode(&self, _: &mut impl Write) -> std::io::Result<()>;
    fn decode(_: &mut impl Read) -> std::io::Result<Self>;
}

macro_rules! impl_piece_for_primitive {
    ($type:ty) => {
        impl Piece for $type {
            fn encode(&self, sink: &mut impl Write) -> std::io::Result<()> {
                sink.write_all(&self.to_le_bytes())
            }

            fn decode(stream: &mut impl Read) -> std::io::Result<Self> {
                let mut buf: [u8; std::mem::size_of::<Self>()] = Default::default();
                stream.read_exact(&mut buf)?;
                Ok(Self::from_le_bytes(buf))
            }
        }
    };
}

impl_piece_for_primitive!(u8);
impl_piece_for_primitive!(u16);
impl_piece_for_primitive!(u32);
impl_piece_for_primitive!(u64);

/// Part of every Bitcoin message.
#[derive(PartialEq, Default, Debug)]
pub(crate) struct Header {
    pub magic: Magic,
    pub command: Command,
    pub payload_length: u32,
    pub payload_hash: u32,
}

impl Header {
    pub fn new(command: &'static [u8]) -> Self {
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

#[derive(PartialEq, Default, Debug)]
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
    pub fn new(command: &'static [u8]) -> Self {
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

    fn decode(stream: &mut impl Read) -> std::io::Result<Self> {
        let mut buf: [u8; 16] = Default::default();
        stream.read_exact(&mut buf)?;
        Ok(Self::from(buf))
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
}
