use std::{io::Write, net::SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

mod utils;

async fn write_padded_bytes<W>(sink: &mut W, buf: &[u8], total_length: usize)
where
    W: AsyncWrite + Unpin,
{
    sink.write_all(buf).await.unwrap();
    assert!(
        buf.len() <= total_length,
        "resulting write would be bigger than `total_length`"
    );
    for _ in 0..total_length - buf.len() {
        sink.write(&[0]).await.unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn smaller_data_gets_additional_padding() {
        let mut sink = Vec::new();
        write_padded_bytes(&mut sink, &[1], 2).await;
        assert_eq!(vec![1, 0], sink);
    }

    #[tokio::test]
    #[should_panic = "resulting write would be bigger than `total_length`"]
    async fn panic_when_data_does_not_fit() {
        let mut sink = Vec::new();
        write_padded_bytes(&mut sink, &[1, 2, 3], 2).await;
        assert_eq!(vec![1, 0], sink);
    }
}

async fn node(addr: SocketAddr) {
    // https://developer.bitcoin.org/devguide/p2p_network.html#connecting-to-peers
    println!("connecting to {}", addr);
    let mut sock = tokio::net::TcpSocket::new_v4().unwrap();
    let mut stream = sock.connect(addr).await.unwrap();

    // https://developer.bitcoin.org/reference/p2p_networking.html#message-headers
    // start string
    stream.write_all(&0xf9beb4d9u32.to_le_bytes()).await.unwrap();
    // command
    write_padded_bytes(&mut stream, b"ping", 12).await;
    // content length
    stream.write_all(&0u32.to_le_bytes()).await.unwrap();
    // checksum
    stream.write_all(&0x5df6e0e2u32.to_le_bytes()).await.unwrap();

    let ans = stream.read_u8().await.unwrap();
    println!("{}", ans);
}

#[tokio::main]
async fn main() {
    println!("looking for seed nodes");
    // https://developer.bitcoin.org/devguide/p2p_network.html#peer-discovery
    let nodes = tokio::net::lookup_host("seed.bitcoin.sipa.be:8333")
        .await
        .unwrap()
        .filter(SocketAddr::is_ipv4)
        .take(3)
        .map(|addr| tokio::spawn(node(addr)));
    futures::future::join_all(nodes).await;
}
