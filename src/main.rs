use crate::protocol::{build_version, current_timestamp, Command, Header, Piece, Version};
use std::{io::Read, net::SocketAddr};
use tokio::io::AsyncReadExt;

mod protocol;

async fn node(addr: SocketAddr) {
    // https://developer.bitcoin.org/devguide/p2p_network.html#connecting-to-peers
    println!("connecting to {}", addr);
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    let mut stream = sock.connect(addr).await.unwrap();

    let version = build_version(current_timestamp());
    version.write(&mut stream).await;

    let mut buf: [u8; 24] = Default::default();
    stream.read_exact(&mut buf).await.unwrap();
    let header = Header::decode(&mut buf.as_slice());
    println!("{header:?}");
    match header {
        Ok(header) => {
            if header.command == Version::command() {
                println!("got version");
            } else {
                println!("{:?}", std::str::from_utf8(&header.command.command));
            }
        }
        _ => panic!("bad"),
    }
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
