use crate::messages::{build_version, current_timestamp, BitcoinMessage};
use std::net::SocketAddr;

mod protocol;
mod messages;

async fn node(addr: SocketAddr) {
    // https://developer.bitcoin.org/devguide/p2p_network.html#connecting-to-peers
    println!("connecting to {}", addr);
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    let mut stream = sock.connect(addr).await.unwrap();

    let version = build_version(current_timestamp());
    version.write(&mut stream).await;

    let incoming = BitcoinMessage::read(&mut stream).await;
    println!("{:?}", incoming);
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
