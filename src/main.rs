use std::net::SocketAddr;

async fn node(addr: SocketAddr) {
    println!("connecting to {}", addr);
    let mut sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.connect(addr).await.unwrap();
}

#[tokio::main]
async fn main() {
    println!("looking for seed nodes");
    let nodes = tokio::net::lookup_host("seed.bitcoin.sipa.be:8333")
        .await
        .unwrap()
        .filter(SocketAddr::is_ipv4)
        .take(3)
        .map(|addr| tokio::spawn(node(addr)));
    futures::future::join_all(nodes).await;
}
