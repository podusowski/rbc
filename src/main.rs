#[tokio::main]
async fn main() {
    println!("looking for seed nodes");
    for addr in tokio::net::lookup_host("seed.bitcoin.sipa.be:0").await.unwrap() {
        println!("{:?}", addr);
    }
}
