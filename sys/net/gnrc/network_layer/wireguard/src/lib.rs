#![no_std]
use riot_wrappers::println;
use sha2::{Digest, Sha256};

#[no_mangle]
pub extern "C" fn wireguard_init() {
    println!("Hello wireguard");
    // create a Sha256 object
    let mut hasher = Sha256::new();

    // write input message
    hasher.update(b"hello world");

    // read hash digest and consume hasher
    let result = hasher.finalize();
    println!("{:?}", result);
}
