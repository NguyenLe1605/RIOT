#![no_std]
use riot_wrappers::println;
use sha2::Digest;

#[no_mangle]
pub extern "C" fn ipsec_init() {
    let mut hasher = sha2::Sha256::new();

    hasher.update(b"Hello world!");

    let result = hasher.finalize();
    println!("{:?}", result);
}
