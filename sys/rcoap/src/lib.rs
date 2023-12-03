#![no_std]


#[no_mangle]
pub extern "C" fn hello() {
    riot_wrappers::println!("TESTING RUST ON RIOT");
}
