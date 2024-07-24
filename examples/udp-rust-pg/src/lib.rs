// Copyright (C) 2020 Christian Amsüss
//
// This file is subject to the terms and conditions of the GNU Lesser
// General Public License v2.1. See the file LICENSE in the top level
// directory for more details.
#![no_std]

use core::ptr::addr_of_mut;

use embedded_nal_async::SocketAddr;
use embedded_nal_async::{UdpStack, UnconnectedUdp};
use riot_sys;
use riot_wrappers::cstr::cstr;
use riot_wrappers::mutex::Mutex;
use riot_wrappers::println;
use riot_wrappers::riot_main;
use riot_wrappers::thread;
use riot_wrappers::ztimer::Clock;

// use embedded_nal::{nb::Error, UdpClientStack, UdpFullStack};
use static_cell::StaticCell;

extern crate rust_riotmodules;

riot_main!(main);

static mut STACK: [u8; 2048] = [0; 2048];
// static mut TEST: fn() = udp_pg;

static mut EVENT_LOOP: fn() = event_loop;

static EXECUTOR: StaticCell<embassy_executor_riot::Executor> = StaticCell::new();
static UDP_SOCKET: StaticCell<riot_sys::sock_udp_t> = StaticCell::new();

// hack to get it to work
fn event_loop() {
    let executor: &'static mut _ = EXECUTOR.init_with(|| embassy_executor_riot::Executor::new());
    executor.run(|spawner| {
        spawner.spawn(async_main(spawner)).unwrap();
    });
    unreachable!();
}

fn main() {
    println!("Hello Rust!");
    thread::spawn(
        unsafe { STACK.as_mut() },
        unsafe { &mut *addr_of_mut!(EVENT_LOOP) },
        cstr!("udp_pg"),
        (riot_sys::THREAD_PRIORITY_MAIN - 2) as _,
        (riot_sys::THREAD_CREATE_STACKTEST) as _,
    )
    .unwrap();
    println!("ended");
}

#[embassy_executor::task]
async fn async_main(spawner: embassy_executor::Spawner) {
    println!("hello");
    let stack =
        riot_wrappers::socket_embedded_nal_async_udp::UdpStack::new(|| UDP_SOCKET.try_uninit());
    let mut sock = stack
        .bind_multiple(SocketAddr::new("::".parse().unwrap(), 8088))
        .await
        .unwrap();
    let mut buffer = [0u8; 32];
    loop {
        let (nbytes, local, remote) = sock.receive_into(&mut buffer).await.unwrap();
        match buffer[..nbytes - 1].as_ref() {
            b"handshake" => {
                sock.send(local, remote, b"hand con cac").await.unwrap();
            }
            b"transport" => {
                println!("received: {:?}", buffer);
            }
            _ => {}
        }
        println!("test");
        buffer.iter_mut().for_each(|b| *b = 0);
    }
}
//
// fn udp_pg() {
//     let mut stack: Stack<1> = Stack::new();
//     stack.run(|mut stack| {
//         let mut sock = stack.socket().unwrap();
//         stack.bind(&mut sock, 8088).unwrap();
//         let mut buffer = [0u8; 12];
//         loop {
//             let remote = loop {
//                 match stack.receive(&mut sock, &mut buffer) {
//                     Ok((_, remote)) => break remote,
//                     Err(Error::WouldBlock) => {
//                         let mut sec = Clock::msec();
//                         sec.sleep(core::time::Duration::from_millis(100));
//                     }
//                     _ => panic!("wtf"),
//                 }
//             };
//             if buffer[0..9].as_ref() == b"handshake" {
//                 stack.send_to(&mut sock, remote, b"hand con cac").unwrap();
//                 println!("sending: {:?}", buffer);
//             }
//             println!("received: {:?}", buffer);
//         }
//     });
// }
