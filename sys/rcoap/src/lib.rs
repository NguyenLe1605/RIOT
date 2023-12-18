#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#![no_std]

pub const CONFIG_RCOAP_NOPTS_MAX: u32 = 16;

pub use riot_wrappers::riot_sys::sock_udp_ep_t;
pub type rcoap_method_flags_t = u16;
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct rcoap_hdr_t {
    pub ver_t_tkl: u8,
    pub code: u8,
    pub id: u16,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rcoap_optpos_t {
    pub opt_num: u16,
    pub offset: u16,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rcoap_pkt_t {
    pub hdr: *mut rcoap_hdr_t,
    pub payload: *mut u8,
    pub payload_len: u16,
    pub options_len: u16,
    pub options: [rcoap_optpos_t; 16usize],
    pub opt_crit: [u8; 2usize],
}
pub type rcoap_request_ctx_t = _coap_request_ctx;
pub type rcoap_handler_t = ::core::option::Option<
    unsafe extern "C" fn(
        pkt: *mut rcoap_pkt_t,
        buf: *mut u8,
        len: usize,
        context: *mut rcoap_request_ctx_t,
    ) -> isize,
>;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rcoap_resource_t {
    pub path: *const ::core::ffi::c_char,
    pub methods: rcoap_method_flags_t,
    pub handler: rcoap_handler_t,
    pub context: *mut ::core::ffi::c_void,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _coap_request_ctx {
    pub resource: *const rcoap_resource_t,
    pub remote: *mut sock_udp_ep_t,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rcoap_link_encoder_ctx_t {
    pub content_format: ::core::ffi::c_uint,
    pub link_pos: usize,
    pub flags: u16,
}
pub type rcoap_link_encoder_t = ::core::option::Option<
    unsafe extern "C" fn(
        resource: *const rcoap_resource_t,
        buf: *mut ::core::ffi::c_char,
        maxlen: usize,
        context: *mut rcoap_link_encoder_ctx_t,
    ) -> isize,
>;
pub type rcoap_listener_t = rcoap_listener;
pub type rcoap_request_matcher_t = ::core::option::Option<
    unsafe extern "C" fn(
        listener: *mut rcoap_listener_t,
        resource: *mut *const rcoap_resource_t,
        pdu: *mut rcoap_pkt_t,
    ) -> ::core::ffi::c_int,
>;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum rcoap_socket_type_t {
    RCOAP_SOCKET_TYPE_UNDEF = 0x0,
    RCOAP_SOCKET_TYPE_UDP,
    RCOAP_SOCKET_TYPE_DTLS,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rcoap_listener {
    pub resources: *const rcoap_resource_t,
    pub resources_len: usize,
    pub tl_type: rcoap_socket_type_t,
    pub link_encoder: rcoap_link_encoder_t,
    pub next: *mut rcoap_listener,
    pub request_matcher: rcoap_request_matcher_t,
}

#[no_mangle]
pub extern "C" fn hello() {
    // riot_wrappers::println!("Hello Nhi");
}
