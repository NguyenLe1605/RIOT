#ifndef _WIREGUARD_H_
#define _WIREGUARD_H_

// TODO: add license and mention: https://github.com/smartalock/wireguard-lwip

#include "net/gnrc/netif.h"
#include "net/ipv6/addr.h"
#include "wireguard/crypto.h"
#include "wireguard/device.h"
#include "wireguard/messages.h"
#include "wireguard/peer.h"
#include <stdint.h>

// Default MTU for WireGuard is 1420 bytes
#define WG_MTU (1420)

#define WG_DEFAULT_PORT (51820)
#define WG_KEEPALIVE_DEFAULT (0xFFFF)
#define WG_INVALID_INDEX (0xFF)

typedef struct wg_config {
  // Required: the private key of this WireGuard network interface
  const char *privkey;
  // Required: What UDP port to listen on
  uint16_t listen_port;
  // Optional: restrict send/receive of encapsulated WireGuard traffic to this
  // network interface only (NULL to use routing table)
  gnrc_netif_t *bind_netif;
} wg_config_t;

// This struct represents a peer residing on the wireguard netif
typedef struct wg_ifpeer {
  const char *pubkey;
  // Optional pre-shared key (32 bytes) - make sure this is NULL if not to be
  // used
  const uint8_t *preshared_key;
  // tai64n of largest timestamp we have seen during handshake to avoid replays
  uint8_t greatest_timestamp[NOISE_TIMESTAMP_LEN];

  // Allowed ip/netmask (can add additional later but at least one is required)
  ipv6_addr_t allowed_ip;
  // TODO: add prefix length later after reading on ipv6 RFC
  // uint16_t prefix_length;

  // End-point details (may be blank)
  struct endpoint ep;

  uint16_t keep_alive;
} wg_ifpeer_t;

// // TODO: Hardcoded setup to get running for now, change later
// void wg_setup(void);
//
// // Initialize a new Wireguard Network interface
// int wg_init(gnrc_netif_t *netif);
//
// // Helper to initialise the wg_ifpeer struct with defaults
// void wg_ifpeer_init(wg_ifpeer_t *peer);
//
// // Add a new peer to the specified interface - see wireguard/device.h for
// // maximum number of peers allowed. On success the peer_index can be used to
// // reference this peer in future function calls
// int wg_add_ifpeer(gnrc_netif_t *netif, wg_ifpeer_t *peer, uint8_t
// *peer_index);
//
// // Remove the given peer from the network interface
// int wg_remove_ifpeer(gnrc_netif_t *netif, uint8_t peer_index);
//
// // Update the "connect" IP of the given peer
// int wg_update_endpoint(gnrc_netif_t *netif, uint8_t peer_index,
//                        const wg_endpoint_t *ep);
//
// // Try and connect to the given peer
// int wg_connect(gnrc_netif_t *netif, uint8_t peer_index);
//
// // Stop trying to connect to the given peer
// int wg_disconnect(gnrc_netif_t *netif, uint8_t peer_index);
//
// // Is the given peer "up"? A peer is up if it has a valid session key it can
// // communicate with
// int wg_ifpeer_is_up(gnrc_netif_t *netif, uint8_t peer_index,
//                     const wg_endpoint_t *current_ep);

#endif
