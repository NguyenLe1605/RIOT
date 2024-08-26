#ifndef _WIREGUARD_H_
#define _WIREGUARD_H_

// TODO: add license and mention: https://github.com/smartalock/wireguard-lwip

#include "net/gnrc/netif.h"
#include "net/gnrc/netif/internal.h"
#include "net/gnrc/netif/ipv6.h"
#include "net/ipv6/addr.h"
#include "net/sock/udp.h"
#include "wireguard/messages.h"
#include <stdint.h>

/* Default MTU for WireGuard is 1420 bytes */
#define WIREGUARD_MTU (1420)

#define WIREGUARD_KEEPALIVE_DEFAULT (0xFFFF)
#define WG_INVALID_INDEX (0xFF)
#define BASE64_PRIVATE_KEY_LEN (44)

/* This struct represents a peer residing on the wireguard netif */
typedef struct wireguard_netif_peer {
  const char *public_key;

  size_t public_key_len;
  /* Optional pre-shared key (32 bytes) - make sure this is NULL if not to be
   * used */
  const uint8_t *preshared_key;
  /* tai64n of largest timestamp we have seen during handshake to avoid replays
   */
  // TODO: remove this
  uint8_t greatest_timestamp[NOISE_TIMESTAMP_LEN];

  ipv6_addr_t allowed_ip;
  /* prefix length */
  unsigned int pfx_len;

  /* End-point details (may be blank) */
  sock_udp_ep_t remote;

  uint16_t keep_alive;
} wireguard_netif_peer_t;

/* Initialize a new wireguard network interface along with the wireguard device
 */
int gnrc_netif_wireguard_create(gnrc_netif_t *netif, char *stack, int stacksize,
                                char priority, char *name, netdev_t *dev);

/* Add ipv6 address to the interface */
inline int gnrc_netif_wireguard_add_ipv6_addr(gnrc_netif_t *netif,
                                              ipv6_addr_t *addr,
                                              unsigned int pfx_len) {
  return gnrc_netif_ipv6_addr_add_internal(
      netif, addr, pfx_len, GNRC_NETIF_IPV6_ADDRS_FLAGS_STATE_VALID);
}

/* Helper to initialise the wg_ifpeer struct with defaults */
void gnrc_netif_wireguard_peer_init(wireguard_netif_peer_t *peer);

/* Add a new peer to the specified interface - see device.h for maximum
 * number of peers allowed On success the peer_index can be used to reference
 * this peer in future function calls */
int gnrc_netif_wireguard_add_peer(gnrc_netif_t *netif,
                                  wireguard_netif_peer_t *peer,
                                  uint8_t *peer_idx);

/* Remove the given peer from the network interface */
int gnrc_netif_wireguard_remove_peer(gnrc_netif_t *netif, uint8_t peer_idx);

/* Update the "connect" IP of the given peer */
int gnrc_netif_wireguard_update_endpoint(gnrc_netif_t *netif, uint8_t peer_idx,
                                         const ipv6_addr_t *ip, uint16_t port);

/* Try and connect the given peer */
int gnrc_netif_wireguard_connect(gnrc_netif_t *netif, uint8_t peer_idx);

/* Stop trying to connect to the given peer */
int gnrc_netif_wireguard_disconnect(gnrc_netif_t *netif, uint8_t peer_idx);

/* Is the given peer "up"? A peer is up if it has a valid session key it can
 * communicate with */
int gnrc_netif_wireguard_peer_is_up(gnrc_netif_t *netif, uint8_t peer_idx,
                                    ipv6_addr_t *current_ip,
                                    uint16_t *current_port);

#endif
