/*
 * Copyright (C) 2024 NguyenLe1605
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup net_gnrc_netif
 * @{
 *
 * @file
 * @brief   Wireguard adaption for @ref net_gnrc_netif
 * @{
 *
 * @file
 *
 * @author      Nguyen Le Hoang Dang <lhdnguyen2002@gmail.com>
 */

#ifndef GNRC_NETIF_WIREGUARD_H
#define GNRC_NETIF_WIREGUARD_H

#include "net/gnrc/netif.h"
#include "net/gnrc/netif/internal.h"
#include "net/netdev.h"
#include "net/sock/udp.h"
#include "wireguard_peer.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  ipv6_addr_t addr;
  unsigned int pfx_len;
} wireguard_netif_allowed_ip_t;

/* This struct represents a peer residing on the wireguard netif */
typedef struct wireguard_netif_peer {
  const char *public_key;
  /* Optional pre-shared key (32 bytes) - NULL if not used */
  const uint8_t *preshared_key;

  /* ptr to an array of allowed ips*/
  wireguard_netif_allowed_ip_t *allowed_ips;
  /* lenght of the array of allowed_ips, must be less than or equal to
   * MAX_SRC_IPS */
  int allowed_ips_len;

  /* End-point details */
  sock_udp_ep_t endpoint;

  /**< a seconds interval, between 1 and 65535 inclusive, of how often to send
     an authenticated empty packet to the peer for the purpose of keeping a
     stateful firewall or NAT mapping valid persistently. Set zero to disable
     the feature. Default is zero. */
  int persistent_keepalive;
} wireguard_netif_peer_t;

/**
 * @brief   Creates a wireguard network interface
 *
 * @param[out] netif    The interface. May not be `NULL`.
 * @param[in] stack     The stack for the network interface's thread.
 * @param[in] stacksize Size of @p stack.
 * @param[in] priority  Priority for the network interface's thread.
 * @param[in] name      Name for the network interface. May be NULL.
 * @param[in] dev       Device for the interface.
 *
 * @see @ref gnrc_netif_create()
 *
 * @return  0 on success
 * @return  negative number on error
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

/* Helper to initialise the netif peer struct with defaults */
void gnrc_netif_wireguard_peer_init(wireguard_netif_peer_t *peer);

/* Add a new peer to the specified interface - see wireguard_constants.h for
 * maximum number of peers allowed. On success the peer_index can be used to
 * reference this peer in future function calls */
int gnrc_netif_wireguard_add_peer(gnrc_netif_t *netif,
                                  wireguard_netif_peer_t *peer,
                                  uint8_t *peer_idx);

/* Try and connect the given peer */
int gnrc_netif_wireguard_connect(gnrc_netif_t *netif, uint8_t peer_idx);

#ifdef __cplusplus
}
#endif

#endif /* GNRC_NETIF_WIREGUARD_H */
/** @} */
