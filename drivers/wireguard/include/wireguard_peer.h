/*
 * Copyright (C) 2024 NguyenLe1605
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     drivers_wireguard
 * @{
 *
 * @file
 * @brief       Definition of a peer on the wireguard device
 *
 * @author      Nguyen Le Hoang Dang <lhdnguyen2002@gmail.com>
 */

#ifndef WIREGUARD_PEER_H
#define WIREGUARD_PEER_H

#include "net/ipv6/addr.h"
#include "net/sock/udp.h"
#include "wireguard_constants.h"
#include "wireguard_cookie.h"
#include "wireguard_noise.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct wireguard_device;

typedef struct {
  event_t super;
  struct wireguard_peer *peer;
} handshake_event_t;

struct wireguard_allowed_ip {
  bool valid;
  ipv6_addr_t ip;
  unsigned int pfx_len;
};

struct wireguard_peer {
  struct wireguard_device *device;
  /* valid to mark if the object has been destroyed or not */
  bool valid;
  /* should we be actively trying to connect */
  bool active;
  struct noise_keypairs keypairs;
  struct noise_handshake handshake;
  /* configured endpoint of peer */
  sock_udp_ep_t endpoint;
  /* latest received endpoint */
  sock_udp_ep_t latest_endpoint;
  /* keep-alive interval in seconds, 0 is disable */
  uint16_t keepalive_interval;
  /* index of peer */
  uint8_t peer_idx;
  struct wireguard_allowed_ip allowed_source_ips[MAX_SRC_IPS];
  handshake_event_t handshake_init_evt;
  /* The last time we received a valid initiation message */
  uint32_t last_initiation_rx;
  /* The last time we sent an initiation message to this peer */
  uint32_t last_initiation_tx;
  /* last sending and receiving of transport data */
  uint32_t last_tx;
  uint32_t last_rx;

  struct cookie latest_cookie;
};

bool wireguard_peer_init(struct wireguard_device *wg,
                         struct wireguard_peer *peer,
                         const uint8_t public_key[NOISE_PUBLIC_KEY_LEN],
                         const uint8_t preshared_key[NOISE_SYMMETRIC_KEY_LEN]);

bool wireguard_peer_add_ip(struct wireguard_peer *peer, ipv6_addr_t *allowed_ip,
                           unsigned int pfx_len);

struct wireguard_peer *wireguard_peer_lookup_by_pubkey(
    struct wireguard_peer peers[MAX_PEERS_PER_DEVICE],
    const uint8_t pubkey[NOISE_PUBLIC_KEY_LEN]);

struct wireguard_peer *
wireguard_peer_alloc(struct wireguard_peer peers[MAX_PEERS_PER_DEVICE]);

struct wireguard_peer *wireguard_peer_lookup_by_index(
    struct wireguard_peer peers[MAX_PEERS_PER_DEVICE], uint8_t index);

int wireguard_sched_handshake_init(struct wireguard_peer *peer);

struct wireguard_peer *wireguard_peer_lookup_by_handshake_receiver(
    struct wireguard_peer peers[MAX_PEERS_PER_DEVICE], uint32_t receiver_index);

struct wireguard_peer *wireguard_peer_lookup_by_allowed_ip(
    struct wireguard_peer peers[MAX_PEERS_PER_DEVICE], const ipv6_addr_t *addr);

struct wireguard_peer *wireguard_peer_lookup_by_keypair_receiver(
    struct wireguard_peer peers[MAX_PEERS_PER_DEVICE], uint32_t receiver);
#endif

#ifdef __cplusplus
}
#endif /* WIREGUARD_PEER_H */
