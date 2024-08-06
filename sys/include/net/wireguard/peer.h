#ifndef _WIREGUARD_PEER_H_
#define _WIREGUARD_PEER_H_

#include "cookie.h"
#include "messages.h"
#include "net/ipv6/addr.h"
#include "noise.h"
#include <stdint.h>

struct wg_device;

// // TODO: may change to use sock_udp_ep later on
struct endpoint {
  // TODO: the definition of ipv6 address may change later
  ipv6_addr_t addr;
  uint16_t port;
};

struct wg_peer {
  struct wg_device *device;
  /* valid to mark if the object has been destroyed or not */
  bool valid;
  bool is_dead;
  struct noise_keypairs keypairs;
  struct endpoint endpoint;
  struct noise_handshake handshake;
  // TODO: the index of the handshake???
  uint64_t last_sent_handshake;
  struct cookie latest_cookie;
  // TODO: add more fields
};

struct wg_peer *
wg_lookup_peer_by_pubkey(struct wg_peer peers[MAX_PEERS_PER_DEVICE],
                         const uint8_t pubkey[NOISE_PUBLIC_KEY_LEN]);

uint32_t wg_generate_unique_index(struct wg_peer peers[MAX_PEERS_PER_DEVICE]);
struct wg_peer *
wg_lookup_peer_by_handshake_receiver(struct wg_peer peers[MAX_PEERS_PER_DEVICE],
                                     uint32_t receiver_index);

struct wg_peer *
wg_noise_handshake_consume_response(struct message_handshake_response *src,
                                    struct wg_device *wg);

#endif
