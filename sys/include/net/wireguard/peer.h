#ifndef _WIREGUARD_PEER_H_
#define _WIREGUARD_PEER_H_

#include "cookie.h"
#include "messages.h"
#include "net/gnrc/pkt.h"
#include "net/ipv6/addr.h"
#include "net/sock/udp.h"
#include "noise.h"
#include <stdint.h>

#define WIREGUARD_INVALID_INDEX (0xff)
#define MAX_SRC_IPS (2)

struct wg_device;

struct wg_allowed_ip {
  bool valid;
  ipv6_addr_t ip;
  unsigned int pfx_len;
};

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
  /* should we be actively trying to connect */
  bool active;
  struct noise_keypairs keypairs;
  // struct endpoint endpoint;
  struct noise_handshake handshake;
  // TODO: the index of the handshake???
  uint32_t last_sent_handshake;
  struct cookie latest_cookie;
  /* configured endpoint of peer */
  sock_udp_ep_t endpoint;
  /* latest received endpoint */
  sock_udp_ep_t latest_endpoint;
  /* keep-alive interval in seconds, 0 is disable */
  uint16_t keepalive_interval;
  /* index of peer */
  uint8_t peer_idx;
  struct wg_allowed_ip allowed_source_ips[MAX_SRC_IPS];
  /* The last time we received a valid initiation message */
  uint32_t last_initiation_rx;
  /* The last time we sent an initiation message to this peer */
  uint32_t last_initiation_tx;

  /* last sending and receiving of transport data */
  uint32_t last_tx;
  uint32_t last_rx;

  /* We set this flag on RX/TX of packets if we think that we should initiate a
   * new handshake */
  bool send_handshake;
  // TODO: add more fields
};

bool wireguard_peer_init(struct wg_device *wg, struct wg_peer *peer,
                         const uint8_t public_key[NOISE_PUBLIC_KEY_LEN],
                         const uint8_t preshared_key[NOISE_SYMMETRIC_KEY_LEN]);

bool peer_add_ip(struct wg_peer *peer, ipv6_addr_t *allowed_ip,
                 unsigned int pfx_len);

struct wg_peer *
peer_lookup_by_pubkey(struct wg_peer peers[MAX_PEERS_PER_DEVICE],
                      const uint8_t pubkey[NOISE_PUBLIC_KEY_LEN]);

struct wg_peer *peer_lookup_by_index(struct wg_peer peers[MAX_PEERS_PER_DEVICE],
                                     uint8_t index);
struct wg_peer *
peer_lookup_by_allowed_ip(struct wg_peer peers[MAX_PEERS_PER_DEVICE],
                          const ipv6_addr_t *addr);

struct wg_peer *peer_alloc(struct wg_peer peers[MAX_PEERS_PER_DEVICE]);
void peer_remove(struct wg_peer *peer);

uint32_t wg_generate_unique_index(struct wg_peer peers[MAX_PEERS_PER_DEVICE]);
struct wg_peer *
peer_lookup_by_handshake_receiver(struct wg_peer peers[MAX_PEERS_PER_DEVICE],
                                  uint32_t receiver_index);

#endif
