#include "wireguard_peer.h"
#include "crypto/helper.h"
#include "event.h"
#include "wireguard.h"
#include "wireguard_constants.h"
#include "wireguard_cookie.h"
#include "wireguard_internal.h"
#include "wireguard_noise.h"
#include "wireguard_timer.h"

#define ENABLE_DEBUG 1
#include "debug.h"

bool wireguard_peer_init(struct wireguard_device *wg,
                         struct wireguard_peer *peer,
                         const uint8_t public_key[NOISE_PUBLIC_KEY_LEN],
                         const uint8_t preshared_key[NOISE_SYMMETRIC_KEY_LEN]) {
  assert(wg);
  assert(peer);
  if (!wg->valid) {
    return false;
  }
  /* clean up the peer */
  memset(peer, 0, sizeof(struct wireguard_peer));
  peer->device = wg;
  peer->queue_entry = NULL;
  peer->valid = wireguard_noise_handshake_init(
      &peer->handshake, &wg->static_identity, public_key, preshared_key, peer);
  if (peer->valid) {
    wireguard_cookie_init(&peer->latest_cookie);
    wireguard_cookie_checker_precompute_peer_keys(peer);
    wireguard_noise_reset_last_sent_handshake(&peer->last_sent_handshake);
    wireguard_timers_init(peer);
  }
  return peer->valid;
}

bool wireguard_peer_add_ip(struct wireguard_peer *peer, ipv6_addr_t *allowed_ip,
                           unsigned int pfx_len) {
  bool result = false;
  struct wireguard_allowed_ip *allowed;
  int i;

  /* check for existing match */
  for (i = 0; i < MAX_SRC_IPS; ++i) {
    allowed = &peer->allowed_source_ips[i];
    if (allowed->valid && ipv6_addr_equal(&allowed->ip, allowed_ip) &&
        allowed->pfx_len == pfx_len) {
      result = true;
      break;
    }
  }

  /* fresh allowed ip, add to the list*/
  if (!result) {
    for (i = 0; i < MAX_SRC_IPS; ++i) {
      allowed = &peer->allowed_source_ips[i];
      if (!allowed->valid) {
        allowed->valid = true;
        allowed->ip = *allowed_ip;
        allowed->pfx_len = pfx_len;
        result = true;
        break;
      }
    }
  }
  return result;
}

struct wireguard_peer *wireguard_peer_lookup_by_pubkey(
    struct wireguard_peer peers[MAX_PEERS_PER_DEVICE],
    const uint8_t pubkey[NOISE_PUBLIC_KEY_LEN]) {
  struct wireguard_peer *ret_peer = NULL;
  struct wireguard_peer *peer;
  int i = 0;
  if (peers == NULL) {
    return NULL;
  }
  for (i = 0; i < MAX_PEERS_PER_DEVICE; ++i) {
    peer = &peers[i];
    if (peer->valid && crypto_equals(pubkey, peer->handshake.remote_static,
                                     NOISE_PUBLIC_KEY_LEN)) {
      ret_peer = peer;
      break;
    }
  }
  return ret_peer;
}

struct wireguard_peer *
wireguard_peer_alloc(struct wireguard_peer peers[MAX_PEERS_PER_DEVICE]) {
  uint8_t i;
  struct wireguard_peer *peer = NULL;
  for (i = 0; i < MAX_PEERS_PER_DEVICE; ++i) {
    peer = &peers[i];
    if (!peer->valid) {
      peer->peer_idx = i;
      break;
    }
  }
  return peer;
}

struct wireguard_peer *wireguard_peer_lookup_by_index(
    struct wireguard_peer peers[MAX_PEERS_PER_DEVICE], uint8_t index) {
  struct wireguard_peer *result = NULL;
  if (index < MAX_PEERS_PER_DEVICE && peers[index].valid) {
    result = &peers[index];
  }
  return result;
}

struct wireguard_peer *wireguard_peer_lookup_by_handshake_receiver(
    struct wireguard_peer peers[MAX_PEERS_PER_DEVICE],
    uint32_t receiver_index) {
  struct wireguard_peer *ret_peer = NULL;
  struct wireguard_peer *peer;
  int i = 0;
  if (peers == NULL) {
    return NULL;
  }
  for (i = 0; i < MAX_PEERS_PER_DEVICE; ++i) {
    peer = &peers[i];
    if (peer->valid && peer->handshake.handshaking &&
        peer->handshake.local_index == receiver_index) {
      ret_peer = peer;
      break;
    }
  }
  return ret_peer;
}

struct wireguard_peer *wireguard_peer_lookup_by_allowed_ip(
    struct wireguard_peer peers[MAX_PEERS_PER_DEVICE],
    const ipv6_addr_t *addr) {
  struct wireguard_peer *peer = NULL;
  struct wireguard_peer *tmp;
  struct wireguard_allowed_ip *allowed;
  uint8_t best_match = 0;
  uint8_t match;
  size_t i;
  size_t j;

  for (i = 0; i < MAX_PEERS_PER_DEVICE; ++i) {
    tmp = &peers[i];
    if (!tmp->valid) {
      continue;
    }
    /* perform longest prefix match to find the dest ip */
    for (j = 0; j < MAX_SRC_IPS; ++j) {
      allowed = &tmp->allowed_source_ips[i];
      if (!allowed->valid)
        continue;
      match = ipv6_addr_match_prefix(&allowed->ip, addr);
      if (match < allowed->pfx_len)
        continue;
      /* the 0 case is when the destination allowed ip is an unspecified IPv6
       * address */
      if (match > best_match || best_match == 0) {
        peer = tmp;
        best_match = match;
      }
      /* found the exact match on the ipv6 address destination */
      if (best_match == IPV6_ADDR_BIT_LEN) {
        return peer;
      }
    }
  }
  return peer;
}

struct wireguard_peer *wireguard_peer_lookup_by_keypair_receiver(
    struct wireguard_peer peers[MAX_PEERS_PER_DEVICE], uint32_t receiver) {
  struct wireguard_peer *result = NULL;
  struct wireguard_peer *tmp;
  struct noise_keypairs *keypairs;
  int x;
  for (x = 0; x < MAX_PEERS_PER_DEVICE; x++) {
    tmp = &peers[x];
    if (tmp->valid) {
      keypairs = &tmp->keypairs;
      if ((keypairs->current_keypair.valid &&
           (keypairs->current_keypair.local_index == receiver)) ||
          (keypairs->next_keypair.valid &&
           (keypairs->next_keypair.local_index == receiver)) ||
          (keypairs->previous_keypair.valid &&
           (keypairs->previous_keypair.local_index == receiver))) {
        result = tmp;
        break;
      }
    }
  }
  return result;
}
