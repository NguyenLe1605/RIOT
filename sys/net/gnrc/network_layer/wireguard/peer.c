#include "net/wireguard/peer.h"
#include "crypto/helper.h"
#include "net/ipv6/addr.h"
#include "net/wireguard/cookie.h"
#include "net/wireguard/device.h"
#include "net/wireguard/messages.h"
#include "net/wireguard/noise.h"
#include "random.h"

struct wg_peer *
peer_lookup_by_pubkey(struct wg_peer peers[MAX_PEERS_PER_DEVICE],
                      const uint8_t pubkey[NOISE_PUBLIC_KEY_LEN]) {
  struct wg_peer *ret_peer = NULL;
  struct wg_peer *peer;
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

struct wg_peer *peer_lookup_by_index(struct wg_peer peers[MAX_PEERS_PER_DEVICE],
                                     uint8_t index) {
  struct wg_peer *result = NULL;
  if (index < MAX_PEERS_PER_DEVICE && peers[index].valid) {
    result = &peers[index];
  }
  return result;
}

struct wg_peer *
peer_lookup_by_allowed_ip(struct wg_peer peers[MAX_PEERS_PER_DEVICE],
                          const ipv6_addr_t *addr) {
  struct wg_peer *peer = NULL;
  struct wg_peer *tmp;
  struct wg_allowed_ip *allowed;
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

struct wg_peer *peer_alloc(struct wg_peer peers[MAX_PEERS_PER_DEVICE]) {
  uint8_t i;
  struct wg_peer *peer = NULL;
  for (i = 0; i < MAX_PEERS_PER_DEVICE; ++i) {
    peer = &peers[i];
    if (!peer->valid) {
      peer->peer_idx = i;
      break;
    }
  }
  return peer;
}

void peer_remove(struct wg_peer *peer) {
  wg_noise_handshake_clear(&peer->handshake);
  wg_noise_keypairs_clear(&peer->keypairs);
  crypto_secure_wipe(peer, sizeof(struct wg_peer));
  peer->valid = false;
}

bool wireguard_peer_init(struct wg_device *wg, struct wg_peer *peer,
                         const uint8_t public_key[NOISE_PUBLIC_KEY_LEN],
                         const uint8_t preshared_key[NOISE_SYMMETRIC_KEY_LEN]) {
  assert(wg);
  assert(peer);
  /* clean up the peer */
  memset(peer, 0, sizeof(struct wg_peer));
  if (!wg->valid) {
    return false;
  }
  peer->device = wg;
  peer->valid = wg_noise_handshake_init(&peer->handshake, &wg->static_identity,
                                        public_key, preshared_key, peer);
  if (peer->valid) {
    wg_cookie_init(&peer->latest_cookie);
    wg_cookie_checker_precompute_peer_keys(peer);
    wg_noise_reset_last_sent_handshake(&peer->last_sent_handshake);
  }
  return peer->valid;
}

bool peer_add_ip(struct wg_peer *peer, ipv6_addr_t *allowed_ip,
                 unsigned int pfx_len) {
  bool result = false;
  struct wg_allowed_ip *allowed;
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

uint32_t wg_generate_unique_index(struct wg_peer peers[MAX_PEERS_PER_DEVICE]) {
  /* generate 32-bit random index that has not been used by any valid handshake
   * or key */
  uint32_t result;
  int i;
  struct wg_peer *peer = NULL;
  bool existing = false;
  do {
    do {
      result = random_uint32();
    } while (result == 0 || result == 0xFFFFFFFF);
    for (i = 0; i < MAX_PEERS_PER_DEVICE; ++i) {
      peer = &peers[i];
      if (peer->valid) {
        if (peer->keypairs.current_keypair.valid) {
          existing = existing ||
                     (result == peer->keypairs.current_keypair.local_index);
        }
        if (peer->keypairs.previous_keypair.valid) {
          existing = existing ||
                     (result == peer->keypairs.previous_keypair.local_index);
        }
        if (peer->keypairs.next_keypair.valid) {
          existing =
              existing || (result == peer->keypairs.next_keypair.local_index);
        }
        if (peer->handshake.valid) {
          existing = existing ||
                     (result == peer->keypairs.current_keypair.local_index);
        }
      }
    }
  } while (existing);
  return result;
}

struct wg_peer *
peer_lookup_by_handshake_receiver(struct wg_peer peers[MAX_PEERS_PER_DEVICE],
                                  uint32_t receiver_index) {
  struct wg_peer *ret_peer = NULL;
  struct wg_peer *peer;
  int i = 0;
  if (peers == NULL) {
    return NULL;
  }
  for (i = 0; i < MAX_PEERS_PER_DEVICE; ++i) {
    peer = &peers[i];
    if (peer->valid && peer->handshake.valid &&
        peer->handshake.local_index == receiver_index) {
      ret_peer = peer;
      break;
    }
  }
  return ret_peer;
}
