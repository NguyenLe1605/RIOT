#include "net/wireguard/peer.h"
#include "crypto/helper.h"
#include "net/wireguard/messages.h"
#include "random.h"

struct wg_peer *
wg_lookup_peer_by_pubkey(struct wg_peer peers[MAX_PEERS_PER_DEVICE],
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
      /* For invalid keypair, we will reuse it?? */
      if (peer->valid) {
        if (peer->keypairs.current_keypair.is_valid) {
          existing = existing ||
                     (result == peer->keypairs.current_keypair.local_index);
        }
        if (peer->keypairs.previous_keypair.is_valid) {
          existing = existing ||
                     (result == peer->keypairs.previous_keypair.local_index);
        }
        if (peer->keypairs.next_keypair.is_valid) {
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
wg_lookup_peer_by_handshake_receiver(struct wg_peer peers[MAX_PEERS_PER_DEVICE],
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

// static void add_new_keypair(wg_peer_t *peer, wg_keypair_t new_keypair);
//
// void keypair_destroy(wg_keypair_t *keypair) {
//   crypto_secure_wipe(keypair, sizeof(wg_keypair_t));
//   keypair->valid = false;
// }
//
// void keypair_update(wg_peer_t *peer, wg_keypair_t *received_keypair) {
//   bool key_is_next = (received_keypair == &peer->next_keypair);
//   if (key_is_next) {
//     peer->prev_keypair = peer->curr_keypair;
//     peer->curr_keypair = peer->next_keypair;
//     keypair_destroy(&peer->next_keypair);
//   }
// }
//
// void wg_start_session(wg_peer_t *peer, bool initiator) {
//   wg_noise_handshake_t *handshake = &peer->handshake;
//   wg_keypair_t new_keypair;
//
//   crypto_secure_wipe(&new_keypair, sizeof(wg_keypair_t));
//   new_keypair.initiator = initiator;
//   new_keypair.local_index = handshake->local_index;
//   new_keypair.remote_index = handshake->remote_index;
//
//   new_keypair.keypair_millis = ztimer_now(ZTIMER_MSEC);
//   new_keypair.sending_valid = true;
//   new_keypair.receiving_valid = true;
//
//   // 5.4.5 Transport Data Key Derivation
//   // (Tsendi = Trecvr, Trecvi = Tsendr) := Kdf2(Ci = Cr,E)
//   if (new_keypair.initiator) {
//     kdf2(new_keypair.sending_key, new_keypair.receiving_key,
//          handshake->chaining_key, NULL, 0);
//   } else {
//     kdf2(new_keypair.receiving_key, new_keypair.sending_key,
//          handshake->chaining_key, NULL, 0);
//   }
//
//   new_keypair.replay_bitmap = 0;
//   new_keypair.replay_counter = 0;
//
//   new_keypair.last_tx = 0;
//   new_keypair.last_rx = 0; // No packets received yet
//
//   new_keypair.valid = true;
//
//   // Eprivi = Epubi = Eprivr = Epubr = Ci = Cr := E
//   crypto_secure_wipe(handshake->ephemeral_private, WG_PUBLIC_KEY_LEN);
//   crypto_secure_wipe(handshake->remote_ephemeral, WG_PUBLIC_KEY_LEN);
//   crypto_secure_wipe(handshake->hash, WG_HASH_LEN);
//   crypto_secure_wipe(handshake->chaining_key, WG_HASH_LEN);
//   handshake->remote_index = 0;
//   handshake->local_index = 0;
//   handshake->valid = false;
//
//   add_new_keypair(peer, new_keypair);
// }
//
// static void add_new_keypair(wg_peer_t *peer, wg_keypair_t new_keypair) {
//   if (new_keypair.initiator) {
//     if (peer->next_keypair.valid) {
//       peer->prev_keypair = peer->next_keypair;
//       keypair_destroy(&peer->next_keypair);
//     } else {
//       peer->prev_keypair = peer->curr_keypair;
//     }
//     peer->curr_keypair = new_keypair;
//   } else {
//     peer->next_keypair = new_keypair;
//     keypair_destroy(&peer->prev_keypair);
//   }
// }
