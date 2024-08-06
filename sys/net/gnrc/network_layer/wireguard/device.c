#include "net/wireguard/device.h"
#include "blake2.h"
#include "crypto/helper.h"
#include "net/ipv6/addr.h"
#include "net/sock/async/types.h"
#include "net/wireguard/crypto.h"
#include "net/wireguard/messages.h"
#include "net/wireguard/noise.h"
#include "net/wireguard/peer.h"
#include "random.h"
#include "ztimer.h"
#include <stdint.h>
#include <string.h>

#define REPLAY_WINDOW_SIZE (32)
// For HMAC calculation
#define WG_BLAKE2S_BLOCK_SIZE (64)
#define COOKIE_NONCE_LEN (24)

// TODO: refactor it to peer.h

// wg_peer_t *peer_alloc(wg_device_t *device) {
//   int i;
//   wg_peer_t *result = NULL;
//   wg_peer_t *tmp;
//   for (i = 0; i < WG_MAX_PEERS; ++i) {
//     tmp = &device->peers[i];
//     if (!tmp->valid) {
//       result = tmp;
//       break;
//     }
//   }
//   return result;
// }
//
// wg_peer_t *peer_lookup_by_pubkey(wg_device_t *device, const uint8_t *pubkey)
// {
//   int i;
//   wg_peer_t *result = NULL;
//   wg_peer_t *tmp;
//   for (i = 0; i < WG_MAX_PEERS; ++i) {
//     tmp = &device->peers[i];
//     if (crypto_equals(tmp->pubkey, pubkey, WG_PUBLIC_KEY_LEN)) {
//       result = tmp;
//       break;
//     }
//   }
//   return result;
// }
//
// // TODO: considering remove it later for better peer acknowledge its position
// // inside the container
// uint8_t lookup_index_for_peer(wg_device_t *device, wg_peer_t *peer) {
//   uint8_t result = 0xFF;
//   uint8_t i;
//   for (i = 0; i < WG_MAX_PEERS; ++i) {
//     if (peer == &device->peers[i]) {
//       result = i;
//       break;
//     }
//   }
//   return result;
// }
//
// wg_peer_t *peer_lookup_by_index(wg_device_t *device, uint8_t index) {
//   wg_peer_t *result = NULL;
//   if (index < WG_MAX_PEERS && device->peers[index].valid) {
//     result = &device->peers[index];
//   }
//   return result;
// }
//
// wg_peer_t *peer_lookup_by_receiver(wg_device_t *device, uint32_t receiver) {
//   wg_peer_t *result = NULL;
//   wg_peer_t *tmp;
//   int x;
//   for (x = 0; x < WG_MAX_PEERS; x++) {
//     tmp = &device->peers[x];
//     if (!tmp->valid) {
//       continue;
//     }
//     if ((tmp->curr_keypair.valid &&
//          (tmp->curr_keypair.local_index == receiver)) ||
//         (tmp->next_keypair.valid &&
//          (tmp->next_keypair.local_index == receiver)) ||
//         (tmp->prev_keypair.valid &&
//          (tmp->prev_keypair.local_index == receiver))) {
//       result = tmp;
//       break;
//     }
//   }
//   return result;
// }
//
// wg_peer_t *peer_lookup_by_handshake(wg_device_t *device, uint32_t receiver) {
//   wg_peer_t *result = NULL;
//   wg_peer_t *tmp;
//   int x;
//   for (x = 0; x < WG_MAX_PEERS; x++) {
//     tmp = &device->peers[x];
//     if (!tmp->valid) {
//       continue;
//     }
//     if (tmp->handshake.valid && tmp->handshake.initiator &&
//         (tmp->handshake.local_index == receiver)) {
//       result = tmp;
//       break;
//     }
//   }
//   return result;
// }
//
// bool wg_expired(uint32_t birthday_millis, uint32_t valid_seconds) {
//   uint32_t diff = ztimer_now(ZTIMER_MSEC) - birthday_millis;
//   return (diff >= valid_seconds * 1000);
// }
//
// bool wg_check_replay(wg_keypair_t *keypair, uint64_t seq) {
//   // Implementation of sliding windows algorithm from appendix C
//   // https://datatracker.ietf.org/doc/html/rfc2401
//   uint32_t diff;
//
//   // wireguard packet start from 0, but the algorithm requires to start from
//   1 seq++; if (seq == 0) // first == 0 or wrapped
//     return false;
//
//   if (seq > keypair->replay_counter) {
//     diff = seq - keypair->replay_counter;
//     if (diff < REPLAY_WINDOW_SIZE) { // In Window
//       keypair->replay_bitmap <<= diff;
//       keypair->replay_bitmap |= 1;
//     } else {
//       keypair->replay_bitmap = 1;
//     }
//
//     keypair->replay_counter = seq;
//     return true;
//   }
//
//   diff = keypair->replay_counter - seq;
//   if (diff > REPLAY_WINDOW_SIZE) // Too old or wrapped
//     return false;
//
//   if (keypair->replay_bitmap & (1UL << diff)) // already seen
//     return false;
//   keypair->replay_bitmap |= (1UL << diff); // mark as seen
//
//   return true; // out of order but not replay packet
// }
//
// wg_keypair_t *get_keypair_for_idx(wg_peer_t *peer, uint32_t idx) {
//   if (peer->curr_keypair.valid && peer->curr_keypair.local_index == idx) {
//     return &peer->curr_keypair;
//   } else if (peer->next_keypair.valid &&
//              peer->next_keypair.local_index == idx) {
//     return &peer->next_keypair;
//   } else if (peer->prev_keypair.valid &&
//              peer->prev_keypair.local_index == idx) {
//     return &peer->prev_keypair;
//   }
//   return NULL;
// }
//
// bool wg_validate_mac1(wg_device_t *device, const uint8_t *data, size_t len,
//                       const uint8_t *mac1) {
//   bool result = false;
//   uint8_t calculated[WG_COOKIE_LEN];
//   mac(calculated, data, len, device->label_mac1_key, WG_SESSION_KEY_LEN);
//   if (crypto_equals(calculated, mac1, WG_MAC_LEN)) {
//     result = true;
//   }
//   return result;
// }
//
// bool wg_validate_mac2(wg_device_t *device, const uint8_t *data, size_t len,
//                       uint8_t *source_addr_port, size_t source_length,
//                       const uint8_t *mac2) {
//   bool result = false;
//   uint8_t cookie[WG_COOKIE_LEN];
//   uint8_t calculated[WG_COOKIE_LEN];
//
//   generate_peer_cookie(device, cookie, source_addr_port, source_length);
//
//   mac(calculated, data, len, cookie, WG_COOKIE_LEN);
//   if (crypto_equals(calculated, mac2, WG_COOKIE_LEN)) {
//     result = true;
//   }
//   return result;
// }
//
