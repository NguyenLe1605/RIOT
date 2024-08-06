#ifndef _WIREGUARD_NOISE_H_
#define _WIREGUARD_NOISE_H_

#include "messages.h"
#include "time_units.h"
#include "ztimer.h"
#include <stdbool.h>
#include <stdint.h>

struct wg_peer;

struct noise_replay_counter {
  // sliding window bitmap per rfc 2401 appendix C
  uint32_t replay_bitmap;
  uint64_t replay_counter;
};

struct noise_symmetric_key {
  uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
  uint64_t birthdate;
  bool is_valid;
};

struct noise_keypair {
  uint32_t local_index;
  struct noise_symmetric_key sending;
  uint64_t sending_counter;
  struct noise_symmetric_key receiving;
  struct noise_replay_counter receiving_counter;
  uint32_t remote_index;
  bool i_am_the_initiator;
  bool is_valid;
};

struct noise_keypairs {
  struct noise_keypair current_keypair;
  struct noise_keypair previous_keypair;
  struct noise_keypair next_keypair;
};

struct noise_static_identity {
  uint8_t static_public[NOISE_PUBLIC_KEY_LEN];
  uint8_t static_private[NOISE_PUBLIC_KEY_LEN];
  bool has_identity;
};

enum noise_handshake_state {
  HANDSHAKE_ZEROED,
  HANDSHAKE_CREATED_INITIATION,
  HANDSHAKE_CONSUMED_INITIATION,
  HANDSHAKE_CREATED_RESPONSE,
  HANDSHAKE_CONSUMED_RESPONSE
};

/* Each handshake's lifetime is tied to a peer */
struct noise_handshake {
  bool valid; /* valid when the handshake starts */
  // TODO: use for siphash later?
  uint32_t local_index;
  enum noise_handshake_state state;
  uint64_t last_initiation_consumption;

  struct noise_static_identity *static_identity;

  uint8_t ephemeral_private[NOISE_PUBLIC_KEY_LEN];
  uint8_t remote_ephemeral[NOISE_PUBLIC_KEY_LEN];
  // TODO: may remove later and put to peer
  uint8_t remote_static[NOISE_PUBLIC_KEY_LEN];
  uint8_t precomputed_static_static[NOISE_PUBLIC_KEY_LEN];

  uint8_t preshared_key[NOISE_SYMMETRIC_KEY_LEN];

  uint8_t hash[NOISE_HASH_LEN];
  uint8_t chaining_key[NOISE_HASH_LEN];

  uint8_t latest_timestamp[NOISE_TIMESTAMP_LEN];
  uint32_t remote_index;

  /* Protects all members except the immutable (after noise_handshake_
   * init): remote_static, precomputed_static_static, static_identity.
   */
  // struct rw_semaphore lock;
};

struct wg_device;

void wg_noise_init(void);
void wg_noise_handshake_init(
    struct noise_handshake *handshake,
    struct noise_static_identity *static_identity,
    const uint8_t peer_public_key[NOISE_PUBLIC_KEY_LEN],
    const uint8_t peer_preshared_key[NOISE_SYMMETRIC_KEY_LEN],
    struct wg_peer *peer);
void wg_noise_handshake_clear(struct noise_handshake *handshake);
static inline void wg_noise_reset_last_sent_handshake(uint64_t *handshake_us) {
  *handshake_us =
      ztimer_now(ZTIMER_USEC) - (uint64_t)(REKEY_TIMEOUT + 1) * US_PER_SEC;
}

void wg_noise_keypair_put(struct noise_keypair *keypair, bool unreference_now);
struct noise_keypair *wg_noise_keypair_get(struct noise_keypair *keypair);
void wg_noise_keypairs_clear(struct noise_keypairs *keypairs);
bool wg_noise_received_with_keypair(struct noise_keypairs *keypairs,
                                    struct noise_keypair *received_keypair);
void wg_noise_expire_current_peer_keypairs(struct wg_peer *peer);

void wg_noise_set_static_identity_private_key(
    struct noise_static_identity *static_identity,
    const uint8_t private_key[NOISE_PUBLIC_KEY_LEN]);
void wg_noise_precompute_static_static(struct wg_peer *peer);

bool wg_noise_handshake_create_initiation(
    struct message_handshake_initiation *dst, struct noise_handshake *handshake,
    struct wg_device *wg);
struct wg_peer *
wg_noise_handshake_consume_initiation(struct message_handshake_initiation *src,
                                      struct wg_device *wg);

bool wg_noise_handshake_create_response(struct message_handshake_response *dst,
                                        struct noise_handshake *handshake,
                                        struct wg_device *device);
struct wg_peer *
wg_noise_handshake_consume_response(struct message_handshake_response *src,
                                    struct wg_device *wg);

bool wg_noise_handshake_begin_session(struct noise_handshake *handshake,
                                      struct noise_keypairs *keypairs);

#endif
