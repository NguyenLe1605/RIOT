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
 * @brief       Implementation of NoiseIKPsk2 hanshake for wireguard
 *
 * @author      Nguyen Le Hoang Dang <lhdnguyen2002@gmail.com>
 */

#ifndef WIREGUARD_NOISE_H
#define WIREGUARD_NOISE_H

#include "time_units.h"
#include "wireguard_constants.h"
#include "wireguard_messages.h"
#include "ztimer.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct noise_static_identity {
  uint8_t static_public[NOISE_PUBLIC_KEY_LEN];
  uint8_t static_private[NOISE_PUBLIC_KEY_LEN];
  bool has_identity;
};

struct noise_symmetric_key {
  uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
  uint32_t birthdate;
  bool valid;
};

struct noise_replay_window {
  uint32_t bitmap;
  uint64_t last_seq;
};

struct noise_keypair {
  uint32_t local_index;
  struct noise_symmetric_key sending;
  /* TODO: change to uint32_t if needed */
  uint64_t sending_counter;
  struct noise_symmetric_key receiving;
  struct noise_replay_window receiving_counter;
  uint32_t remote_index;
  uint32_t birthdate;
  bool initiator;
  bool valid;
};

struct noise_keypairs {
  struct noise_keypair current_keypair;
  struct noise_keypair previous_keypair;
  struct noise_keypair next_keypair;
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
  bool handshaking; /* has wireguard started handshaking */
  uint32_t local_index;
  uint32_t remote_index;

  enum noise_handshake_state state;
  struct noise_static_identity *static_identity;

  uint8_t ephemeral_private[NOISE_PUBLIC_KEY_LEN];
  uint8_t remote_ephemeral[NOISE_PUBLIC_KEY_LEN];
  uint8_t remote_static[NOISE_PUBLIC_KEY_LEN];
  uint8_t precomputed_static_static[NOISE_PUBLIC_KEY_LEN];

  uint8_t preshared_key[NOISE_SYMMETRIC_KEY_LEN];

  uint8_t hash[NOISE_HASH_LEN];
  uint8_t chaining_key[NOISE_HASH_LEN];

  /* 5.1 Silence is a Virtue: The responder keeps track of the greatest
   * timestamp received per peer */
  uint8_t greatest_timestamp[NOISE_TIMESTAMP_LEN];
};

struct wireguard_peer;
struct wireguard_device;

void wireguard_noise_init(void);
bool wireguard_noise_handshake_init(
    struct noise_handshake *handshake,
    struct noise_static_identity *static_identity,
    const uint8_t peer_public_key[NOISE_PUBLIC_KEY_LEN],
    const uint8_t peer_preshared_key[NOISE_SYMMETRIC_KEY_LEN],
    struct wireguard_peer *peer);

void wireguard_noise_set_static_identity_private_key(
    struct noise_static_identity *static_identity,
    const uint8_t private_key[NOISE_PUBLIC_KEY_LEN]);
bool wireguard_noise_precompute_static_static(struct wireguard_peer *peer);

bool wireguard_noise_handshake_create_initiation(
    struct message_handshake_initiation *dst, struct noise_handshake *handshake,
    struct wireguard_device *wg);

struct wireguard_peer *wireguard_noise_handshake_consume_initiation(
    struct message_handshake_initiation *src, struct wireguard_device *wg);

bool wireguard_noise_handshake_create_response(
    struct message_handshake_response *dst, struct noise_handshake *handshake,
    struct wireguard_device *device);
struct wireguard_peer *wireguard_noise_handshake_consume_response(
    struct message_handshake_response *src, struct wireguard_device *wg);

bool wireguard_noise_handshake_begin_session(struct noise_handshake *handshake,
                                             struct noise_keypairs *keypairs);

static inline void
wireguard_noise_reset_last_sent_handshake(uint32_t *handshake_ms) {
  *handshake_ms =
      ztimer_now(ZTIMER_MSEC) - (uint32_t)(REKEY_TIMEOUT + 1) * MS_PER_SEC;
}

/* Zeroize the keypair and mark the memory pointed by keypair is reusable */
void wireguard_noise_destroy_keypair(struct noise_keypair *keypair);
bool wireguard_noise_received_with_keypair(
    struct noise_keypairs *keypairs, struct noise_keypair *received_keypair);

#ifdef __cplusplus
}
#endif

#endif /* WIREGUARD_NOISE_H */
/** @} */
