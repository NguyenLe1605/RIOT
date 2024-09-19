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
 * @brief       Internal addresses, registers and constants
 *
 * @author      Nguyen Le Hoang Dang <lhdnguyen2002@gmail.com>
 */

#ifndef WIREGUARD_CONSTANTS_H
#define WIREGUARD_CONSTANTS_H

#include "blake2.h"
#include "c25519.h"
#include "crypto/chacha20poly1305.h"
#include "time_units.h"

#ifdef __cplusplus
extern "C" {
#endif

/* define here the addresses, register and constants of the driver */
#define IPV6_ADDR_BYTE_LEN (16)
#define UNDER_LOAD_EVENT_QUEUE_SIZE (12)
#define WIREGUARD_NETIF_MTU (1420)
#define WIREGUARD_DEFAULT_UDP_PORT (51820)

#ifndef WIREGUARD_NETIF_PRIO
#define WIREGUARD_NETIF_PRIO GNRC_NETIF_PRIO
#endif

#ifndef WIREGUARD_NETIF_STACKSIZE
/* extra 1K bytes for c25519 */
#define WIREGUARD_NETIF_STACKSIZE (THREAD_STACKSIZE_DEFAULT + 1024)
#endif

#ifndef MAX_SRC_IPS
#define MAX_SRC_IPS (2)
#endif

#ifndef MAX_PEERS_PER_DEVICE
#define MAX_PEERS_PER_DEVICE (1)
#endif

#define WIREGUARD_INVALID_INDEX (0xff)
#define BASE64_PRIVATE_KEY_LEN (44)
#define BASE64_PUBLIC_KEY_LEN BASE64_PRIVATE_KEY_LEN

#define WIREGUARD_KEEPALIVE_DEFAULT (0xffff)
/* TODO: define it so clangd shut up */
// #define C25519_EXPONENT_SIZE (32)

#define CURVE25519_KEY_SIZE C25519_EXPONENT_SIZE

enum noise_lengths {
  NOISE_PUBLIC_KEY_LEN = CURVE25519_KEY_SIZE,
  NOISE_PRIVATE_KEY_LEN = CURVE25519_KEY_SIZE,
  NOISE_SYMMETRIC_KEY_LEN = CHACHA20POLY1305_KEY_BYTES,
  NOISE_TIMESTAMP_LEN = sizeof(uint64_t) + sizeof(uint32_t),
  NOISE_AUTHTAG_LEN = CHACHA20POLY1305_TAG_BYTES,
  NOISE_HASH_LEN = BLAKE2S_OUTBYTES,
};

#define noise_encrypted_len(plain_len) ((plain_len) + NOISE_AUTHTAG_LEN)

enum cookie_values {
  COOKIE_SECRET_MAX_AGE = 2 * 60,
  COOKIE_SECRET_LATENCY = 5,
  COOKIE_NONCE_LEN = XCHACHA20POLY1305_NONCE_BYTES,
  COOKIE_LEN = 16
};

/* Timer/limits */
#define REKEY_AFTER_MESSAGES (1ULL << 60)
#define REJECT_AFTER_MESSAGES (0xFFFFFFFFFFFFFFFFULL - (1ULL << 13))
enum limits {
  REKEY_AFTER_TIME = 120,
  REJECT_AFTER_TIME = 180,
  REKEY_TIMEOUT = 5,
  KEEPALIVE_TIMEOUT = 10,
  /* Peers are allocated statically inside the device structure to avoid malloc
   */
  /* Maximum number of handshake initiation per second */
  INITIATIONS_PER_SECOND = 2,
  MAX_TIMER_HANDSHAKES = 90 / REKEY_TIMEOUT,
  REKEY_TIMEOUT_JITTER_MAX_MS = MS_PER_SEC / 3,
};

#ifdef __cplusplus
}
#endif

#endif /* WIREGUARD_CONSTANTS_H */
/** @} */
