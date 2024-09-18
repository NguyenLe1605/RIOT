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
 * @brief       Definition of wireguard messages
 *
 * @author      Nguyen Le Hoang Dang <lhdnguyen2002@gmail.com>
 */

#ifndef WIREGUARD_MESSAGES_H
#define WIREGUARD_MESSAGES_H

#include "byteorder.h"
#include "wireguard_constants.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TRANSPORT_DATA_HEADER_LEN (16)

enum message_type {
  MESSAGE_INVALID = 0,
  MESSAGE_HANDSHAKE_INITIATION = 1,
  MESSAGE_HANDSHAKE_RESPONSE = 2,
  MESSAGE_HANDSHAKE_COOKIE = 3,
  MESSAGE_DATA = 4
};

struct message_header {
  /* The actual layout of this that we want is:
   * uint8_t type
   * uint8_t reserved_zero[3]
   *
   * But it turns out that by encoding this as little endian,
   * we achieve the same thing, and it makes checking faster.
   */
  le_uint32_t type;
} __attribute__((__packed__));

struct message_macs {
  /* the mac of responder's public key, always present and valid */
  uint8_t mac1[COOKIE_LEN];
  /* valid mac for message during under load */
  uint8_t mac2[COOKIE_LEN];
} __attribute__((__packed__));

// 5.4.2 First Message: Initiator to Responder
struct message_handshake_initiation {
  struct message_header header;
  /* tie subsequent replies to the session begun by this message */
  le_uint32_t sender_index;
  uint8_t unencrypted_ephemeral[NOISE_PUBLIC_KEY_LEN];
  uint8_t encrypted_static[noise_encrypted_len(NOISE_PUBLIC_KEY_LEN)];
  uint8_t encrypted_timestamp[noise_encrypted_len(NOISE_TIMESTAMP_LEN)];
  struct message_macs macs;
} __attribute__((__packed__));

// 5.4.3 Second Message: Responder to Initiator
struct message_handshake_response {
  struct message_header header;
  /* tie subsequent replies to the session begun by this message */
  le_uint32_t sender_index;
  le_uint32_t receiver_index;
  uint8_t unencrypted_ephemeral[NOISE_PUBLIC_KEY_LEN];
  uint8_t encrypted_nothing[noise_encrypted_len(0)];
  struct message_macs macs;

} __attribute__((__packed__));

// 5.4.6 Subsequent Messages: Transport Data Messages
struct message_transport_data {
  struct message_header header;
  le_uint32_t receiver_idx;
  le_uint64_t counter;
  uint8_t encrypted_data[];
} __attribute__((__packed__));

// 5.4.7 Under Load: Cookie Reply Message
struct message_cookie_reply {
  struct message_header header;
  /* determined by the initiator msg.sender field */
  le_uint32_t receiver_idx;
  uint8_t nonce[COOKIE_NONCE_LEN];
  uint8_t encrypted_cookie[noise_encrypted_len(COOKIE_LEN)];
} __attribute__((__packed__));

#define message_data_len(plain_len)                                            \
  (noise_encrypted_len(plain_len) + sizeof(struct message_data))

#endif

#ifdef __cplusplus
}
#endif

/** @} */
