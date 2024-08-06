#ifndef _WIREGUARD_MESSAGES_H_
#define _WIREGUARD_MESSAGES_H_

#include "blake2.h"
#include "c25519.h"
#include "crypto/chacha20poly1305.h"
#include <stddef.h>
#include <stdint.h>

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

// TODO: use for replay, may remove it later
// enum counter_values {
//   COUNTER_BITS_TOTAL = 8192,
//   COUNTER_REDUNDANT_BITS = 64,
//   COUNTER_WINDOW_SIZE = COUNTER_BITS_TOTAL - COUNTER_REDUNDANT_BITS
// };

/* Timer/limits */
#define REKEY_AFTER_MESSAGES (1ULL << 60)
#define REJECT_AFTER_MESSAGES (0xFFFFFFFFFFFFFFFFULL - (1ULL << 13))
#define REKEY_AFTER_TIME (120)
#define REJECT_AFTER_TIME (180)
#define REKEY_TIMEOUT (5)
#define KEEPALIVE_TIMEOUT (10)
/* Peers are allocated statically inside the device structure to avoid malloc */
#define MAX_PEERS_PER_DEVICE (1)
/* Maximum number of handshake initiation per second */
#define INITIATIONS_PER_SECOND (2)

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
  uint32_t type;
};

struct message_macs {
  /* the mac of responder's public key, always present and valid */
  uint8_t mac1[COOKIE_LEN];
  /* valid mac for message during under load */
  uint8_t mac2[COOKIE_LEN];
};

// 5.4.2 First Message: Initiator to Responder
struct message_handshake_initiation {
  struct message_header header;
  /* tie subsequent replies to the session begun by this message */
  uint32_t sender_index;
  uint8_t unencrypted_ephemeral[NOISE_PUBLIC_KEY_LEN];
  uint8_t encrypted_static[noise_encrypted_len(NOISE_PUBLIC_KEY_LEN)];
  uint8_t encrypted_timestamp[noise_encrypted_len(NOISE_TIMESTAMP_LEN)];
  struct message_macs macs;
}; /* __attribute__((__packed__))*/

// 5.4.3 Second Message: Responder to Initiator
struct message_handshake_response {
  struct message_header header;
  /* tie subsequent replies to the session begun by this message */
  uint32_t sender_index;
  uint32_t receiver_index;
  uint8_t unencrypted_ephemeral[NOISE_PUBLIC_KEY_LEN];
  uint8_t encrypted_nothing[noise_encrypted_len(0)];
  struct message_macs macs;

} /*__attribute__((__packed__))*/;

// 5.4.6 Subsequent Messages: Transport Data Messages
struct message_transport_data {
  struct message_header header;
  uint32_t receiver_idx;
  uint64_t counter;
  uint8_t encrypted_data[];
} /*__attribute__((__packed__))*/;

// 5.4.7 Under Load: Cookie Reply Message
struct message_cookie_reply {
  struct message_header header;
  /* determined by the initiator msg.sender field */
  uint32_t receiver_idx;
  uint8_t nonce[COOKIE_NONCE_LEN];
  uint8_t encrypted_cookie[noise_encrypted_len(COOKIE_LEN)];
} /*__attribute__((__packed__))*/;

#define message_data_len(plain_len)                                            \
  (noise_encrypted_len(plain_len) + sizeof(struct message_data))

#endif
