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
 * @brief       Implementation for cookie messages
 *
 * @author      Nguyen Le Hoang Dang <lhdnguyen2002@gmail.com>
 */

#ifndef WIREGUARD_COOKIE_H
#define WIREGUARD_COOKIE_H

#include "net/sock/udp.h"
#include "wireguard_constants.h"
#include "wireguard_messages.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct wireguard_peer;
struct wireguard_device;

struct cookie_checker {
  uint8_t secret[NOISE_HASH_LEN];
  uint8_t cookie_encryption_key[NOISE_SYMMETRIC_KEY_LEN];
  uint8_t message_mac1_key[NOISE_SYMMETRIC_KEY_LEN];
  uint32_t secret_birthdate;
  struct wireguard_device *device;
};

struct cookie {
  uint32_t birthdate;
  bool valid;
  uint8_t cookie[COOKIE_LEN];
  bool have_sent_mac1;
  uint8_t last_mac1_sent[COOKIE_LEN];
  uint8_t cookie_decryption_key[NOISE_SYMMETRIC_KEY_LEN];
  uint8_t message_mac1_key[NOISE_SYMMETRIC_KEY_LEN];
};

enum cookie_mac_state {
  INVALID_MAC,
  VALID_MAC_BUT_NO_COOKIE,
  VALID_MAC_WITH_COOKIE
};

void wireguard_cookie_checker_init(struct cookie_checker *checker,
                                   struct wireguard_device *wg);
void wireguard_cookie_checker_precompute_device_keys(
    struct cookie_checker *checker);
void wireguard_cookie_checker_precompute_peer_keys(struct wireguard_peer *peer);
void wireguard_cookie_init(struct cookie *cookie);

enum cookie_mac_state
wireguard_cookie_validate_packet(struct cookie_checker *checker, uint8_t *buf,
                                 size_t len, sock_udp_ep_t *remote,
                                 bool check_cookie);
void wireguard_cookie_add_mac_to_packet(void *message, size_t len,
                                        struct wireguard_peer *peer);

void wireguard_cookie_message_create(struct message_cookie_reply *dst,
                                     uint8_t *buf, size_t len,
                                     sock_udp_ep_t *remote, uint32_t index,
                                     struct cookie_checker *checker);
bool wireguard_cookie_message_consume(struct message_cookie_reply *src,
                                      struct wireguard_device *wg);

#ifdef __cplusplus
}
#endif

#endif /* WIREGUARD_COOKIE_H */
/** @} */
