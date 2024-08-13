
#ifndef _WIREGUARD_COOKIE_H_
#define _WIREGUARD_COOKIE_H_

#include "messages.h"
#include "net/gnrc/pkt.h"
#include "net/sock/udp.h"
#include <stdbool.h>
#include <stdint.h>

struct wg_peer;

struct cookie_checker {
  uint8_t secret[NOISE_HASH_LEN];
  uint8_t cookie_encryption_key[NOISE_SYMMETRIC_KEY_LEN];
  uint8_t message_mac1_key[NOISE_SYMMETRIC_KEY_LEN];
  uint64_t secret_birthdate;
  struct wg_device *device;
};

struct cookie {
  uint64_t birthdate;
  bool is_valid;
  uint8_t cookie[COOKIE_LEN];
  bool have_sent_mac1;
  uint8_t last_mac1_sent[COOKIE_LEN];
  uint8_t cookie_decryption_key[NOISE_SYMMETRIC_KEY_LEN];
  uint8_t message_mac1_key[NOISE_SYMMETRIC_KEY_LEN];
};

enum cookie_mac_state {
  INVALID_MAC,
  VALID_MAC_BUT_NO_COOKIE,
  VALID_MAC_WITH_COOKIE_BUT_RATELIMITED,
  VALID_MAC_WITH_COOKIE
};

void wg_cookie_checker_init(struct cookie_checker *checker,
                            struct wg_device *wg);
void wg_cookie_checker_precompute_device_keys(struct cookie_checker *checker);
void wg_cookie_checker_precompute_peer_keys(struct wg_peer *peer);
void wg_cookie_init(struct cookie *cookie);

enum cookie_mac_state wg_cookie_validate_packet(struct cookie_checker *checker,
                                                uint8_t *buf, size_t len,
                                                sock_udp_ep_t *remote,
                                                bool check_cookie);
void wg_cookie_add_mac_to_packet(void *message, size_t len,
                                 struct wg_peer *peer);

void wg_cookie_message_create(struct message_cookie_reply *dst, uint8_t *buf,
                              size_t len, sock_udp_ep_t *remote, uint32_t index,
                              struct cookie_checker *checker);
void wg_cookie_message_consume(struct message_cookie_reply *src,
                               struct wg_device *wg);

#endif
