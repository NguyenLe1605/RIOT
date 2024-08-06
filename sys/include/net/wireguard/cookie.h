
#ifndef _WIREGUARD_COOKIE_H_
#define _WIREGUARD_COOKIE_H_

#include "messages.h"
#include <stdbool.h>
#include <stdint.h>

struct cookie {
  uint64_t birthdate;
  bool is_valid;
  uint8_t cookie[COOKIE_LEN];
  bool have_sent_mac1;
  uint8_t last_mac1_sent[COOKIE_LEN];
  uint8_t cookie_decryption_key[NOISE_SYMMETRIC_KEY_LEN];
  uint8_t message_mac1_key[NOISE_SYMMETRIC_KEY_LEN];
};

#endif
