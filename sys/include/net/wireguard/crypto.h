#ifndef _WIREGUARD_CRYPTO_H_
#define _WIREGUARD_CRYPTO_H_

#include "c25519.h"
#include "crypto/chacha20poly1305.h"
#include "messages.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define WG_BLAKE2S_BLOCK_SIZE (64)

// TODO: add testing

static const uint8_t zerokey[32] = {0};
// perform the ECDH to generate the shared secret from the private and public
// key
bool dh_agree(uint8_t *shared_secret, const uint8_t *privkey,
              const uint8_t *pubkey);

void dh_generate_private_key(uint8_t *key);

bool dh_generate_public_key(uint8_t *pubkey, const uint8_t *privkey);

void mac_key(uint8_t *key, const uint8_t *pubkey, const uint8_t *label,
             size_t label_len);

static inline void dh_clamp_private_key(uint8_t *key) { c25519_prepare(key); }

static inline void aead_encrypt(uint8_t *cipher, const uint8_t *msg,
                                size_t msglen, const uint8_t *aad,
                                size_t aadlen, const uint8_t *key,
                                const uint8_t *nonce) {
  chacha20poly1305_encrypt(cipher, msg, msglen, aad, aadlen, key, nonce);
}

static inline bool aead_decrypt(const uint8_t *cipher, size_t cipherlen,
                                uint8_t *msg, size_t *msglen,
                                const uint8_t *aad, size_t aadlen,
                                const uint8_t *key, const uint8_t *nonce) {
  return chacha20poly1305_decrypt(cipher, cipherlen, msg, msglen, aad, aadlen,
                                  key, nonce) == 1;
}

void mac(uint8_t *dst, const void *message, size_t inlen, const uint8_t *key,
         size_t keylen);

void hmac(uint8_t *result, const uint8_t *key, size_t key_len,
          const uint8_t *msg, size_t msglen);

/* This is Hugo Krawczyk's HKDF:
 *  - https://eprint.iacr.org/2010/264.pdf
 *  - https://tools.ietf.org/html/rfc5869
 */
void kdf(uint8_t *first_dst, uint8_t *second_dst, uint8_t *third_dst,
         const uint8_t *data, size_t first_len, size_t second_len,
         size_t third_len, size_t data_len,
         const uint8_t chaining_key[NOISE_HASH_LEN]);

#endif
