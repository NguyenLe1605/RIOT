#include "net/wireguard/crypto.h"
#include "blake2.h"
#include "c25519.h"
#include "crypto/helper.h"
#include "net/wireguard/messages.h"
#include "random.h"
#include <stdint.h>

static inline bool x25519_core(uint8_t *out, const uint8_t *point,
                               const uint8_t *scalar) {
  c25519_smult(out, point, scalar);
  return crypto_equals(out, zerokey, NOISE_SYMMETRIC_KEY_LEN) == 0;
}

static inline bool x25519_base(uint8_t *out, const uint8_t *scalar) {
  return x25519_core(out, c25519_base_x, scalar);
}

bool dh_generate_public_key(uint8_t *pubkey, const uint8_t *privkey) {
  return x25519_base(pubkey, privkey);
}

bool dh_agree(uint8_t *shared_secret, const uint8_t *privkey,
              const uint8_t *pubkey) {
  return x25519_core(shared_secret, pubkey, privkey);
}

void dh_generate_private_key(uint8_t *key) {
  random_bytes(key, NOISE_PRIVATE_KEY_LEN);
  dh_clamp_private_key(key);
}

void hmac(uint8_t *result, const uint8_t *key, size_t key_len,
          const uint8_t *msg, size_t msglen) {
  /* Adapted from appendix example in RFC2104 to use BLAKE2S instead of MD5 -
   https://tools.ietf.org/html/rfc2104 */
  blake2s_state ctx;
  uint8_t k_ipad[BLAKE2S_BLOCKBYTES]; /* inner padding - key XORd with ipad */
  uint8_t k_opad[BLAKE2S_BLOCKBYTES]; /* outer padding - key XORd with opad */

  uint8_t tk[NOISE_HASH_LEN];
  int i;
  /* if key is longer than BLAKE2S_BLOCK_SIZE bytes reset it to key=BLAKE2S(key)
   */
  if (key_len > BLAKE2S_BLOCKBYTES) {
    blake2s_state tctx;
    blake2s_init(&tctx, NOISE_HASH_LEN);
    blake2s_update(&tctx, key, key_len);
    blake2s_final(&tctx, tk, NOISE_HASH_LEN);
    key = tk;
    key_len = NOISE_HASH_LEN;
  }

  /* the HMAC transform looks like:
   * HASH(K XOR opad, HASH(K XOR ipad, text))
   * where K is an n byte key
   * ipad is the byte 0x36 repeated BLAKE2S_BLOCK_SIZE times
   * opad is the byte 0x5c repeated BLAKE2S_BLOCK_SIZE times
   * and text is the data being protected
   * */
  memset(k_ipad, 0, sizeof(k_ipad));
  memset(k_opad, 0, sizeof(k_opad));
  memcpy(k_ipad, key, key_len);
  memcpy(k_opad, key, key_len);

  /* XOR key with ipad and opad values */
  for (i = 0; i < BLAKE2S_BLOCKBYTES; i++) {
    k_ipad[i] ^= 0x36;
    k_opad[i] ^= 0x5c;
  }
  /* perform inner HASH */
  blake2s_init(&ctx, NOISE_HASH_LEN); /* init context for 1st pass */
  blake2s_update(&ctx, k_ipad, BLAKE2S_BLOCKBYTES); /* start with inner pad */
  blake2s_update(&ctx, msg, msglen);                /* then text of datagram */
  blake2s_final(&ctx, result, NOISE_HASH_LEN);      /* finish up 1st pass */

  /* perform outer HASH */
  blake2s_init(&ctx, NOISE_HASH_LEN); /* init context for 2nd pass */
  blake2s_update(&ctx, k_opad, BLAKE2S_BLOCKBYTES); /* start with outer pad */
  blake2s_update(&ctx, result, NOISE_HASH_LEN); /* then results of 1st hash */
  blake2s_final(&ctx, result, NOISE_HASH_LEN);  /* finish up 2nd pass */
}

void kdf(uint8_t *first_dst, uint8_t *second_dst, uint8_t *third_dst,
         const uint8_t *data, size_t first_len, size_t second_len,
         size_t third_len, size_t data_len,
         const uint8_t chaining_key[NOISE_HASH_LEN]) {
  uint8_t output[BLAKE2S_OUTBYTES + 1];
  uint8_t secret[BLAKE2S_OUTBYTES];

  /* Extract entropy from data into secret */
  hmac(secret, chaining_key, NOISE_HASH_LEN, data, data_len);

  if (!first_dst || !first_len)
    goto out;

  /* Expand first key: key = secret, data = 0x1 */
  output[0] = 1;
  hmac(output, secret, BLAKE2S_OUTBYTES, output, 1);
  memcpy(first_dst, output, first_len);

  if (!second_dst || !second_len)
    goto out;

  /* Expand second key: key = secret, data = first-key || 0x2 */
  output[BLAKE2S_OUTBYTES] = 2;
  hmac(output, secret, BLAKE2S_OUTBYTES, output, BLAKE2S_OUTBYTES + 1);
  memcpy(second_dst, output, second_len);

  if (!third_dst || !third_len)
    goto out;

  /* Expand third key: key = secret, data = second-key || 0x3 */
  output[BLAKE2S_OUTBYTES] = 3;
  hmac(output, secret, BLAKE2S_OUTBYTES, output, BLAKE2S_OUTBYTES + 1);
  memcpy(third_dst, output, third_len);

out:
  /* Clear sensitive data from stack */
  crypto_secure_wipe(secret, BLAKE2S_OUTBYTES);
  crypto_secure_wipe(output, BLAKE2S_OUTBYTES + 1);
}

void mix_hash(uint8_t *hash, const uint8_t *src, size_t src_len) {
  blake2s_state ctx;
  blake2s_init(&ctx, NOISE_HASH_LEN);
  blake2s_update(&ctx, hash, NOISE_HASH_LEN);
  blake2s_update(&ctx, src, src_len);
  blake2s_final(&ctx, hash, NOISE_HASH_LEN);
}
