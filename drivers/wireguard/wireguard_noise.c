#include "wireguard_noise.h"
#include "blake2.h"
#include "c25519.h"
#include "crypto/helper.h"
#include "random.h"
#include "wireguard_constants.h"
#include "wireguard_internal.h"
#include "wireguard_peer.h"
#include "ztimer.h"
#include <string.h>

/* This implements Noise_IKpsk2:
 *
 * <- s
 * ******
 * -> e, es, s, ss, {t}
 * <- e, ee, se, psk, {}
 */

static const uint8_t construction[37] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const uint8_t identifier[34] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
static uint8_t handshake_init_hash[NOISE_HASH_LEN];
static uint8_t handshake_init_chaining_key[NOISE_HASH_LEN];
static const uint8_t zerokey[32] = {0};

/* crypto helper for noise protocols */
static inline bool x25519_core(uint8_t *out, const uint8_t *point,
                               const uint8_t *scalar) {
  c25519_smult(out, point, scalar);
  return crypto_equals(out, zerokey, NOISE_SYMMETRIC_KEY_LEN) == 0;
}
static inline bool x25519_base(uint8_t *out, const uint8_t *scalar) {
  return x25519_core(out, c25519_base_x, scalar);
}
static inline void ecdh_clamp_private_key(uint8_t *key) { c25519_prepare(key); }
static inline bool ecdh_agree(uint8_t *shared_secret, const uint8_t *privkey,
                              const uint8_t *pubkey) {
  return x25519_core(shared_secret, pubkey, privkey);
}
static inline bool ecdh_generate_public_key(uint8_t *pubkey,
                                            const uint8_t *privkey) {
  return x25519_base(pubkey, privkey);
}
static void ecdh_generate_private_key(uint8_t *key);
static void mix_hash(uint8_t *hash, const uint8_t *src, size_t src_len);
static void hmac(uint8_t *result, const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msglen);
static void kdf(uint8_t *first_dst, uint8_t *second_dst, uint8_t *third_dst,
                const uint8_t *data, size_t first_len, size_t second_len,
                size_t third_len, size_t data_len,
                const uint8_t chaining_key[NOISE_HASH_LEN]);
static void derive_keys(struct noise_symmetric_key *first_dst,
                        struct noise_symmetric_key *second_dst,
                        const uint8_t chaining_key[NOISE_HASH_LEN]);
static bool mix_dh(uint8_t chaining_key[NOISE_HASH_LEN],
                   uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
                   const uint8_t private[NOISE_PUBLIC_KEY_LEN],
                   const uint8_t public[NOISE_PUBLIC_KEY_LEN]);
static bool mix_precomputed_dh(uint8_t chaining_key[NOISE_HASH_LEN],
                               uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
                               const uint8_t precomputed[NOISE_PUBLIC_KEY_LEN]);
static void mix_psk(uint8_t chaining_key[NOISE_HASH_LEN],
                    uint8_t hash[NOISE_HASH_LEN],
                    uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
                    const uint8_t psk[NOISE_SYMMETRIC_KEY_LEN]);
static void handshake_init(uint8_t chaining_key[NOISE_HASH_LEN],
                           uint8_t hash[NOISE_HASH_LEN],
                           const uint8_t remote_static[NOISE_PUBLIC_KEY_LEN]);
static void handshake_zero(struct noise_handshake *handshake);
static void message_encrypt(uint8_t *dst_ciphertext,
                            const uint8_t *src_plaintext, size_t src_len,
                            uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
                            uint8_t hash[NOISE_HASH_LEN]);
static bool message_decrypt(uint8_t *dst_plaintext,
                            const uint8_t *src_ciphertext, size_t src_len,
                            uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
                            uint8_t hash[NOISE_HASH_LEN]);
static void message_ephemeral(uint8_t ephemeral_dst[NOISE_PUBLIC_KEY_LEN],
                              const uint8_t ephemeral_src[NOISE_PUBLIC_KEY_LEN],
                              uint8_t chaining_key[NOISE_HASH_LEN],
                              uint8_t hash[NOISE_HASH_LEN]);
static void tai64n_now(uint8_t *buf);
static void add_new_keypair(struct noise_keypairs *keypairs,
                            struct noise_keypair *new_keypair);

void wireguard_noise_init(void) {
  blake2s_state s;
  /* Ci := Hash(Construction) */
  blake2s(handshake_init_chaining_key, construction, NULL, NOISE_HASH_LEN,
          sizeof(construction), 0);

  /* Pre-calculate initial handshake hash: Hi := Hash(Ci || Identifier) */
  blake2s_init(&s, NOISE_HASH_LEN);
  blake2s_update(&s, handshake_init_chaining_key,
                 sizeof(handshake_init_chaining_key));
  blake2s_update(&s, identifier, sizeof(identifier));
  blake2s_final(&s, handshake_init_hash, sizeof(handshake_init_hash));
}

/* Precompute ss, false if the generated static public key is invalid */
bool wireguard_noise_precompute_static_static(struct wireguard_peer *peer) {
  if (!peer->handshake.static_identity->has_identity ||
      !ecdh_agree(peer->handshake.precomputed_static_static,
                  peer->handshake.static_identity->static_private,
                  peer->handshake.remote_static)) {
    crypto_secure_wipe(peer->handshake.precomputed_static_static,
                       NOISE_PUBLIC_KEY_LEN);
    return false;
  }
  return true;
}

bool wireguard_noise_handshake_init(
    struct noise_handshake *handshake,
    struct noise_static_identity *static_identity,
    const uint8_t peer_public_key[NOISE_PUBLIC_KEY_LEN],
    const uint8_t peer_preshared_key[NOISE_SYMMETRIC_KEY_LEN],
    struct wireguard_peer *peer) {
  memset(handshake, 0, sizeof(*handshake));
  memcpy(handshake->remote_static, peer_public_key, NOISE_PUBLIC_KEY_LEN);
  if (peer_preshared_key) {
    memcpy(handshake->preshared_key, peer_preshared_key,
           NOISE_SYMMETRIC_KEY_LEN);
  } else {
    crypto_secure_wipe(handshake->preshared_key, NOISE_SYMMETRIC_KEY_LEN);
  }
  handshake->static_identity = static_identity;
  handshake->state = HANDSHAKE_ZEROED;
  handshake->handshaking = false;
  memset(handshake->greatest_timestamp, 0, NOISE_TIMESTAMP_LEN);
  return wireguard_noise_precompute_static_static(peer);
}

void wireguard_noise_set_static_identity_private_key(
    struct noise_static_identity *static_identity,
    const uint8_t private_key[NOISE_PUBLIC_KEY_LEN]) {
  memcpy(static_identity->static_private, private_key, NOISE_PUBLIC_KEY_LEN);
  ecdh_clamp_private_key(static_identity->static_private);
  static_identity->has_identity =
      ecdh_generate_public_key(static_identity->static_public, private_key);
}

bool wireguard_noise_handshake_create_initiation(
    struct message_handshake_initiation *dst, struct noise_handshake *handshake,
    struct wireguard_device *wg) {
  uint8_t timestamp[NOISE_TIMESTAMP_LEN];
  uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
  bool ret = false;

  if (unlikely(!handshake->static_identity->has_identity))
    goto out;

  dst->header.type = byteorder_htoll(MESSAGE_HANDSHAKE_INITIATION);

  handshake_init(handshake->chaining_key, handshake->hash,
                 handshake->remote_static);

  /* e */
  ecdh_generate_private_key(handshake->ephemeral_private);
  if (!ecdh_generate_public_key(dst->unencrypted_ephemeral,
                                handshake->ephemeral_private))
    goto out;

  message_ephemeral(dst->unencrypted_ephemeral, dst->unencrypted_ephemeral,
                    handshake->chaining_key, handshake->hash);

  /* es */
  if (!mix_dh(handshake->chaining_key, key, handshake->ephemeral_private,
              handshake->remote_static))
    goto out;

  /* s */
  message_encrypt(dst->encrypted_static,
                  handshake->static_identity->static_public,
                  NOISE_PUBLIC_KEY_LEN, key, handshake->hash);

  /* ss */
  if (!mix_precomputed_dh(handshake->chaining_key, key,
                          handshake->precomputed_static_static))
    goto out;

  /* {t} */
  tai64n_now(timestamp);
  message_encrypt(dst->encrypted_timestamp, timestamp, NOISE_TIMESTAMP_LEN, key,
                  handshake->hash);

  handshake->local_index = wireguard_generate_unique_index(wg);
  dst->sender_index = byteorder_htoll(handshake->local_index);

  handshake->state = HANDSHAKE_CREATED_INITIATION;
  handshake->handshaking = true;
  ret = true;

out:
  crypto_secure_wipe(key, NOISE_SYMMETRIC_KEY_LEN);
  return ret;
}

struct wireguard_peer *wireguard_noise_handshake_consume_initiation(
    struct message_handshake_initiation *src, struct wireguard_device *wg) {
  struct wireguard_peer *peer = NULL, *ret_peer = NULL;
  struct noise_handshake *handshake;
  bool replay_attack, flood_attack;
  uint32_t now;
  uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
  uint8_t chaining_key[NOISE_HASH_LEN];
  uint8_t hash[NOISE_HASH_LEN];
  uint8_t s[NOISE_PUBLIC_KEY_LEN];
  uint8_t e[NOISE_PUBLIC_KEY_LEN];
  uint8_t t[NOISE_TIMESTAMP_LEN];

  if (unlikely(!wg->static_identity.has_identity))
    goto out;

  handshake_init(chaining_key, hash, wg->static_identity.static_public);

  /* e */
  message_ephemeral(e, src->unencrypted_ephemeral, chaining_key, hash);

  /* es */
  if (!mix_dh(chaining_key, key, wg->static_identity.static_private, e))
    goto out;

  /* s */
  if (!message_decrypt(s, src->encrypted_static, sizeof(src->encrypted_static),
                       key, hash))
    goto out;

  /* Lookup which peer we're actually talking to */
  peer = wireguard_peer_lookup_by_pubkey(wg->peers, s);
  if (!peer)
    goto out;
  handshake = &peer->handshake;

  /* ss */
  if (!mix_precomputed_dh(chaining_key, key,
                          handshake->precomputed_static_static))
    goto out;

  /* {t} */
  if (!message_decrypt(t, src->encrypted_timestamp,
                       sizeof(src->encrypted_timestamp), key, hash))
    goto out;

  now = ztimer_now(ZTIMER_MSEC);
  replay_attack =
      memcmp(t, handshake->greatest_timestamp, NOISE_TIMESTAMP_LEN) <= 0;
  /* we can only get 2 maximum initiations per peer every second */
  flood_attack = handshake->last_initiation_consumption +
                     (MS_PER_SEC / INITIATIONS_PER_SECOND) >
                 now;

  if (replay_attack || flood_attack)
    goto out;

  /* Success! Copy everything to peer */
  memcpy(handshake->remote_ephemeral, e, NOISE_PUBLIC_KEY_LEN);
  if (memcmp(t, handshake->greatest_timestamp, NOISE_TIMESTAMP_LEN) > 0)
    memcpy(handshake->greatest_timestamp, t, NOISE_TIMESTAMP_LEN);
  memcpy(handshake->hash, hash, NOISE_HASH_LEN);
  memcpy(handshake->chaining_key, chaining_key, NOISE_HASH_LEN);
  handshake->remote_index = byteorder_ltohl(src->sender_index);
  now = ztimer_now(ZTIMER_MSEC);
  if (handshake->last_initiation_consumption < now) {
    handshake->last_initiation_consumption = now;
  }
  handshake->state = HANDSHAKE_CONSUMED_INITIATION;
  handshake->handshaking = true;
  ret_peer = peer;

out:
  crypto_secure_wipe(key, NOISE_SYMMETRIC_KEY_LEN);
  crypto_secure_wipe(hash, NOISE_HASH_LEN);
  crypto_secure_wipe(chaining_key, NOISE_HASH_LEN);
  return ret_peer;
}

bool wireguard_noise_handshake_create_response(
    struct message_handshake_response *dst, struct noise_handshake *handshake,
    struct wireguard_device *wg) {
  uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
  bool ret = false;

  if (handshake->state != HANDSHAKE_CONSUMED_INITIATION)
    goto out;

  dst->header.type = byteorder_htoll(MESSAGE_HANDSHAKE_RESPONSE);
  dst->receiver_index = byteorder_htoll(handshake->remote_index);

  /* e */
  ecdh_generate_private_key(handshake->ephemeral_private);
  if (!ecdh_generate_public_key(dst->unencrypted_ephemeral,
                                handshake->ephemeral_private))
    goto out;

  message_ephemeral(dst->unencrypted_ephemeral, dst->unencrypted_ephemeral,
                    handshake->chaining_key, handshake->hash);

  /* ee */
  if (!mix_dh(handshake->chaining_key, NULL, handshake->ephemeral_private,
              handshake->remote_ephemeral))
    goto out;

  /* se */
  if (!mix_dh(handshake->chaining_key, NULL, handshake->ephemeral_private,
              handshake->remote_static))
    goto out;

  /* psk */
  mix_psk(handshake->chaining_key, handshake->hash, key,
          handshake->preshared_key);

  /* {} */
  message_encrypt(dst->encrypted_nothing, NULL, 0, key, handshake->hash);

  handshake->local_index = wireguard_generate_unique_index(wg);
  dst->sender_index = byteorder_htoll(handshake->local_index);

  handshake->state = HANDSHAKE_CREATED_RESPONSE;
  ret = true;

out:
  crypto_secure_wipe(key, NOISE_SYMMETRIC_KEY_LEN);
  return ret;
}

struct wireguard_peer *wireguard_noise_handshake_consume_response(
    struct message_handshake_response *src, struct wireguard_device *wg) {
  enum noise_handshake_state state = HANDSHAKE_ZEROED;
  struct wireguard_peer *peer = NULL, *ret_peer = NULL;
  struct noise_handshake *handshake;
  uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
  uint8_t hash[NOISE_HASH_LEN];
  uint8_t chaining_key[NOISE_HASH_LEN];
  uint8_t e[NOISE_PUBLIC_KEY_LEN];
  uint8_t ephemeral_private[NOISE_PUBLIC_KEY_LEN];
  uint8_t static_private[NOISE_PUBLIC_KEY_LEN];
  uint8_t preshared_key[NOISE_SYMMETRIC_KEY_LEN];
  uint32_t receiver;

  if (!wg->static_identity.has_identity)
    goto out;

  receiver = byteorder_ltohl(src->receiver_index);
  peer = wireguard_peer_lookup_by_handshake_receiver(wg->peers, receiver);
  if (!peer)
    goto out;

  handshake = &peer->handshake;
  if (unlikely(!handshake->handshaking))
    goto out;

  state = handshake->state;
  memcpy(hash, handshake->hash, NOISE_HASH_LEN);
  memcpy(chaining_key, handshake->chaining_key, NOISE_HASH_LEN);
  memcpy(ephemeral_private, handshake->ephemeral_private, NOISE_PUBLIC_KEY_LEN);
  memcpy(preshared_key, handshake->preshared_key, NOISE_SYMMETRIC_KEY_LEN);

  if (state != HANDSHAKE_CREATED_INITIATION)
    goto out;

  /* e */
  message_ephemeral(e, src->unencrypted_ephemeral, chaining_key, hash);

  /* ee */
  if (!mix_dh(chaining_key, NULL, ephemeral_private, e))
    goto out;

  /* se */
  if (!mix_dh(chaining_key, NULL, wg->static_identity.static_private, e))
    goto out;

  /* psk */
  mix_psk(chaining_key, hash, key, preshared_key);

  /* {} */
  if (!message_decrypt(NULL, src->encrypted_nothing,
                       sizeof(src->encrypted_nothing), key, hash))
    goto out;

  /* Success! Copy everything to peer */
  memcpy(handshake->remote_ephemeral, e, NOISE_PUBLIC_KEY_LEN);
  memcpy(handshake->hash, hash, NOISE_HASH_LEN);
  memcpy(handshake->chaining_key, chaining_key, NOISE_HASH_LEN);
  handshake->remote_index = byteorder_ltohl(src->sender_index);
  handshake->state = HANDSHAKE_CONSUMED_RESPONSE;
  ret_peer = peer;
  goto out;

out:
  crypto_secure_wipe(key, NOISE_SYMMETRIC_KEY_LEN);
  crypto_secure_wipe(hash, NOISE_HASH_LEN);
  crypto_secure_wipe(chaining_key, NOISE_HASH_LEN);
  crypto_secure_wipe(ephemeral_private, NOISE_PUBLIC_KEY_LEN);
  crypto_secure_wipe(static_private, NOISE_PUBLIC_KEY_LEN);
  crypto_secure_wipe(preshared_key, NOISE_SYMMETRIC_KEY_LEN);
  return ret_peer;
}

bool wireguard_noise_handshake_begin_session(struct noise_handshake *handshake,
                                             struct noise_keypairs *keypairs) {
  assert(handshake);
  assert(handshake->handshaking);
  struct noise_keypair new_keypair;
  bool ret = false;

  if (handshake->state != HANDSHAKE_CREATED_RESPONSE &&
      handshake->state != HANDSHAKE_CONSUMED_RESPONSE)
    goto out;

  new_keypair.initiator = handshake->state == HANDSHAKE_CONSUMED_RESPONSE;
  new_keypair.remote_index = handshake->remote_index;
  new_keypair.receiving_counter.bitmap = 0;
  new_keypair.receiving_counter.last_seq = 0;
  new_keypair.sending_counter = 0;

  if (new_keypair.initiator)
    derive_keys(&new_keypair.sending, &new_keypair.receiving,
                handshake->chaining_key);
  else
    derive_keys(&new_keypair.receiving, &new_keypair.sending,
                handshake->chaining_key);
  new_keypair.birthdate = new_keypair.sending.birthdate;
  new_keypair.valid = new_keypair.sending.valid && new_keypair.receiving.valid;

  handshake_zero(handshake);

  if (likely(
          container_of(handshake, struct wireguard_peer, handshake)->valid)) {
    new_keypair.local_index = handshake->local_index;
    handshake->local_index = 0;
    handshake->handshaking = false;
    add_new_keypair(keypairs, &new_keypair);
    ret = true;
  }
out:
  wireguard_noise_destroy_keypair(&new_keypair);
  return ret;
}

/* Zeroize the keypair and mark the memory pointed by keypair is reusable */
void wireguard_noise_destroy_keypair(struct noise_keypair *keypair) {
  crypto_secure_wipe(keypair, sizeof(struct noise_keypair));
  keypair->valid = false;
}

bool wireguard_noise_received_with_keypair(
    struct noise_keypairs *keypairs, struct noise_keypair *received_keypair) {
  bool key_is_new = received_keypair == &keypairs->next_keypair;
  if (!key_is_new)
    return false;
  /* When we've finally received the confirmation, we slide the next
   * into the current, the current into the previous, and get rid of
   * the next keypair.
   */
  memcpy(&keypairs->previous_keypair, &keypairs->current_keypair,
         sizeof(struct noise_keypair));
  /* clone the received keypair */
  memcpy(&keypairs->current_keypair, received_keypair,
         sizeof(struct noise_keypair));
  wireguard_noise_destroy_keypair(&keypairs->next_keypair);
  return true;
}

void wireguard_noise_keypairs_clear(struct noise_keypairs *keypairs) {
  wireguard_noise_destroy_keypair(&keypairs->next_keypair);
  wireguard_noise_destroy_keypair(&keypairs->current_keypair);
  wireguard_noise_destroy_keypair(&keypairs->previous_keypair);
}

void wireguard_noise_handshake_clear(struct noise_handshake *handshake) {
  handshake->handshaking = false;
  handshake->local_index = 0;
  handshake_zero(handshake);
}

static void ecdh_generate_private_key(uint8_t *key) {
  random_bytes(key, NOISE_PRIVATE_KEY_LEN);
  ecdh_clamp_private_key(key);
}

static void hmac(uint8_t *result, const uint8_t *key, size_t key_len,
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

/* This is Hugo Krawczyk's HKDF:
 *  - https://eprint.iacr.org/2010/264.pdf
 *  - https://tools.ietf.org/html/rfc5869
 */
static void kdf(uint8_t *first_dst, uint8_t *second_dst, uint8_t *third_dst,
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

static void mix_hash(uint8_t *hash, const uint8_t *src, size_t src_len) {
  blake2s_state ctx;
  blake2s_init(&ctx, NOISE_HASH_LEN);
  blake2s_update(&ctx, hash, NOISE_HASH_LEN);
  blake2s_update(&ctx, src, src_len);
  blake2s_final(&ctx, hash, NOISE_HASH_LEN);
}

static void derive_keys(struct noise_symmetric_key *first_dst,
                        struct noise_symmetric_key *second_dst,
                        const uint8_t chaining_key[NOISE_HASH_LEN]) {
  uint32_t birthdate = ztimer_now(ZTIMER_MSEC);
  kdf(first_dst->key, second_dst->key, NULL, NULL, NOISE_SYMMETRIC_KEY_LEN,
      NOISE_SYMMETRIC_KEY_LEN, 0, 0, chaining_key);
  first_dst->birthdate = second_dst->birthdate = birthdate;
  first_dst->valid = second_dst->valid = true;
}

static bool mix_dh(uint8_t chaining_key[NOISE_HASH_LEN],
                   uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
                   const uint8_t private[NOISE_PUBLIC_KEY_LEN],
                   const uint8_t public[NOISE_PUBLIC_KEY_LEN]) {
  uint8_t dh_calculation[NOISE_PUBLIC_KEY_LEN];

  if (unlikely(!ecdh_agree(dh_calculation, private, public))) {
    return false;
  }
  kdf(chaining_key, key, NULL, dh_calculation, NOISE_HASH_LEN,
      NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_PUBLIC_KEY_LEN, chaining_key);
  crypto_secure_wipe(dh_calculation, NOISE_PUBLIC_KEY_LEN);
  return true;
}

static bool
mix_precomputed_dh(uint8_t chaining_key[NOISE_HASH_LEN],
                   uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
                   const uint8_t precomputed[NOISE_PUBLIC_KEY_LEN]) {

  if (unlikely(crypto_equals(precomputed, zerokey, NOISE_PUBLIC_KEY_LEN))) {
    return false;
  }
  kdf(chaining_key, key, NULL, precomputed, NOISE_HASH_LEN,
      NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_PUBLIC_KEY_LEN, chaining_key);
  return true;
}

static void mix_psk(uint8_t chaining_key[NOISE_HASH_LEN],
                    uint8_t hash[NOISE_HASH_LEN],
                    uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
                    const uint8_t psk[NOISE_SYMMETRIC_KEY_LEN]) {
  uint8_t temp_hash[NOISE_HASH_LEN];

  kdf(chaining_key, temp_hash, key, psk, NOISE_HASH_LEN, NOISE_HASH_LEN,
      NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, chaining_key);
  mix_hash(hash, temp_hash, NOISE_HASH_LEN);
  crypto_secure_wipe(temp_hash, NOISE_HASH_LEN);
}

static void handshake_init(uint8_t chaining_key[NOISE_HASH_LEN],
                           uint8_t hash[NOISE_HASH_LEN],
                           const uint8_t remote_static[NOISE_PUBLIC_KEY_LEN]) {
  memcpy(hash, handshake_init_hash, NOISE_HASH_LEN);
  memcpy(chaining_key, handshake_init_chaining_key, NOISE_HASH_LEN);
  mix_hash(hash, remote_static, NOISE_PUBLIC_KEY_LEN);
}

static void message_encrypt(uint8_t *dst_ciphertext,
                            const uint8_t *src_plaintext, size_t src_len,
                            uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
                            uint8_t hash[NOISE_HASH_LEN]) {
  uint8_t nonce[CHACHA20POLY1305_NONCE_BYTES] = {0};
  chacha20poly1305_encrypt(dst_ciphertext, src_plaintext, src_len, hash,
                           NOISE_HASH_LEN, key,
                           nonce); /* Always zero for Noise_IK */
  mix_hash(hash, dst_ciphertext, noise_encrypted_len(src_len));
}

static bool message_decrypt(uint8_t *dst_plaintext,
                            const uint8_t *src_ciphertext, size_t src_len,
                            uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
                            uint8_t hash[NOISE_HASH_LEN]) {
  uint8_t nonce[CHACHA20POLY1305_NONCE_BYTES] = {0};
  size_t msglen = src_len;
  if (!chacha20poly1305_decrypt(src_ciphertext, src_len, dst_plaintext, &msglen,
                                hash, NOISE_HASH_LEN, key,
                                nonce /* Always zero for Noise_IK */))
    return false;
  mix_hash(hash, src_ciphertext, src_len);
  return true;
}

static void message_ephemeral(uint8_t ephemeral_dst[NOISE_PUBLIC_KEY_LEN],
                              const uint8_t ephemeral_src[NOISE_PUBLIC_KEY_LEN],
                              uint8_t chaining_key[NOISE_HASH_LEN],
                              uint8_t hash[NOISE_HASH_LEN]) {
  if (ephemeral_dst != ephemeral_src)
    memcpy(ephemeral_dst, ephemeral_src, NOISE_PUBLIC_KEY_LEN);
  mix_hash(hash, ephemeral_src, NOISE_PUBLIC_KEY_LEN);
  kdf(chaining_key, NULL, NULL, ephemeral_src, NOISE_HASH_LEN, 0, 0,
      NOISE_PUBLIC_KEY_LEN, chaining_key);
}

static void tai64n_now(uint8_t *buf) {
  uint32_t now = ztimer_now(ZTIMER_MSEC);
  /* https://cr.yp.to/libtai/tai64.html */
  uint64_t sec = 0x400000000000000aULL + now / MS_PER_SEC;
  /* truncate 24 bits to prevent unsuitable information leak */
  uint32_t nano = (now * NS_PER_MS) & 0xFF000000UL;
  byteorder_htobebufll(buf, sec);
  byteorder_htobebufl(buf + sizeof(uint64_t), nano);
}

static void handshake_zero(struct noise_handshake *handshake) {
  crypto_secure_wipe(&handshake->ephemeral_private, NOISE_PRIVATE_KEY_LEN);
  crypto_secure_wipe(&handshake->remote_ephemeral, NOISE_PUBLIC_KEY_LEN);
  crypto_secure_wipe(&handshake->hash, NOISE_HASH_LEN);
  crypto_secure_wipe(&handshake->chaining_key, NOISE_HASH_LEN);
  handshake->remote_index = 0;
  handshake->state = HANDSHAKE_ZEROED;
}

/* copy the struct right now, because we won't use any malloc.
 * After calling this function, the new_keypair from the caller needs to be
 * wiped */
static void add_new_keypair(struct noise_keypairs *keypairs,
                            struct noise_keypair *new_keypair) {
  if (new_keypair->initiator) {
    /* If we're the initiator, it means we've sent a handshake, and
     * received a confirmation response, which means this new
     * keypair can now be used.
     */
    if (keypairs->next_keypair.valid) {
      /* If there already was a next keypair pending, we
       * demote it to be the previous keypair, and destroy the
       * existing current.*/
      memcpy(&keypairs->previous_keypair, &keypairs->next_keypair,
             sizeof(struct noise_keypair));
      wireguard_noise_destroy_keypair(&keypairs->next_keypair);
    } else { /* If there wasn't an existing next keypair, we replace
              * the previous with the current one.
              */
      memcpy(&keypairs->previous_keypair, &keypairs->current_keypair,
             sizeof(struct noise_keypair));
    }
    /* At this point we can get rid of the old previous keypair, and
     * set up the new keypair.
     */
    memcpy(&keypairs->current_keypair, new_keypair,
           sizeof(struct noise_keypair));
  } else {
    /* If we're the responder, it means we can't use the new keypair
     * until we receive confirmation via the first data packet, so
     * we get rid of the existing previous one, the possibly
     * existing next one, and slide in the new next one.
     */
    memcpy(&keypairs->next_keypair, new_keypair, sizeof(struct noise_keypair));
    wireguard_noise_destroy_keypair(&keypairs->previous_keypair);
  }
}
