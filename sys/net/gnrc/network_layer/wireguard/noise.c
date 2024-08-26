#include "net/wireguard/noise.h"
#include "blake2.h"
#include "byteorder.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/helper.h"
#include "net/wireguard/crypto.h"
#include "net/wireguard/device.h"
#include "net/wireguard/messages.h"
#include "net/wireguard/peer.h"
#include "time_units.h"
#include "ztimer.h"

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
// static uint8_t keypair_counter = 0;

void wg_noise_init(void) {
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
bool wg_noise_precompute_static_static(struct wg_peer *peer) {
  if (!peer->handshake.static_identity->has_identity ||
      !dh_agree(peer->handshake.precomputed_static_static,
                peer->handshake.static_identity->static_private,
                peer->handshake.remote_static)) {
    memset(peer->handshake.precomputed_static_static, 0, NOISE_PUBLIC_KEY_LEN);
    return false;
  }
  return true;
}

bool wg_noise_handshake_init(
    struct noise_handshake *handshake,
    struct noise_static_identity *static_identity,
    const uint8_t peer_public_key[NOISE_PUBLIC_KEY_LEN],
    const uint8_t peer_preshared_key[NOISE_SYMMETRIC_KEY_LEN],
    struct wg_peer *peer) {
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
  handshake->valid = false;
  return wg_noise_precompute_static_static(peer);
}

static void handshake_zero(struct noise_handshake *handshake) {
  crypto_secure_wipe(&handshake->ephemeral_private, NOISE_PRIVATE_KEY_LEN);
  crypto_secure_wipe(&handshake->remote_ephemeral, NOISE_PUBLIC_KEY_LEN);
  crypto_secure_wipe(&handshake->hash, NOISE_HASH_LEN);
  crypto_secure_wipe(&handshake->chaining_key, NOISE_HASH_LEN);
  handshake->remote_index = 0;
  handshake->state = HANDSHAKE_ZEROED;
}

/* Zeroize the keypair and mark the memory pointed by keypair is reusable */
void wg_noise_destroy_keypair(struct noise_keypair *keypair) {
  crypto_secure_wipe(keypair, sizeof(struct noise_keypair));
  keypair->valid = false;
}

/* Zeroize the handshake, mark the memory pointed by the handshake is reusable
 */
void wg_noise_handshake_clear(struct noise_handshake *handshake) {
  handshake->valid = false;
  handshake->local_index = 0;
  handshake_zero(handshake);
}

void wg_noise_keypairs_clear(struct noise_keypairs *keypairs) {
  wg_noise_destroy_keypair(&keypairs->next_keypair);
  wg_noise_destroy_keypair(&keypairs->current_keypair);
  wg_noise_destroy_keypair(&keypairs->previous_keypair);
}

void wg_noise_expire_current_peer_keypairs(struct wg_peer *peer) {
  struct noise_keypair *keypair;

  wg_noise_handshake_clear(&peer->handshake);
  wg_noise_reset_last_sent_handshake(&peer->last_sent_handshake);

  keypair = &peer->keypairs.next_keypair;
  if (keypair->valid) {
    keypair->sending.valid = false;
  }
  keypair = &peer->keypairs.current_keypair;
  if (keypair->valid) {
    keypair->sending.valid = false;
  }
}

/* copy the struct right now, because we won't use any malloc.
 * After calling this function, the received keypair from the caller needs to be
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
      keypairs->previous_keypair = keypairs->next_keypair;
      wg_noise_destroy_keypair(&keypairs->next_keypair);
    } else /* If there wasn't an existing next keypair, we replace
            * the previous with the current one.
            */
      keypairs->previous_keypair = keypairs->current_keypair;
    /* At this point we can get rid of the old previous keypair, and
     * set up the new keypair.
     */
    keypairs->current_keypair = *new_keypair;
  } else {
    /* If we're the responder, it means we can't use the new keypair
     * until we receive confirmation via the first data packet, so
     * we get rid of the existing previous one, the possibly
     * existing next one, and slide in the new next one.
     */
    keypairs->next_keypair = *new_keypair;
    wg_noise_destroy_keypair(&keypairs->previous_keypair);
  }
}

bool wg_noise_received_with_keypair(struct noise_keypairs *keypairs,
                                    struct noise_keypair *received_keypair) {
  bool key_is_new = received_keypair == &keypairs->next_keypair;
  if (!key_is_new)
    return false;
  /* When we've finally received the confirmation, we slide the next
   * into the current, the current into the previous, and get rid of
   * the next keypair.
   */
  keypairs->previous_keypair = keypairs->current_keypair;
  /* clone the received keypair */
  keypairs->current_keypair = *received_keypair;
  wg_noise_destroy_keypair(&keypairs->next_keypair);
  return true;
}

void wg_noise_set_static_identity_private_key(
    struct noise_static_identity *static_identity,
    const uint8_t private_key[NOISE_PUBLIC_KEY_LEN]) {
  memcpy(static_identity->static_private, private_key, NOISE_PUBLIC_KEY_LEN);
  dh_clamp_private_key(static_identity->static_private);
  static_identity->has_identity =
      dh_generate_public_key(static_identity->static_public, private_key);
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

  if (unlikely(!dh_agree(dh_calculation, private, public))) {
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

static void mix_hash(uint8_t hash[NOISE_HASH_LEN], const uint8_t *src,
                     size_t src_len) {
  blake2s_state blake;

  blake2s_init(&blake, NOISE_HASH_LEN);
  blake2s_update(&blake, hash, NOISE_HASH_LEN);
  blake2s_update(&blake, src, src_len);
  blake2s_final(&blake, hash, NOISE_HASH_LEN);
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
  if (!chacha20poly1305_decrypt(src_ciphertext, src_len, dst_plaintext,
                                &src_len, hash, NOISE_HASH_LEN, key,
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

bool wg_noise_handshake_create_initiation(
    struct message_handshake_initiation *dst, struct noise_handshake *handshake,
    struct wg_device *wg) {
  uint8_t timestamp[NOISE_TIMESTAMP_LEN];
  uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
  bool ret = false;

  if (unlikely(!handshake->static_identity->has_identity))
    goto out;

  dst->header.type = byteorder_htoll(MESSAGE_HANDSHAKE_INITIATION);

  handshake_init(handshake->chaining_key, handshake->hash,
                 handshake->remote_static);

  /* e */
  dh_generate_private_key(handshake->ephemeral_private);
  if (!dh_generate_public_key(dst->unencrypted_ephemeral,
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

  handshake->local_index = wg_generate_unique_index(wg->peers);
  dst->sender_index = byteorder_htoll(handshake->local_index);

  handshake->state = HANDSHAKE_CREATED_INITIATION;
  ret = true;

out:
  crypto_secure_wipe(key, NOISE_SYMMETRIC_KEY_LEN);
  return ret;
}

struct wg_peer *
wg_noise_handshake_consume_initiation(struct message_handshake_initiation *src,
                                      struct wg_device *wg) {
  struct wg_peer *peer = NULL, *ret_peer = NULL;
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
  peer = peer_lookup_by_pubkey(wg->peers, s);
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
  flood_attack =
      (peer->last_initiation_rx - now) < (MS_PER_SEC / INITIATIONS_PER_SECOND);

  if (replay_attack || flood_attack)
    goto out;

  /* Success! Copy everything to peer */
  memcpy(handshake->remote_ephemeral, e, NOISE_PUBLIC_KEY_LEN);
  if (memcmp(t, handshake->greatest_timestamp, NOISE_TIMESTAMP_LEN) > 0)
    memcpy(handshake->greatest_timestamp, t, NOISE_TIMESTAMP_LEN);
  memcpy(handshake->hash, hash, NOISE_HASH_LEN);
  memcpy(handshake->chaining_key, chaining_key, NOISE_HASH_LEN);
  handshake->remote_index = byteorder_ltohl(src->sender_index);
  peer->last_initiation_rx = now;
  handshake->state = HANDSHAKE_CONSUMED_INITIATION;
  handshake->valid = true;
  ret_peer = peer;

out:
  crypto_secure_wipe(key, NOISE_SYMMETRIC_KEY_LEN);
  crypto_secure_wipe(hash, NOISE_HASH_LEN);
  crypto_secure_wipe(chaining_key, NOISE_HASH_LEN);
  return ret_peer;
}

bool wg_noise_handshake_create_response(struct message_handshake_response *dst,
                                        struct noise_handshake *handshake,
                                        struct wg_device *wg) {
  uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
  bool ret = false;

  if (handshake->state != HANDSHAKE_CONSUMED_INITIATION)
    goto out;

  dst->header.type = byteorder_htoll(MESSAGE_HANDSHAKE_RESPONSE);
  dst->receiver_index = byteorder_htoll(handshake->remote_index);

  /* e */
  dh_generate_private_key(handshake->ephemeral_private);
  if (!dh_generate_public_key(dst->unencrypted_ephemeral,
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

  handshake->local_index = wg_generate_unique_index(wg->peers);
  dst->sender_index = byteorder_htoll(handshake->local_index);

  handshake->state = HANDSHAKE_CREATED_RESPONSE;
  ret = true;

out:
  crypto_secure_wipe(key, NOISE_SYMMETRIC_KEY_LEN);
  return ret;
}

struct wg_peer *
wg_noise_handshake_consume_response(struct message_handshake_response *src,
                                    struct wg_device *wg) {
  enum noise_handshake_state state = HANDSHAKE_ZEROED;
  struct wg_peer *peer = NULL, *ret_peer = NULL;
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
  peer = peer_lookup_by_handshake_receiver(wg->peers, receiver);
  handshake = &peer->handshake;
  if (unlikely(!handshake->valid))
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

bool wg_noise_handshake_begin_session(struct noise_handshake *handshake,
                                      struct noise_keypairs *keypairs) {
  assert(handshake);
  assert(handshake->valid);
  struct noise_keypair new_keypair;
  bool ret = false;

  if (handshake->state != HANDSHAKE_CREATED_RESPONSE &&
      handshake->state != HANDSHAKE_CONSUMED_RESPONSE)
    goto out;

  new_keypair.initiator = handshake->state == HANDSHAKE_CONSUMED_RESPONSE;
  new_keypair.remote_index = handshake->remote_index;
  new_keypair.receiving_counter.bitmap = 0;
  new_keypair.receiving_counter.last_seq = 0;

  if (new_keypair.initiator)
    derive_keys(&new_keypair.sending, &new_keypair.receiving,
                handshake->chaining_key);
  else
    derive_keys(&new_keypair.receiving, &new_keypair.sending,
                handshake->chaining_key);
  new_keypair.birthdate = new_keypair.sending.birthdate;
  new_keypair.valid = new_keypair.sending.valid && new_keypair.receiving.valid;

  handshake_zero(handshake);

  if (likely(container_of(handshake, struct wg_peer, handshake)->valid)) {
    add_new_keypair(keypairs, &new_keypair);
    new_keypair.local_index = handshake->local_index;
    handshake->local_index = 0;
    handshake->valid = false;
  }
out:
  wg_noise_destroy_keypair(&new_keypair);
  return ret;
}
