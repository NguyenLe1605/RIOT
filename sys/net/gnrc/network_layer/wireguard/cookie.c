#include "net/wireguard/cookie.h"
#include "blake2.h"
#include "byteorder.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/helper.h"
#include "net/gnrc/pkt.h"
#include "net/ipv6/hdr.h"
#include "net/sock/udp.h"
#include "net/udp.h"
#include "net/wireguard/device.h"
#include "net/wireguard/messages.h"
#include "net/wireguard/peer.h"
#include "net/wireguard/timer.h"
#include "random.h"
#include "ztimer.h"

#define ENABLE_DEBUG 0
#include "debug.h"

#define COOKIE_KEY_LABEL_LEN (8)

void wg_cookie_checker_init(struct cookie_checker *checker,
                            struct wg_device *wg) {
  checker->secret_birthdate = ztimer_now(ZTIMER_MSEC);
  random_bytes(checker->secret, NOISE_HASH_LEN);
  checker->device = wg;
}

static const uint8_t mac1_key_label[COOKIE_KEY_LABEL_LEN] = "mac1----";
static const uint8_t cookie_key_label[COOKIE_KEY_LABEL_LEN] = "cookie--";

static void precompute_key(uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
                           const uint8_t pubkey[NOISE_PUBLIC_KEY_LEN],
                           const uint8_t label[COOKIE_KEY_LABEL_LEN]) {
  blake2s_state blake;

  blake2s_init(&blake, NOISE_SYMMETRIC_KEY_LEN);
  blake2s_update(&blake, label, COOKIE_KEY_LABEL_LEN);
  blake2s_update(&blake, pubkey, NOISE_PUBLIC_KEY_LEN);
  blake2s_final(&blake, key, NOISE_SYMMETRIC_KEY_LEN);
}

void wg_cookie_checker_precompute_device_keys(struct cookie_checker *checker) {
  if (checker->device->static_identity.has_identity) {
    precompute_key(checker->cookie_encryption_key,
                   checker->device->static_identity.static_public,
                   cookie_key_label);
    precompute_key(checker->message_mac1_key,
                   checker->device->static_identity.static_public,
                   mac1_key_label);
  } else {
    memset(checker->cookie_encryption_key, 0, NOISE_SYMMETRIC_KEY_LEN);
    memset(checker->message_mac1_key, 0, NOISE_SYMMETRIC_KEY_LEN);
  }
}

void wg_cookie_checker_precompute_peer_keys(struct wg_peer *peer) {
  precompute_key(peer->latest_cookie.cookie_decryption_key,
                 peer->handshake.remote_static, cookie_key_label);
  precompute_key(peer->latest_cookie.message_mac1_key,
                 peer->handshake.remote_static, mac1_key_label);
}

void wg_cookie_init(struct cookie *cookie) {
  memset(cookie, 0, sizeof(*cookie));
}

static void compute_mac1(uint8_t mac1[COOKIE_LEN], const void *message,
                         size_t len,
                         const uint8_t key[NOISE_SYMMETRIC_KEY_LEN]) {
  len = len - sizeof(struct message_macs) + offsetof(struct message_macs, mac1);
  blake2s(mac1, message, key, COOKIE_LEN, len, NOISE_SYMMETRIC_KEY_LEN);
}

static void compute_mac2(uint8_t mac2[COOKIE_LEN], const void *message,
                         size_t len, const uint8_t cookie[COOKIE_LEN]) {
  len = len - sizeof(struct message_macs) + offsetof(struct message_macs, mac2);
  blake2s(mac2, message, cookie, COOKIE_LEN, len, COOKIE_LEN);
}

/* Remote will be set in a sock_udp_recv called */
static void make_cookie(uint8_t cookie[COOKIE_LEN], sock_udp_ep_t *remote,
                        struct cookie_checker *checker) {
  blake2s_state state;

  if (wg_birthdate_has_expired(checker->secret_birthdate,
                               COOKIE_SECRET_MAX_AGE)) {
    checker->secret_birthdate = ztimer_now(ZTIMER_MSEC);
    random_bytes(checker->secret, NOISE_HASH_LEN);
  }

  blake2s_init_key(&state, COOKIE_LEN, checker->secret, NOISE_HASH_LEN);

  blake2s_update(&state, (uint8_t *)&remote->addr, sizeof(remote->addr));

  blake2s_update(&state, (uint8_t *)&remote->port, sizeof(uint16_t));
  blake2s_final(&state, cookie, COOKIE_LEN);
}

enum cookie_mac_state wg_cookie_validate_packet(struct cookie_checker *checker,
                                                uint8_t *buf, size_t len,
                                                sock_udp_ep_t *remote,
                                                bool check_cookie) {
  struct message_macs *macs =
      (struct message_macs *)(buf + len - sizeof(*macs));
  enum cookie_mac_state ret;
  uint8_t computed_mac[COOKIE_LEN];
  uint8_t cookie[COOKIE_LEN];

  ret = INVALID_MAC;
  compute_mac1(computed_mac, buf, len, checker->message_mac1_key);
  if (!crypto_equals(computed_mac, macs->mac1, COOKIE_LEN)) {
    goto out;
  }

  ret = VALID_MAC_BUT_NO_COOKIE;

  if (!check_cookie)
    goto out;

  make_cookie(cookie, remote, checker);

  compute_mac2(computed_mac, buf, len, cookie);
  if (!crypto_equals(computed_mac, macs->mac2, COOKIE_LEN)) {
    goto out;
  }

  ret = VALID_MAC_WITH_COOKIE;

out:
  return ret;
}

void wg_cookie_add_mac_to_packet(void *message, size_t len,
                                 struct wg_peer *peer) {
  struct message_macs *macs =
      (struct message_macs *)((uint8_t *)message + len - sizeof(*macs));
  compute_mac1(macs->mac1, message, len, peer->latest_cookie.message_mac1_key);
  memcpy(peer->latest_cookie.last_mac1_sent, macs->mac1, COOKIE_LEN);
  peer->latest_cookie.have_sent_mac1 = true;
  if (peer->latest_cookie.is_valid &&
      !wg_birthdate_has_expired(peer->latest_cookie.birthdate,
                                COOKIE_SECRET_MAX_AGE - COOKIE_SECRET_LATENCY))
    compute_mac2(macs->mac2, message, len, peer->latest_cookie.cookie);
  else
    memset(macs->mac2, 0, COOKIE_LEN);
}

void wg_cookie_message_create(struct message_cookie_reply *dst, uint8_t *buf,
                              size_t len, sock_udp_ep_t *remote, uint32_t index,
                              struct cookie_checker *checker) {
  struct message_macs *macs =
      (struct message_macs *)(buf + len - sizeof(*macs));
  uint8_t cookie[COOKIE_LEN];
  dst->header.type = byteorder_htoll(MESSAGE_HANDSHAKE_COOKIE);
  dst->receiver_idx = byteorder_htoll(index);
  random_bytes(dst->nonce, COOKIE_NONCE_LEN);
  make_cookie(cookie, remote, checker);
  xchacha20poly1305_encrypt(dst->encrypted_cookie, cookie, COOKIE_LEN,
                            macs->mac1, COOKIE_LEN,
                            checker->cookie_encryption_key, dst->nonce);
}

bool wg_cookie_message_consume(struct message_cookie_reply *src,
                               struct wg_device *wg) {
  struct wg_peer *peer = NULL;
  uint8_t cookie[COOKIE_LEN];
  bool ret;
  size_t s;
  uint32_t receiver;
  receiver = byteorder_ltohl(src->receiver_idx);
  peer = peer_lookup_by_handshake_receiver(wg->peers, receiver);
  if (peer == NULL)
    return false;

  if (!peer->latest_cookie.have_sent_mac1)
    return false;

  s = sizeof(cookie);
  ret = xchacha20poly1305_decrypt(
      src->encrypted_cookie, sizeof(src->encrypted_cookie), cookie, &s,
      peer->latest_cookie.last_mac1_sent, COOKIE_LEN,
      peer->latest_cookie.cookie_decryption_key, src->nonce);

  if (ret) {
    memcpy(peer->latest_cookie.cookie, cookie, COOKIE_LEN);
    peer->latest_cookie.birthdate = ztimer_now(ZTIMER_MSEC);
    peer->latest_cookie.is_valid = true;
    peer->latest_cookie.have_sent_mac1 = false;
  } else {
    DEBUG("wireguard_receive: could not decrypt invalid cookie response\n");
  }
  return ret != 0;
}
