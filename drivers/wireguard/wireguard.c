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
 * @brief       Device driver implementation for the wireguard
 *
 * @author      Nguyen Le Hoang Dang <lhdnguyen2002@gmail.com>
 *
 * @}
 */

#include "wireguard.h"
#include "base64.h"
#include "clist.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/helper.h"
#include "irq.h"
#include "net/gnrc/ipv6/nib/nc.h"
#include "net/gnrc/netif.h"
#include "net/ipv6/addr.h"
#include "net/ipv6/hdr.h"
#include "net/netdev.h"
#include "net/sock/async/event.h"
#include "net/sock/async/types.h"
#include "net/sock/udp.h"
#include "wireguard_constants.h"
#include "wireguard_cookie.h"
#include "wireguard_internal.h"
#include "wireguard_netdev.h"
#include "wireguard_noise.h"
#include "wireguard_timer.h"

#include "net/sock.h"
#include <stdint.h>

#define ENABLE_DEBUG 1
#include "debug.h"

#define REPLAY_WINDOW_SIZE (32)

static bool wireguard_add_private_key(wireguard_t *dev,
                                      const uint8_t *private_key);
static inline int wireguard_send_buffer_to_peer(struct wireguard_peer *peer,
                                                uint8_t *buffer, size_t len) {
  return sock_udp_send(&peer->device->udp, buffer, len, &peer->latest_endpoint);
}

static inline size_t align_mask(size_t len, size_t mask) {
  return (len + (mask - 1)) & ~(mask);
}

static void wireguard_recv(sock_udp_t *sock, sock_async_flags_t flags,
                           void *args);
static void wireguard_receive_handshake_packet(wireguard_t *wg, uint8_t *buf,
                                               size_t len,
                                               sock_udp_ep_t *remote,
                                               uint32_t type);
static uint32_t wireguard_get_message_type(const uint8_t *buf, size_t len);
static int wireguard_send_pkt_to_peer(wireguard_t *wg, gnrc_pktsnip_t *pkt,
                                      const ipv6_addr_t *addr,
                                      struct wireguard_peer *peer);
static int wireguard_prepare_transport_snip(gnrc_pktsnip_t *pkt);
static void wireguard_encrypt_packet(struct noise_keypair *keypair, void *buf,
                                     size_t len);
static void wireguard_consume_data(struct wireguard_peer *peer,
                                   struct message_transport_data *data,
                                   size_t len, sock_udp_ep_t *remote);
static void wireguard_dispatch_ipv6_pkt(wireguard_t *wg, uint8_t *buf,
                                        size_t len);
static bool wireguard_anti_replay(struct noise_keypair *keypair, uint64_t seq);

static int wireguard_send_cookie_reply(wireguard_t *wg, uint8_t *buf,
                                       size_t len, sock_udp_ep_t *remote,
                                       uint32_t index);
static struct noise_keypair *
get_peer_keypair_for_idx(struct wireguard_peer *peer, uint32_t idx);

static void keep_key_fresh(struct wireguard_peer *peer);

void wireguard_setup(wireguard_t *dev, const wireguard_params_t *params,
                     uint8_t index) {
  memset(dev, 0, sizeof(wireguard_t));
  netdev_t *netdev = (netdev_t *)dev;

  netdev->driver = &wireguard_driver;
  dev->params = (wireguard_params_t *)params;
  netdev_register(&dev->netdev, NETDEV_WIREGUARD, index);
}

int wireguard_init(wireguard_t *dev) {
  /* Initialize peripherals, gpios, setup registers, etc */
  assert(dev);
  int result;
  uint8_t private_key[NOISE_PRIVATE_KEY_LEN];
  size_t private_key_len;
  size_t key_len;
  gnrc_netif_t *iter = NULL;

  wireguard_noise_init();
  wireguard_cookie_checker_init(&dev->cookie_checker, dev);

  key_len = BASE64_PRIVATE_KEY_LEN;
  private_key_len = key_len;
  if (base64_decode(dev->params->private_key, key_len, (void *)private_key,
                    &private_key_len) != BASE64_SUCCESS ||
      private_key_len != NOISE_PRIVATE_KEY_LEN) {
    return -EINVAL;
  }

  if (!wireguard_add_private_key(dev, private_key)) {
    return -EINVAL;
  }
  crypto_secure_wipe(private_key, private_key_len);

  sock_udp_ep_t local_ep;
  dev->netif = dev->netdev.context;
  dev->evq = &dev->netif->evq[GNRC_NETIF_EVQ_INDEX_PRIO_HIGH];
  dev->listen_port = dev->params->listen_port;
  memset(&local_ep, 0, sizeof(local_ep));
  local_ep = (sock_udp_ep_t)SOCK_IPV6_EP_ANY;
  local_ep.port =
      dev->listen_port ? dev->listen_port : WIREGUARD_DEFAULT_UDP_PORT;

  /* find a free netif that is not wireguard or 0, weird behavior cause the
   * udp packet is not sent on ANY_NETIF.*/
  for (iter = gnrc_netif_iter(NULL); iter != NULL;
       iter = gnrc_netif_iter(iter)) {
    if (iter->pid > 0 && iter->pid != dev->netif->pid &&
        iter->device_type != NETDEV_WIREGUARD) {

      local_ep.netif = iter->pid;
      break;
    }
  }

  dev->params = NULL;

  if ((result = sock_udp_create(&dev->udp, &local_ep, NULL, 0)) < 0) {
    wireguard_cleanup(dev);
    return result;
  }
  sock_udp_event_init(&dev->udp, dev->evq, wireguard_recv, dev);

  /* TODO: init the timers */
  return 0;
}

int wireguard_send(wireguard_t *dev, gnrc_pktsnip_t *pkt) {
  struct wireguard_peer *peer;
  ipv6_hdr_t *hdr = (ipv6_hdr_t *)pkt->data;
  ipv6_addr_t addr = hdr->dst;

  peer = wireguard_peer_lookup_by_allowed_ip(dev->peers, &addr);

  if (!peer || !peer->valid || !peer->active) {
    /* if match no peer, the packet is dropped */
    return -ENOKEY;
  }

  return wireguard_send_pkt_to_peer(dev, pkt, &addr, peer);
}

void wireguard_cleanup(wireguard_t *dev) {
  assert(dev);
  /* wiping the private key */
  crypto_secure_wipe(dev->static_identity.static_public, NOISE_PUBLIC_KEY_LEN);
  crypto_secure_wipe(dev->static_identity.static_private,
                     NOISE_PRIVATE_KEY_LEN);
  dev->static_identity.has_identity = false;
}

static bool wireguard_add_private_key(wireguard_t *dev,
                                      const uint8_t *private_key) {

  assert(dev);
  wireguard_noise_set_static_identity_private_key(&dev->static_identity,
                                                  private_key);
  dev->valid = dev->static_identity.has_identity;
  if (!dev->valid) {
    crypto_secure_wipe(dev->static_identity.static_private,
                       NOISE_PRIVATE_KEY_LEN);
  } else {
    wireguard_cookie_checker_precompute_device_keys(&dev->cookie_checker);
  }
  return dev->valid;
}

int wireguard_send_handshake_initiation(struct wireguard_peer *peer) {
  int result = 0;
  struct message_handshake_initiation packet;
  /* TODO: add timeout due to REKEY_TIMEOUT */

  if (wireguard_noise_handshake_create_initiation(&packet, &peer->handshake,
                                                  peer->device)) {
    wireguard_cookie_add_mac_to_packet(&packet, sizeof(packet), peer);
    result =
        wireguard_send_buffer_to_peer(peer, (uint8_t *)&packet, sizeof(packet));

    if (result < 0) {
      DEBUG("[wireguard] send: could not send handshake initiation - %d\n",
            result);
    }

    peer->last_initiation_tx = ztimer_now(ZTIMER_MSEC);

  } else {
    result = -EINVAL;
  }
  DEBUG("[wireguard] send: send handshake initiation sucessfully \n");
  return result;
}

int wireguard_send_handshake_response(struct wireguard_peer *peer) {
  int result = 0;
  struct message_handshake_response packet;

  if (wireguard_noise_handshake_create_response(&packet, &peer->handshake,
                                                peer->device)) {
    /* TODO: add timer */
    wireguard_cookie_add_mac_to_packet(&packet, sizeof(packet), peer);
    if (!wireguard_noise_handshake_begin_session(&peer->handshake,
                                                 &peer->keypairs)) {
      DEBUG("[wireguard] send: invalid session key after sending handshake "
            "response\n");
      return -EINVAL;
    }
    result =
        wireguard_send_buffer_to_peer(peer, (uint8_t *)&packet, sizeof(packet));

  } else {
    DEBUG("[wireguard] send: could not create handshake response\n");
    result = -EINVAL;
  }
  return result;
}

static void wireguard_recv(sock_udp_t *sock, sock_async_flags_t flags,
                           void *args) {
  if (!(flags & SOCK_ASYNC_MSG_RECV)) {
    return;
  }
  void *stackbuf;
  void *buf_ctx = NULL;
  sock_udp_ep_t remote;
  uint32_t message_type;
  ssize_t res;
  struct wireguard_peer *peer;
  wireguard_t *wg = (wireguard_t *)args;
  // struct wireguard_peer *peer = NULL;
  if (!wg->valid)
    return;

  res = sock_udp_recv_buf(sock, &stackbuf, &buf_ctx, 0, &remote);
  if (res < 0) {
    DEBUG("[wireguard] receive: udp recv failure: %" PRIdSIZE "\n", res);
    return;
  }

  message_type = wireguard_get_message_type(stackbuf, res);
  switch (message_type) {
  case MESSAGE_HANDSHAKE_INITIATION:
  case MESSAGE_HANDSHAKE_RESPONSE:
  case MESSAGE_HANDSHAKE_COOKIE: {
    wireguard_receive_handshake_packet(wg, stackbuf, res, &remote,
                                       message_type);
    break;
  }
  case MESSAGE_DATA: {
    struct message_transport_data *msg_data =
        (struct message_transport_data *)stackbuf;
    uint32_t receiver = byteorder_ltohl(msg_data->receiver_idx);
    peer = wireguard_peer_lookup_by_keypair_receiver(wg->peers, receiver);
    if (peer) {
      wireguard_consume_data(peer, msg_data, res - TRANSPORT_DATA_HEADER_LEN,
                             &remote);
    }
    break;
  }
  default:
    /* Unknown packet or bad header */
    break;
  }

  return;
}

static uint32_t wireguard_get_message_type(const uint8_t *buf, size_t len) {
  uint32_t result = MESSAGE_INVALID;
  if (len < 4) {
    return result;
  }

  uint32_t message_type = byteorder_lebuftohl(buf);
  switch (message_type) {
  case MESSAGE_HANDSHAKE_INITIATION:
    if (len == sizeof(struct message_handshake_initiation)) {
      result = MESSAGE_HANDSHAKE_INITIATION;
    }
    break;
  case MESSAGE_HANDSHAKE_RESPONSE:
    if (len == sizeof(struct message_handshake_response)) {
      result = MESSAGE_HANDSHAKE_RESPONSE;
    }
    break;
  case MESSAGE_HANDSHAKE_COOKIE:
    if (len == sizeof(struct message_cookie_reply)) {
      result = MESSAGE_HANDSHAKE_COOKIE;
    }
    break;
  case MESSAGE_DATA:
    if (len >= sizeof(struct message_transport_data) + NOISE_AUTHTAG_LEN) {
      result = MESSAGE_DATA;
    }
    break;
  default:
    break;
  }
  return result;
}

static void wireguard_receive_handshake_packet(wireguard_t *wg, uint8_t *buf,
                                               size_t len,
                                               sock_udp_ep_t *remote,
                                               uint32_t type) {
  (void)len;
  enum cookie_mac_state mac_state;
  struct wireguard_peer *peer = NULL;
  bool packet_needs_cookie;
  bool under_load;
  int result;
  unsigned state;
  /* Don't care about race during calculation of loading. */
  static uint32_t last_under_load;

  if (type == MESSAGE_HANDSHAKE_COOKIE) {
    DEBUG("[wireguard] receive: receving cookie\n");
    if (wireguard_cookie_message_consume((struct message_cookie_reply *)buf,
                                         wg)) {
      if (wireguard_set_endpoint(&peer->latest_endpoint, wg->netif->pid,
                                 remote) < 0) {
        DEBUG("[wireguard] receive: could not set endpoint\n");
        return;
      }
    }
    return;
  }

  state = irq_disable();
  under_load = clist_count(&wg->evq->event_list) > UNDER_LOAD_EVENT_QUEUE_SIZE;
  irq_restore(state);

  if (under_load) {
    last_under_load = ztimer_now(ZTIMER_MSEC);
  } else if (last_under_load) {
    under_load = !wireguard_expired_birthdate(last_under_load, 1);
    if (!under_load)
      last_under_load = 0;
  }

  mac_state = wireguard_cookie_validate_packet(&wg->cookie_checker, buf, len,
                                               remote, under_load);
  if ((under_load && mac_state == VALID_MAC_WITH_COOKIE) ||
      (!under_load && VALID_MAC_BUT_NO_COOKIE)) {
    packet_needs_cookie = false;
  } else if (under_load && mac_state == VALID_MAC_BUT_NO_COOKIE) {
    packet_needs_cookie = true;
  } else {
    DEBUG("[wireguard] receive: invalid mac from handshake, dropping packet\n");
    return;
  }

  switch (type) {
  case MESSAGE_HANDSHAKE_INITIATION: {
    struct message_handshake_initiation *msg =
        (struct message_handshake_initiation *)buf;
    if (packet_needs_cookie) {
      result = wireguard_send_cookie_reply(wg, buf, len, remote,
                                           byteorder_ltohl(msg->sender_index));
      if (result < 0) {
        DEBUG("[wireguard] receive: sending cookie reply failed\n");
      }
      return;
    }
    peer = wireguard_noise_handshake_consume_initiation(msg, wg);
    if (!peer || !peer->valid) {
      DEBUG("[wireguard] receive: invalid handshake initation from peer\n");
      return;
    }
    peer->active = true;

    /* TODO: concurency around endpoint */
    if (wireguard_set_endpoint(&peer->latest_endpoint, wg->netif->pid, remote) <
        0) {
      DEBUG("[wireguard] receive: can not set latest endpoint\n");
      break;
    }
    DEBUG("[wireguard] receive: receiving handshake initiation from peer\n");
    wireguard_send_handshake_response(peer);
    break;
  }
  case MESSAGE_HANDSHAKE_RESPONSE: {

    struct message_handshake_response *msg =
        (struct message_handshake_response *)buf;
    if (packet_needs_cookie) {
      result = wireguard_send_cookie_reply(wg, buf, len, remote,
                                           byteorder_ltohl(msg->sender_index));
      if (result < 0) {
        DEBUG("[wireguard] receive: sending cookie reply failed\n");
      }
      return;
    }

    peer = wireguard_noise_handshake_consume_response(msg, wg);
    if (!peer || !peer->valid) {
      DEBUG("[wireguard] receive: invalid handshake response from peer\n");
      return;
    }
    DEBUG("[wireguard] receive: consume handshake response\n");

    if (wireguard_noise_handshake_begin_session(&peer->handshake,
                                                &peer->keypairs)) {

      DEBUG("[wireguard] receive: sucessfully derive the keys\n");
      if (wireguard_set_endpoint(&peer->latest_endpoint, wg->netif->pid,
                                 remote) < 0) {
        DEBUG("[wireguard] receive: can not set latest endpoint\n");
        break;
      }
      /* sending keepalive to confirm the session */
      wireguard_send_keepalive(peer);
      // wg->netdev.event_callback(&wg->netdev, NETDEV_EVENT_LINK_UP);
    }
    break;
  }
  }
}

static int wireguard_send_pkt_to_peer(wireguard_t *wg, gnrc_pktsnip_t *pkt,
                                      const ipv6_addr_t *addr,
                                      struct wireguard_peer *peer) {
  (void)addr;
  struct noise_keypair *keypair;
  sock_udp_ep_t remote;
  int res = 0;

  keypair = &peer->keypairs.current_keypair;

  if (!keypair->valid || !keypair->sending.valid) {
    goto out_nokey;
  }

  if (wireguard_expired_birthdate(keypair->sending.birthdate,
                                  REJECT_AFTER_TIME) ||
      keypair->sending_counter >= REKEY_AFTER_MESSAGES) {
    goto out_invalid;
  }

  /* send to last now endpoint, not the preconfigured. */
  remote = peer->latest_endpoint;

  res = wireguard_prepare_transport_snip(pkt);
  if (res < 0) {
    return res;
  }

  wireguard_encrypt_packet(&peer->keypairs.current_keypair, pkt->data,
                           pkt->size);

  /* TODO: timer here */
  /* TODO: identify sending keep alive */

  res = sock_udp_send(&wg->udp, pkt->data, pkt->size, &remote);
  if (res < 0) {
    DEBUG("[wireguard] send: could not send transport data\n");
    return res;
  }

  /* TODO: add timer for data sent */
  peer->last_tx = ztimer_now(ZTIMER_MSEC);
  keep_key_fresh(peer);
  return 0;

out_invalid:
  /* destroy the sending key.*/
  keypair->sending.valid = false;
out_nokey:
  /* TODO: queue the first packet that come */
  return -ENOKEY;
}

static int wireguard_prepare_transport_snip(gnrc_pktsnip_t *pkt) {
  assert(pkt != NULL);
  size_t offset;
  size_t ipheader_offset;
  size_t plaintext_len;
  size_t trailer_len;
  size_t packet_len;
  uint8_t *buf;
  uint8_t *ip_end;
  int res = 0;

  offset = pkt->size;
  ipheader_offset = offset - 1;
  plaintext_len = gnrc_pkt_len(pkt);
  /* routnd to 16 bytes boundary */
  trailer_len =
      align_mask(plaintext_len, 16) - plaintext_len + noise_encrypted_len(0);
  packet_len = TRANSPORT_DATA_HEADER_LEN + plaintext_len + trailer_len;
  /* Re-allocate data to have enough buffer for:
   * transport_header + ipv6 packet + payload + padded 0 + auth tag*/
  res = gnrc_pktbuf_realloc_data(pkt, packet_len);
  if (res != 0) {
    DEBUG("[wireguard] send: realloc data failed");
    return res;
  }

  /* Copy data to new buffer */
  buf = ((uint8_t *)pkt->data) + TRANSPORT_DATA_HEADER_LEN;
  for (gnrc_pktsnip_t *ptr = pkt->next; ptr != NULL; ptr = ptr->next) {
    memcpy(buf + offset, ptr->data, ptr->size);
    offset += ptr->size;
  }
  /* reverse copying the ipv6 header since the transport header is shorter */
  ip_end = ((uint8_t *)pkt->data);
  /* Chapter 5.6: Mitigation Strategies for integer overflow in a reverse for
   * loop - Secure Coding in C and C++ */
  for (size_t i = ipheader_offset; i != SIZE_MAX; i--) {
    buf[i] = ip_end[i];
  }

  /* Note: do we have to hadnle ipv6 checksum? */

  /* Release old pktsnips and data*/
  gnrc_pktbuf_release(pkt->next);
  pkt->next = NULL;

  return 0;
}

static void wireguard_encrypt_packet(struct noise_keypair *keypair, void *buf,
                                     size_t len) {
  struct message_transport_data *header;
  uint8_t *dst;
  uint8_t nonce[CHACHA20POLY1305_NONCE_BYTES];
  memset(nonce, 0, CHACHA20POLY1305_NONCE_BYTES);
  memcpy(&nonce[4], (uint8_t *)&keypair->sending_counter, sizeof(uint64_t));

  header = (struct message_transport_data *)buf;
  header->header.type = byteorder_htoll(MESSAGE_DATA);
  header->receiver_idx = byteorder_htoll(keypair->remote_index);
  header->counter = byteorder_htolll(keypair->sending_counter);
  dst = &header->encrypted_data[0];
  chacha20poly1305_encrypt(dst, dst,
                           len - TRANSPORT_DATA_HEADER_LEN - NOISE_AUTHTAG_LEN,
                           NULL, 0, keypair->sending.key, nonce);
  keypair->sending_counter++;
}

static void keep_key_fresh(struct wireguard_peer *peer) {
  struct noise_keypair *keypair;
  bool send;
  keypair = &peer->keypairs.current_keypair;
  send = keypair->valid && keypair->sending.valid &&
         ((keypair->sending_counter > REKEY_AFTER_MESSAGES) ||
          (keypair->initiator &&
           wireguard_expired_birthdate(keypair->birthdate, REKEY_AFTER_TIME)));
  if (send) {
    /* TODO: resend handshake initiation, reread the timer */
  }
}

int wireguard_set_endpoint(sock_udp_ep_t *endpoint, unsigned int iface,
                           sock_udp_ep_t *remote) {

  /* TODO: this whole process of adding neighbor cache is hacky */
  /* register neighbor cache entry to send data out */
  ipv6_addr_t dst;
  memcpy(&dst.u8, endpoint->addr.ipv6, sizeof(ipv6_addr_t));
  gnrc_ipv6_nib_nc_del(&dst, iface);
  memcpy(endpoint, remote, sizeof(sock_udp_ep_t));
  memcpy(&dst.u8, remote->addr.ipv6, sizeof(ipv6_addr_t));
  return gnrc_ipv6_nib_nc_set(&dst, iface, NULL, 0);
}

int wireguard_send_keepalive(struct wireguard_peer *peer) {
  uint8_t pkt[TRANSPORT_DATA_HEADER_LEN + noise_encrypted_len(0)];
  int res;
  memset(pkt, 0, sizeof(pkt));
  wireguard_encrypt_packet(&peer->keypairs.current_keypair, pkt, sizeof(pkt));
  res = sock_udp_send(&peer->device->udp, pkt, sizeof(pkt), &peer->endpoint);
  if (res < 0) {
    DEBUG("[wireguard] send: could not send keeaplive transport data\n");
  }
  return res;
}

static struct noise_keypair *
get_peer_keypair_for_idx(struct wireguard_peer *peer, uint32_t idx) {
  struct noise_keypairs *keypairs = &peer->keypairs;
  if (keypairs->current_keypair.valid &&
      keypairs->current_keypair.local_index == idx) {
    return &keypairs->current_keypair;
  } else if (keypairs->next_keypair.valid &&
             keypairs->next_keypair.local_index == idx) {
    return &keypairs->next_keypair;
  } else if (keypairs->previous_keypair.valid &&
             keypairs->previous_keypair.local_index == idx) {
    return &keypairs->previous_keypair;
  }
  return NULL;
}

/* implementation of RFC 2401, appendix C */
static bool wireguard_anti_replay(struct noise_keypair *keypair, uint64_t seq) {
  uint32_t diff;
  struct noise_replay_window *window = &keypair->receiving_counter;

  /* Wireguard nonce starts from 0, but the algorithm expects the number start
   * from 1*/
  seq++;

  if (seq == 0)
    /* first == 0 or wrapped */
    return false;

  if (seq > window->last_seq) {
    /* new larger sequence number */
    diff = seq - window->last_seq;
    if (diff < REPLAY_WINDOW_SIZE) {
      /* in window */
      window->bitmap <<= diff;
      window->bitmap |= 1; /* set bit for this packet */
    } else {
      window->bitmap = 1; /* This packet has a "way larger" */
    }
    window->last_seq = seq;
    return true; /* larger is good */
  }

  diff = window->last_seq - seq;
  if (diff >= REPLAY_WINDOW_SIZE)
    return false; /* too old or wrapped */

  if (window->bitmap & (((uint32_t)1) << diff))
    return false; /* already seen */
  window->bitmap = ((uint32_t)1) << diff;
  return true;
}

static void wireguard_dispatch_ipv6_pkt(wireguard_t *wg, uint8_t *buf,
                                        size_t len) {
  /* allocate netif header */
  gnrc_pktsnip_t *if_snip = gnrc_netif_hdr_build(NULL, 0, NULL, 0);
  if (if_snip == NULL) {
    DEBUG("[wireguard] receive: out of memory\n");
    return;
  }

  /* add device PID to the netif header */
  gnrc_netif_hdr_set_netif(if_snip->data, wg->netif);
  /* allocate payload */
  gnrc_pktsnip_t *payload =
      gnrc_pktbuf_add(if_snip, buf, len, GNRC_NETTYPE_IPV6);

  if (payload == NULL) {
    DEBUG("[wireguard] receive: out of memory\n");
    gnrc_pktbuf_release(if_snip);
    return;
  }

  /* finally dispatch the receive packet to GNRC */
  if (!gnrc_netapi_dispatch_receive(payload->type, GNRC_NETREG_DEMUX_CTX_ALL,
                                    payload)) {
    DEBUG("[wireguard] receive: could not dispatch packet\n");
    gnrc_pktbuf_release(payload);
  }
}

static void wireguard_consume_data(struct wireguard_peer *peer,
                                   struct message_transport_data *data,
                                   size_t len, sock_udp_ep_t *remote) {
  struct noise_keypair *keypair;
  struct wireguard_peer *routed_peer;
  uint64_t counter;
  uint8_t *src;
  uint8_t nonce[CHACHA20POLY1305_NONCE_BYTES];
  size_t msg_len;
  ipv6_hdr_t *iphdr;
  wireguard_t *wg = peer->device;
  uint32_t idx = byteorder_ltohl(data->receiver_idx);

  keypair = get_peer_keypair_for_idx(peer, idx);
  if (!keypair || !keypair->valid) {
    return;
  }

  if (!keypair->receiving.valid ||
      wireguard_expired_birthdate(keypair->birthdate, REJECT_AFTER_TIME) ||
      keypair->sending_counter >= REJECT_AFTER_MESSAGES) {
    /* refusing to receive any new data until a new session is made */
    keypair->receiving.valid = false;
    return;
  }

  counter = byteorder_ltohll(data->counter);

  if (!wireguard_anti_replay(keypair, counter)) {
    /* discared duplicated/replayed packets */
    DEBUG("[wireguard] receive: get replay attackecd\n");
    return;
  }
  memset(nonce, 0, sizeof(nonce));
  memcpy(&nonce[4], (uint8_t *)&counter, sizeof(uint64_t));

  src = &data->encrypted_data[0];

  if (!chacha20poly1305_decrypt(src, len, src, &msg_len, NULL, 0,
                                keypair->receiving.key, nonce)) {
    DEBUG("[wireguard] receive: decrypt failed\n");
    return;
  }

  if (wireguard_set_endpoint(&peer->latest_endpoint, peer->device->netif->pid,
                             remote) < 0) {
    DEBUG("[wireguard] receive: set endpoint failed\n");
    return;
  }

  wireguard_noise_received_with_keypair(&peer->keypairs, keypair);

  /* Check rekey condition */
  if (keypair->initiator &&
      wireguard_expired_birthdate(keypair->birthdate,
                                  REJECT_AFTER_TIME - peer->keepalive_interval -
                                      REKEY_TIMEOUT)) {
    /* TODO: add rekey timer */
  }

  /* keep alive packet */
  if (msg_len == 0) {
    DEBUG("[wireguard] receive: keepalive packet\n");
    return;
  }

  iphdr = (ipv6_hdr_t *)src;
  /* if not an ip packet drop it */
  if (msg_len < sizeof(ipv6_hdr_t) || !ipv6_hdr_is(iphdr)) {
    DEBUG("[wireguard] receive: dropping an invalid ipv6 packet");
    return;
  }

  /* check the IP address against the routing table */
  routed_peer = wireguard_peer_lookup_by_allowed_ip(wg->peers, &iphdr->src);
  if (routed_peer != peer) {
    /* dishonest peer */
    DEBUG("[wireguard] receive: packet has unallowed src IPs\n");
    return;
  }

  wireguard_dispatch_ipv6_pkt(peer->device, src, len);
}

static int wireguard_send_cookie_reply(wireguard_t *wg, uint8_t *buf,
                                       size_t len, sock_udp_ep_t *remote,
                                       uint32_t index) {
  struct message_cookie_reply packet;

  wireguard_cookie_message_create(&packet, buf, len, remote, index,
                                  &wg->cookie_checker);
  /* send in reply to received handshake packet */
  return sock_udp_send(&wg->udp, &packet, sizeof(packet), remote);
}
