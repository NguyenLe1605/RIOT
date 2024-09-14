#include "net/wireguard/device.h"
#include "base64.h"
#include "byteorder.h"
#include "container.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/helper.h"
#include "net/gnrc/netif/hdr.h"
#include "net/gnrc/nettype.h"
#include "net/gnrc/pkt.h"
#include "net/gnrc/pktbuf.h"
#include "net/ipv6/addr.h"
#include "net/ipv6/hdr.h"
#include "net/netdev.h"
#include "net/netopt.h"
#include "net/sock.h"
#include "net/sock/async.h"
#include "net/sock/async/types.h"
#include "net/sock/udp.h"
#include "net/wireguard.h"
#include "net/wireguard/cookie.h"
#include "net/wireguard/messages.h"
#include "net/wireguard/noise.h"
#include "net/wireguard/peer.h"
#include "net/wireguard/timer.h"
#include "ztimer.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ENABLE_DEBUG 1
#include "debug.h"

#define REPLAY_WINDOW_SIZE (32)
#define COOKIE_NONCE_LEN (24)

static const netdev_driver_t wireguard_driver;

static void wireguard_cleanup(wireguard_t *wg) {
  crypto_secure_wipe(wg->static_identity.static_public, NOISE_PUBLIC_KEY_LEN);
  crypto_secure_wipe(wg->static_identity.static_private, NOISE_PRIVATE_KEY_LEN);
  wg->static_identity.has_identity = false;
}

static void wireguard_receive_handshake_packet(wireguard_t *wg, uint8_t *buf,
                                               size_t len,
                                               sock_udp_ep_t *remote,
                                               uint32_t type) {
  enum cookie_mac_state mac_state;
  struct wg_peer *peer = NULL;
  bool packet_needs_cookie;
  bool under_load;
  int result;
  /* Don't care about race during calculation of loading. */
  static uint32_t last_under_load;

  if (type == MESSAGE_HANDSHAKE_COOKIE) {
    DEBUG("wireguard_receive: receving cookie\n");
    if (wg_cookie_message_consume((struct message_cookie_reply *)buf, wg)) {
      peer->latest_endpoint = *remote;
      // memcpy(&peer->latest_endpoint, remote, sizeof(sock_udp_ep_t));
    }
    return;
  }

  /* under load condition */
  under_load = wg->num_handshake >= MAX_NUM_OF_HANSHAKE;
  if (under_load) {
    last_under_load = ztimer_now(ZTIMER_MSEC);
  } else if (last_under_load) {
    under_load = !wg_birthdate_has_expired(last_under_load, 1);
    if (!under_load)
      last_under_load = 0;
  }

  mac_state = wg_cookie_validate_packet(&wg->cookie_checker, buf, len, remote,
                                        under_load);
  if ((under_load && mac_state == VALID_MAC_WITH_COOKIE) ||
      (!under_load && VALID_MAC_BUT_NO_COOKIE)) {
    packet_needs_cookie = false;
  } else if (under_load && mac_state == VALID_MAC_BUT_NO_COOKIE) {
    packet_needs_cookie = true;
  } else {
    DEBUG("wireguard_receive: invalid mac from handshake, dropping packet\n");
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
        DEBUG("wireguard_receive: sending cookie reply failed\n");
      }
      return;
    }
    peer = wg_noise_handshake_consume_initiation(msg, wg);
    if (!peer->valid) {
      DEBUG("wireguard_receive: invalid handshake initation from peer\n");
      return;
    }

    memcpy(&peer->latest_endpoint, remote, sizeof(sock_udp_ep_t));
    DEBUG("wireguard receive: receiving handshake initiation from peer\n");
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
        DEBUG("wireguard_receive: sending cookie reply failed\n");
      }
      return;
    }
    peer = wg_noise_handshake_consume_response(msg, wg);
    if (!peer->valid) {
      DEBUG("wireguard_receive: invalid handshake response from peer\n");
      return;
    }

    if (wg_noise_handshake_begin_session(&peer->handshake, &peer->keypairs)) {

      DEBUG("wireguard receive: receiving handshake receive from peer\n");
      memcpy(&peer->latest_endpoint, remote, sizeof(sock_udp_ep_t));
      /* sending keepalive to confirm the session */
      wireguard_send_keepalive(peer);
      wg->netdev.event_callback(&wg->netdev, NETDEV_EVENT_LINK_UP);
    }
    break;
  }
  }
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

static struct noise_keypair *get_peer_keypair_for_idx(struct wg_peer *peer,
                                                      uint32_t idx) {
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
    return;
  }

  /* add device PID to the netif header */
  gnrc_netif_hdr_set_netif(if_snip->data, wg->netif);
  /* allocate payload */
  gnrc_pktsnip_t *payload =
      gnrc_pktbuf_add(if_snip, buf, len, GNRC_NETTYPE_IPV6);

  if (payload == NULL) {
    gnrc_pktbuf_release(if_snip);
    return;
  }

  /* finally dispatch the receive packet to GNRC */
  if (!gnrc_netapi_dispatch_receive(payload->type, GNRC_NETREG_DEMUX_CTX_ALL,
                                    payload)) {
    gnrc_pktbuf_release(payload);
  }
}

static void wireguard_consume_data(struct wg_peer *peer,
                                   struct message_transport_data *data,
                                   size_t len, sock_udp_ep_t *remote) {

  struct noise_keypair *keypair;
  struct wg_peer *routed_peer;
  uint64_t nonce;
  uint8_t *src;
  size_t src_len;
  ipv6_hdr_t *iphdr;
  wireguard_t *wg = peer->device;
  uint32_t idx = byteorder_ltohl(data->receiver_idx);

  keypair = get_peer_keypair_for_idx(peer, idx);
  if (!keypair) {
    return;
  }

  if (!keypair->receiving.valid ||
      wg_birthdate_has_expired(keypair->birthdate, REJECT_AFTER_TIME) ||
      keypair->sending_counter >= REJECT_AFTER_MESSAGES) {
    /* refusing to receive any new data until a new session is made */
    keypair->receiving.valid = false;
    return;
  }

  nonce = byteorder_ltohll(data->counter);
  src = &data->encrypted_data[0];
  src_len = len;

  if (!chacha20poly1305_decrypt(src, len, src, &src_len, NULL, 0,
                                keypair->receiving.key, (uint8_t *)&nonce)) {
    return;
  }

  memcpy(&peer->latest_endpoint, remote, sizeof(sock_udp_ep_t));
  peer->last_rx = ztimer_now(ZTIMER_MSEC);

  /* Shuffle to the next keypair to the current keypair*/
  wg_noise_received_with_keypair(&peer->keypairs, keypair);

  /* Check rekey condition */
  if (keypair->initiator &&
      wg_birthdate_has_expired(keypair->birthdate,
                               REJECT_AFTER_TIME - peer->keepalive_interval -
                                   REKEY_TIMEOUT)) {
    peer->send_handshake = true;
  }

  /* Ensure the link to be up */
  wg->netdev.event_callback(&wg->netdev, NETDEV_EVENT_LINK_UP);

  if (src_len > 0) {
    /* keepalive packet */
    return;
  }

  iphdr = (ipv6_hdr_t *)src;
  /* if not an ip packet drop it */
  if (src_len < sizeof(ipv6_hdr_t) || !ipv6_hdr_is(iphdr)) {
    DEBUG("wireguard_receive: dropping an invalid ipv6 packet");
    return;
  }

  if (!wireguard_anti_replay(keypair, nonce)) {
    /* discared duplicated/replayed packets */
    return;
  }

  /* check the IP address against the routing table */
  routed_peer = peer_lookup_by_allowed_ip(wg->peers, &iphdr->src);
  if (routed_peer != peer) {
    /* dishonest peer */
    DEBUG("wireguard_receive: packet has unallowed src IPs\n");
    return;
  }

  wireguard_dispatch_ipv6_pkt(peer->device, src, len);
}

static void _receive(sock_udp_t *sock, sock_async_flags_t type, void *arg) {
  if (!(type & SOCK_ASYNC_MSG_RECV)) {
    return;
  }
  void *stackbuf;
  void *buf_ctx = NULL;
  sock_udp_ep_t remote;
  uint32_t message_type;
  ssize_t res;
  wireguard_t *wg = (wireguard_t *)arg;
  struct wg_peer *peer = NULL;
  if (!wg->valid)
    return;

  res = sock_udp_recv_buf(sock, &stackbuf, &buf_ctx, 0, &remote);
  if (res < 0) {
    printf("wireguard: udp recv failure: %" PRIdSIZE "\n", res);
    return;
  }

  message_type = wireguard_get_message_type(stackbuf, res);
  switch (message_type) {
  case MESSAGE_HANDSHAKE_INITIATION:
  case MESSAGE_HANDSHAKE_RESPONSE:
  case MESSAGE_HANDSHAKE_COOKIE: {
    wg->num_handshake++;
    wireguard_receive_handshake_packet(wg, stackbuf, res, &remote,
                                       message_type);
    wg->num_handshake--;
    break;
  }
  case MESSAGE_DATA: {
    struct message_transport_data *msg_data =
        (struct message_transport_data *)stackbuf;
    uint32_t receiver = byteorder_ltohl(msg_data->receiver_idx);
    peer = peer_lookup_by_handshake_receiver(wg->peers, receiver);
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

static int _get(netdev_t *dev, netopt_t opt, void *value, size_t max_len) {
  (void)dev;
  int result = -ENOTSUP;
  switch (opt) {
  case NETOPT_MAX_PDU_SIZE:
    assert(max_len >= sizeof(uint16_t));
    *((uint16_t *)value) = WIREGUARD_MTU;
    result = sizeof(uint16_t);
    break;
  case NETOPT_DEVICE_TYPE:
    assert(max_len == sizeof(uint16_t));
    *((uint16_t *)value) = NETDEV_TYPE_WIREGUARD;
    result = sizeof(uint16_t);
    break;
  case NETOPT_PROTO:
    assert(max_len == sizeof(gnrc_nettype_t));
    *((gnrc_nettype_t *)value) = GNRC_NETTYPE_IPV6;
    result = sizeof(gnrc_nettype_t);
    break;
  default:
    break;
  }
  return result;
}

int _set(netdev_t *dev, netopt_t opt, const void *value, size_t len) {
  (void)dev;
  (void)opt;
  (void)value;
  (void)len;
  /* TODO: add option to set encryption key and ipv6 address */
  return -ENOTSUP;
}

static bool wireguard_add_private_key(wireguard_t *dev,
                                      const uint8_t *private_key) {

  assert(dev);
  wg_noise_set_static_identity_private_key(&dev->static_identity, private_key);
  dev->valid = dev->static_identity.has_identity;
  if (!dev->valid) {
    crypto_secure_wipe(dev->static_identity.static_private,
                       NOISE_PRIVATE_KEY_LEN);
  } else {
    wg_cookie_checker_precompute_device_keys(&dev->cookie_checker);
  }
  return dev->valid;
}

static int _init(netdev_t *dev) {
  assert(dev);
  wireguard_t *wg;
  sock_udp_ep_t local_ep;
  uint8_t private_key[NOISE_PRIVATE_KEY_LEN];
  size_t private_key_len;
  size_t key_len;
  int result;

  result = 0;
  wg = container_of(dev, wireguard_t, netdev);

  wg_noise_init();
  wg_cookie_checker_init(&wg->cookie_checker, wg);

  key_len = BASE64_PRIVATE_KEY_LEN;
  private_key_len = key_len;
  if (base64_decode(wg->param->private_key, key_len, (void *)private_key,
                    &private_key_len) != BASE64_SUCCESS ||
      private_key_len != NOISE_PRIVATE_KEY_LEN) {
    return -EINVAL;
  }

  if (!wireguard_add_private_key(wg, private_key)) {
    return -EINVAL;
  }

  crypto_secure_wipe(private_key, private_key_len);

  wg->listen_port = wg->param->listen_port;
  wg->bind_netif = wg->param->bind_netif;
  wg->param = NULL;

  /* initalize the udp port, with the preconfigured bind-netif */
  local_ep = (sock_udp_ep_t)SOCK_IPV6_EP_ANY;
  local_ep.port = wg->listen_port ? wg->listen_port : WIREGUARD_DEFAULT_PORT;
  local_ep.netif = wg->bind_netif ? wg->bind_netif : SOCK_ADDR_ANY_NETIF;

  if ((result = sock_udp_create(&wg->udp, &local_ep, NULL, 0)) < 0) {
    wireguard_cleanup(wg);
    return result;
  }

  /* set callback to handle receiving UDP packet */
  sock_udp_set_cb(&wg->udp, _receive, (void *)wg);

  wg->netif = (gnrc_netif_t *)dev->context;

  /* set up periodic timer to handle timer state machine */
  wg->timer.callback = wireguard_timer;
  wg->timer.arg = wg;
  ztimer_set(ZTIMER_MSEC, &wg->timer, TIMER_INTERVAL_MSEC);

  /* set the link to be up */
  dev->event_callback(dev, NETDEV_EVENT_LINK_UP);

  return result;
}

void wireguard_setup(wireguard_t *dev, wireguard_params_t *param) {
  assert(param);
  memset(dev, 0, sizeof(wireguard_t));
  netdev_t *netdev = &dev->netdev;
  dev->param = param;
  netdev->driver = &wireguard_driver;
  netdev_register(netdev, NETDEV_WIREGUARD, 0);
}

static const netdev_driver_t wireguard_driver = {
    .init = _init,
    .get = _get,
    .set = _set,
};

static int wireguard_send_buffer_to_peer(struct wg_peer *peer, uint8_t *buffer,
                                         size_t len) {
  /* TODO: add support for DSCP and ECN */
  return sock_udp_send(&peer->device->udp, buffer, len, &peer->latest_endpoint);
}

int wireguard_send_handshake_initiation(struct wg_peer *peer) {
  int result = 0;
  struct message_handshake_initiation packet;
  /* TODO: add timeout due to REKEY_TIMEOUT */

  if (wg_noise_handshake_create_initiation(&packet, &peer->handshake,
                                           peer->device)) {
    wg_cookie_add_mac_to_packet(&packet, sizeof(packet), peer);
    peer->last_sent_handshake = ztimer_now(ZTIMER_MSEC);
    result =
        wireguard_send_buffer_to_peer(peer, (uint8_t *)&packet, sizeof(packet));

    if (result < 0) {
      DEBUG("wireguard_send: could not send handshake initiation - %d\n",
            result);
    }

    peer->send_handshake = false;
    peer->last_initiation_tx = ztimer_now(ZTIMER_MSEC);

  } else {
    result = -EINVAL;
  }
  return result;
}

int wireguard_send_handshake_response(struct wg_peer *peer) {
  int result = 0;
  struct message_handshake_response packet;

  if (wg_noise_handshake_create_response(&packet, &peer->handshake,
                                         peer->device)) {
    /* TODO: add timer */
    wg_cookie_add_mac_to_packet(&packet, sizeof(packet), peer);
    if (!wg_noise_handshake_begin_session(&peer->handshake, &peer->keypairs)) {
      return -EINVAL;
    }
    result =
        wireguard_send_buffer_to_peer(peer, (uint8_t *)&packet, sizeof(packet));

  } else {
    result = -EINVAL;
  }
  return result;
}

int wireguard_send_cookie_reply(wireguard_t *wg, uint8_t *buf, size_t len,
                                sock_udp_ep_t *remote, uint32_t index) {
  struct message_cookie_reply packet;

  wg_cookie_message_create(&packet, buf, len, remote, index,
                           &wg->cookie_checker);
  /* send in reply to received handshake packet */
  return sock_udp_send(&wg->udp, &packet, sizeof(packet), remote);
}

static void wireguard_encrypt_packet(struct noise_keypair *keypair, void *buf,
                                     size_t len) {
  struct message_transport_data *header;
  uint8_t *dst;
  header = (struct message_transport_data *)buf;
  header->header.type = byteorder_htoll(MESSAGE_DATA);
  header->receiver_idx = byteorder_htoll(keypair->remote_index);
  header->counter = byteorder_htolll(keypair->sending_counter);
  dst = &header->encrypted_data[0];
  chacha20poly1305_encrypt(dst, dst, len - TRANSPORT_DATA_HEADER_LEN, NULL, 0,
                           keypair->sending.key,
                           (uint8_t *)&keypair->sending_counter);
  keypair->sending_counter++;
}

static inline size_t align_mask(size_t len, size_t mask) {
  return (len + (mask - 1)) & ~(mask);
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
    DEBUG("_send_wireguard: realloc data failed");
    return res;
  }

  /* Copy data to new buffer */
  buf = ((uint8_t *)pkt->data) + TRANSPORT_DATA_HEADER_LEN;
  for (gnrc_pktsnip_t *ptr = pkt->next; ptr != NULL; ptr = ptr->next) {
    memcpy(buf + offset, ptr->data, ptr->size);
    offset += ptr->size;
  }
  /* reverse copying the ipv6 header since the transport header is shorter */
  buf += ipheader_offset;
  ip_end = ((uint8_t *)pkt->data) + ipheader_offset;
  for (size_t i = ipheader_offset; i != SIZE_MAX; i--) {
    buf[i] = ip_end[i];
  }

  /* Note: do we have to hadnle ipv6 checksum? */

  /* Release old pktsnips and data*/
  gnrc_pktbuf_release(pkt->next);
  pkt->next = NULL;

  return 0;
}

static int wireguard_send_pkt_to_peer(wireguard_t *wg, gnrc_pktsnip_t *pkt,
                                      const ipv6_addr_t *addr,
                                      struct wg_peer *peer) {

  struct noise_keypair *keypair;
  sock_udp_ep_t remote;
  int res = 0;

  keypair = &peer->keypairs.current_keypair;
  if (keypair->valid && keypair->sending.valid && (!keypair->initiator) &&
      (peer->last_rx == 0)) {
    keypair = &peer->keypairs.previous_keypair;
  }

  /* uninitialized keypair or a responder but have not received any data */
  if (!keypair->valid || !keypair->sending.valid ||
      !(keypair->initiator || peer->last_rx != 0))
    goto out_nokey;

  /* making current session is unusable until a new session is created through
   * handshake */
  if (wg_birthdate_has_expired(keypair->birthdate, REJECT_AFTER_TIME) ||
      keypair->sending_counter >= REJECT_AFTER_MESSAGES)
    goto out_invalid;

  remote = peer->endpoint;
  memcpy(remote.addr.ipv6, addr, sizeof(ipv6_addr_t));
  res = wireguard_prepare_transport_snip(pkt);
  if (res < 0) {
    return res;
  }
  /* encrypt the packet */
  wireguard_encrypt_packet(&peer->keypairs.current_keypair, pkt->data,
                           pkt->size);

  /* send the actual data out through UDP */
  res = sock_udp_send(&wg->udp, pkt->data, pkt->size, &remote);
  if (res < 0) {
    DEBUG("_send_wireguard: could not send transport data\n");
    return res;
  }
  peer->last_tx = ztimer_now(ZTIMER_MSEC);
  /* keeping key fresh */
  if (keypair->sending_counter >= REKEY_AFTER_MESSAGES ||
      (keypair->initiator &&
       wg_birthdate_has_expired(keypair->birthdate, REKEY_AFTER_TIME))) {
    peer->send_handshake = true;
  }
  return 0;

out_invalid:
  wg_noise_destroy_keypair(&peer->keypairs.current_keypair);
out_nokey:
  return -ENOKEY;
}

int wireguard_send_keepalive(struct wg_peer *peer) {
  uint8_t pkt[TRANSPORT_DATA_HEADER_LEN + noise_encrypted_len(0)];
  int res;
  memset(pkt, 0, sizeof(pkt));
  wireguard_encrypt_packet(&peer->keypairs.current_keypair, pkt, sizeof(pkt));
  res = sock_udp_send(&peer->device->udp, pkt, sizeof(pkt), &peer->endpoint);
  if (res < 0) {
    DEBUG("_send_wireguard: could not send keeaplive transport data\n");
  }
  return res;
}

int wireguard_send(wireguard_t *wg, gnrc_pktsnip_t *pkt,
                   const ipv6_addr_t *addr) {
  struct wg_peer *peer;

  peer = peer_lookup_by_allowed_ip(wg->peers, addr);
  if (!peer) {
    /* if match no peer, the packet is dropped */
    return -ENOKEY;
  }
  return wireguard_send_pkt_to_peer(wg, pkt, addr, peer);
}
