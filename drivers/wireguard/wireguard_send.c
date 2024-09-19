#include "net/gnrc/pktbuf.h"
#include "net/gnrc/pktqueue.h"
#include "net/ipv6/addr.h"
#include "net/ipv6/hdr.h"
#include "wireguard.h"
#include "wireguard_constants.h"
#include "wireguard_internal.h"
#include "wireguard_timer.h"
#include "ztimer.h"

#define ENABLE_DEBUG 1
#include "debug.h"

static gnrc_pktqueue_t queue_pool[MAX_PEERS_PER_DEVICE * 2];

static inline int wireguard_send_buffer_to_peer(struct wireguard_peer *peer,
                                                uint8_t *buffer, size_t len) {
  return sock_udp_send(&peer->device->udp, buffer, len, &peer->latest_endpoint);
}

static inline size_t align_mask(size_t len, size_t mask) {
  return (len + (mask - 1)) & ~(mask);
}
static int wireguard_send_pkt_to_peer(wireguard_t *wg, gnrc_pktsnip_t *pkt,
                                      struct wireguard_peer *peer,
                                      bool is_retry);
static int wireguard_prepare_transport_snip(gnrc_pktsnip_t *pkt);
static void wireguard_encrypt_packet(struct noise_keypair *keypair, void *buf,
                                     size_t len);

static void keep_key_fresh(struct wireguard_peer *peer);
static gnrc_pktqueue_t *_alloc_queue_entry(gnrc_pktsnip_t *pkt);

int wireguard_send_keepalive(struct wireguard_peer *peer) {
  uint8_t pkt[TRANSPORT_DATA_HEADER_LEN + noise_encrypted_len(0)];
  memset(pkt, 0, sizeof(pkt));
  gnrc_pktsnip_t data;

  if (peer->queue_entry == NULL) {
    /* TODO: fine for now as sending only required the data, size, and it checks
     * for the size of keep alive packets */
    data = (gnrc_pktsnip_t){.data = pkt,
                            .size = TRANSPORT_DATA_HEADER_LEN +
                                    noise_encrypted_len(0)};
    return wireguard_send_pkt_to_peer(peer->device, &data, peer, false);
  }
  return wireguard_send_queuing_packets(peer);
}

int wireguard_send_cookie_reply(wireguard_t *wg, uint8_t *buf, size_t len,
                                sock_udp_ep_t *remote, uint32_t index) {
  struct message_cookie_reply packet;

  wireguard_cookie_message_create(&packet, buf, len, remote, index,
                                  &wg->cookie_checker);
  /* send in reply to received handshake packet */
  return sock_udp_send(&wg->udp, &packet, sizeof(packet), remote);
}

int wireguard_send(wireguard_t *dev, gnrc_pktsnip_t *pkt) {
  struct wireguard_peer *peer;
  ipv6_hdr_t *hdr = (ipv6_hdr_t *)pkt->data;
  ipv6_addr_t addr = hdr->dst;

  peer = wireguard_peer_lookup_by_allowed_ip(dev->peers, &addr);

  if (!peer || !peer->valid) {
    /* if match no peer, the packet is dropped */
    return -ENOKEY;
  }

  return wireguard_send_pkt_to_peer(dev, pkt, peer, false);
}

static int wireguard_send_pkt_to_peer(wireguard_t *wg, gnrc_pktsnip_t *pkt,
                                      struct wireguard_peer *peer,
                                      bool is_retry) {
  struct noise_keypair *keypair;
  sock_udp_ep_t remote;
  gnrc_pktqueue_t *entry;
  bool data_sent = false;
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

  if (pkt->size - NOISE_AUTHTAG_LEN > TRANSPORT_DATA_HEADER_LEN) {
    res = wireguard_prepare_transport_snip(pkt);
    if (res < 0) {
      return res;
    }
    data_sent = true;
  }

  wireguard_encrypt_packet(&peer->keypairs.current_keypair, pkt->data,
                           pkt->size);

  wireguard_timers_any_authenticated_packet_traversal(peer);
  wireguard_timers_any_authenticated_packet_sent(peer);
  res = sock_udp_send(&wg->udp, pkt->data, pkt->size, &remote);

  if (data_sent) {
    wireguard_timers_data_sent(peer);
  }
  keep_key_fresh(peer);
  if (is_retry) {
    gnrc_pktbuf_release(pkt);
  }
  return res;

out_invalid:
  /* destroy the sending key.*/
  keypair->sending.valid = false;
out_nokey:
  if (!is_retry) {
    gnrc_pktbuf_hold(pkt, 1);
  }
  entry = _alloc_queue_entry(pkt);
  if (entry != NULL) {
    /* TODO: hold the pkt */
    gnrc_pktqueue_add(&peer->queue_entry, entry);
  }

  wireguard_sched_handshake_init(peer, false);

  return -ENOKEY;
}

static void wireguard_handshake_init_handler(event_t *evt) {
  peer_event_t *hs_evt = container_of(evt, peer_event_t, super);
  wireguard_send_handshake_initiation(hs_evt->peer);
}

void wireguard_sched_handshake_init(struct wireguard_peer *peer,
                                    bool is_retry) {
  assert(peer);

  if (!is_retry) {
    peer->handshake_attempts = 0;
  }

  /* check if we have sent any previous handshake so that we don't have to queue
   * anything unnecessary. */
  if (!wireguard_expired_birthdate(peer->last_sent_handshake, REKEY_TIMEOUT) ||
      !peer->valid) {
    return;
  }

  /* Set the flag to indictate we want to actively connect */
  peer->active = true;
  /* WARN: add to neighbor cache so that it works for now */
  wireguard_set_endpoint(&peer->latest_endpoint, peer->device->netif->pid,
                         &peer->endpoint);
  peer->handshake_init_evt = (peer_event_t){
      .super.handler = wireguard_handshake_init_handler, .peer = peer};
  event_post(peer->device->evq, &peer->handshake_init_evt.super);
  return;
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

int wireguard_send_handshake_initiation(struct wireguard_peer *peer) {
  int result = 0;
  struct message_handshake_initiation packet;
  peer->active = true;
  /* TODO: add timeout due to REKEY_TIMEOUT */

  if (!wireguard_expired_birthdate(peer->last_sent_handshake, REKEY_TIMEOUT)) {
    return 0;
  }
  peer->last_sent_handshake = ztimer_now(ZTIMER_MSEC);

  if (wireguard_noise_handshake_create_initiation(&packet, &peer->handshake,
                                                  peer->device)) {
    wireguard_cookie_add_mac_to_packet(&packet, sizeof(packet), peer);

    wireguard_timers_any_authenticated_packet_traversal(peer);
    wireguard_timers_any_authenticated_packet_sent(peer);

    peer->last_sent_handshake = ztimer_now(ZTIMER_MSEC);
    result =
        wireguard_send_buffer_to_peer(peer, (uint8_t *)&packet, sizeof(packet));

    if (result < 0) {
      DEBUG("[wireguard] send: could not send handshake initiation - %d\n",
            result);
    }
    wireguard_timers_handshake_initiated(peer);
  } else {
    result = -EINVAL;
  }
  DEBUG("[wireguard] send: send handshake initiation sucessfully \n");
  return result;
}

int wireguard_send_handshake_response(struct wireguard_peer *peer) {
  int result = 0;
  struct message_handshake_response packet;
  peer->last_sent_handshake = ztimer_now(ZTIMER_MSEC);

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
    wireguard_timers_session_derived(peer);
    wireguard_timers_any_authenticated_packet_traversal(peer);
    wireguard_timers_any_authenticated_packet_sent(peer);

    peer->last_sent_handshake = ztimer_now(ZTIMER_MSEC);
    result =
        wireguard_send_buffer_to_peer(peer, (uint8_t *)&packet, sizeof(packet));

  } else {
    DEBUG("[wireguard] send: could not create handshake response\n");
    result = -EINVAL;
  }
  return result;
}

int wireguard_send_queuing_packets(struct wireguard_peer *peer) {
  gnrc_pktqueue_t *entry;
  gnrc_pktsnip_t *pkt;
  int result = 0;
  while ((entry = gnrc_pktqueue_remove_head(&peer->queue_entry)) != NULL) {
    pkt = entry->pkt;
    /* make the entry NULL so that we re-enqueue the packet in case of no
     * keypair */
    entry->pkt = NULL;
    if ((result = wireguard_send_pkt_to_peer(peer->device, pkt, peer, true)) <
        0) {
      break;
    }
  }
  return result;
}

void wireguard_purge_queuing_packets(struct wireguard_peer *peer) {
  gnrc_pktqueue_t *entry;
  gnrc_pktsnip_t *pkt;
  while ((entry = gnrc_pktqueue_remove_head(&peer->queue_entry)) != NULL) {
    pkt = entry->pkt;
    entry->pkt = NULL;
    gnrc_pktbuf_release(pkt);
  }
}

static gnrc_pktqueue_t *_alloc_queue_entry(gnrc_pktsnip_t *pkt) {
  for (int i = 0; i < MAX_PEERS_PER_DEVICE * 2; ++i) {
    if (queue_pool[i].pkt == NULL) {
      queue_pool[i].pkt = pkt;
      return &queue_pool[i];
    }
  }

  return NULL;
}
