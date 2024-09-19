#include "container.h"
#include "net/sock/async/types.h"
#include "net/sock/udp.h"
#include "wireguard.h"
#include "wireguard_constants.h"
#include "wireguard_cookie.h"
#include "wireguard_internal.h"
#include "wireguard_noise.h"
#include "wireguard_timer.h"

#define ENABLE_DEBUG 1
#include "debug.h"

#define REPLAY_WINDOW_SIZE (32)

static void wireguard_receive_handshake_packet(wireguard_t *wg, uint8_t *buf,
                                               size_t len,
                                               sock_udp_ep_t *remote,
                                               uint32_t type);
static uint32_t wireguard_get_message_type(const uint8_t *buf, size_t len);
static void wireguard_consume_data(struct wireguard_peer *peer,
                                   struct message_transport_data *data,
                                   size_t len, sock_udp_ep_t *remote);
static void wireguard_dispatch_ipv6_pkt(wireguard_t *wg, uint8_t *buf,
                                        size_t len);
static bool wireguard_anti_replay(struct noise_keypair *keypair, uint64_t seq);
static void keep_key_fresh(struct wireguard_peer *peer);

static struct noise_keypair *
get_peer_keypair_for_idx(struct wireguard_peer *peer, uint32_t idx);
static void wireguard_sched_send_queue_event(struct wireguard_peer *peer);
static void wireguard_send_queue_handler(event_t *evt);

void wireguard_recv(sock_udp_t *sock, sock_async_flags_t flags, void *args) {
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
  if (!keypair) {
    return;
  }

  if (!keypair->receiving.valid ||
      wireguard_expired_birthdate(keypair->birthdate, REJECT_AFTER_TIME) ||
      keypair->receiving_counter.last_seq >= REJECT_AFTER_MESSAGES) {
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

  /* WARN: handle it safely */
  if (wireguard_set_endpoint(&peer->latest_endpoint, peer->device->netif->pid,
                             remote) < 0) {
    DEBUG("[wireguard] receive: set endpoint failed\n");
  }

  if (wireguard_noise_received_with_keypair(&peer->keypairs, keypair)) {
    wireguard_timers_handshake_completed(peer);
    if (peer->queue_entry != NULL) {
      wireguard_sched_send_queue_event(peer);
    }
  }

  keep_key_fresh(peer);

  wireguard_timers_any_authenticated_packet_received(peer);
  wireguard_timers_any_authenticated_packet_traversal(peer);

  /* keep alive packet */
  if (msg_len == 0) {
    DEBUG("[wireguard] receive: keepalive packet\n");
    return;
  }

  wireguard_timers_data_received(peer);

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
    /* WARN: this add to the neighbor cache, which is hacky for now */
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
      wireguard_timers_session_derived(peer);
      wireguard_timers_handshake_completed(peer);
      /* WARN: this add to the neighbor cache to work, change this later on */
      if (wireguard_set_endpoint(&peer->latest_endpoint, wg->netif->pid,
                                 remote) < 0) {
        DEBUG("[wireguard] receive: can not set latest endpoint\n");
      }
      /* sending keepalive to confirm the session or sending packets on the
       * queue */
      wireguard_send_keepalive(peer);
    }
    break;
  }
  }

  wireguard_timers_any_authenticated_packet_received(peer);
  wireguard_timers_any_authenticated_packet_traversal(peer);
}

static void keep_key_fresh(struct wireguard_peer *peer) {
  struct noise_keypair *keypair;
  bool send;

  if (peer->sent_lastminute_handshake) {
    return;
  }

  /* TODO: concurrency protection? */
  keypair = &peer->keypairs.current_keypair;
  send = keypair->valid && keypair->sending.valid && keypair->initiator &&
         wireguard_expired_birthdate(keypair->sending.birthdate,
                                     REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT -
                                         REKEY_TIMEOUT);

  if (send) {
    peer->sent_lastminute_handshake = true;
    wireguard_sched_handshake_init(peer, false);
  }
}

static void wireguard_send_queue_handler(event_t *evt) {
  peer_event_t *queue_evt = container_of(evt, peer_event_t, super);
  wireguard_send_queuing_packets(queue_evt->peer);
}
static void wireguard_sched_send_queue_event(struct wireguard_peer *peer) {
  peer->send_queue_evt = (peer_event_t){
      .super.handler = wireguard_send_queue_handler, .peer = peer};
  event_post(peer->device->evq, &peer->send_queue_evt.super);
}
