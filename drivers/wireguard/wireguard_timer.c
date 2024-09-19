#include "wireguard_timer.h"
#include "event.h"
#include "event/timeout.h"
#include "random.h"
#include "time_units.h"
#include "wireguard.h"
#include "wireguard_constants.h"
#include "wireguard_internal.h"
#include "wireguard_noise.h"
#include "ztimer.h"

static inline void mod_peer_timer(struct wireguard_peer *peer,
                                  event_timeout_t *timer, uint32_t expires) {
  /* TODO: add check when netif is still running */
  if (peer->valid) {
    event_timeout_set(timer, expires);
  }
}

static void wireguard_expired_retransmit_handshake(event_t *ev) {
  struct wireguard_peer *peer =
      container_of(ev, struct wireguard_peer, send_keepalive_event);
  if (peer->handshake_attempts > MAX_TIMER_HANDSHAKES) {
    event_timeout_clear(&peer->send_keepalive_timeout);

    /* drop all packet without a keypair and don't try again */
    wireguard_purge_queuing_packets(peer);

    /* set timer for any partial handshake exchange */
    if (!event_timeout_is_pending(&peer->zero_out_keypairs_timeout)) {
      mod_peer_timer(peer, &peer->zero_out_keypairs_timeout,
                     REJECT_AFTER_TIME * 3 * MS_PER_SEC);
    }
  } else {
    ++peer->handshake_attempts;
    wireguard_sched_handshake_init(peer, true);
  }
}

static void wireguard_expired_send_keepalive(event_t *ev) {
  struct wireguard_peer *peer =
      container_of(ev, struct wireguard_peer, send_keepalive_event);

  wireguard_send_keepalive(peer);
  if (peer->timer_need_another_keepalive) {
    peer->timer_need_another_keepalive = false;
    mod_peer_timer(peer, &peer->send_keepalive_timeout,
                   KEEPALIVE_TIMEOUT * MS_PER_SEC);
  }
}

static void wireguard_expired_send_persistent_keepalive(event_t *ev) {
  struct wireguard_peer *peer =
      container_of(ev, struct wireguard_peer, persistent_keepalive_event);

  if (peer->persistent_keepalive_interval)
    wireguard_send_keepalive(peer);
}

static void wireguard_expired_zero_out_keypairs(event_t *ev) {
  struct wireguard_peer *peer =
      container_of(ev, struct wireguard_peer, persistent_keepalive_event);
  wireguard_noise_handshake_clear(&peer->handshake);
  wireguard_noise_keypairs_clear(&peer->keypairs);
}

static void wireguard_expired_new_handshake(event_t *ev) {

  struct wireguard_peer *peer =
      container_of(ev, struct wireguard_peer, new_handshake_event);

  wireguard_sched_handshake_init(peer, false);
}

/* Should be called after any type of authenticated packet is sent, whether
 * keepalive, data, or handshake.
 */
void wireguard_timers_data_received(struct wireguard_peer *peer) {
  /* TODO: add checking the running state of the netif? */
  if (!event_timeout_is_pending(&peer->send_keepalive_timeout)) {
    mod_peer_timer(peer, &peer->send_keepalive_timeout,
                   KEEPALIVE_TIMEOUT * MS_PER_SEC);
  } else {
    peer->timer_need_another_keepalive = true;
  }
}

/* Should be called after an authenticated data packet is sent. */
void wireguard_timers_data_sent(struct wireguard_peer *peer) {
  if (!event_timeout_is_pending(&peer->new_handshake_timeout)) {
    mod_peer_timer(peer, &peer->new_handshake_timeout,
                   (KEEPALIVE_TIMEOUT + REKEY_TIMEOUT) * MS_PER_SEC +
                       random_uint32_range(0, REKEY_TIMEOUT_JITTER_MAX_MS));
  }
}

/* Should be called after any type of authenticated packet is sent, whether
 * keepalive, data, or handshake.
 */
void wireguard_timers_any_authenticated_packet_sent(
    struct wireguard_peer *peer) {
  event_timeout_clear(&peer->send_keepalive_timeout);
}

/* Should be called after any type of authenticated packet is sent, whether
 * keepalive, data, or handshake.
 */
void wireguard_timers_any_authenticated_packet_received(
    struct wireguard_peer *peer) {
  event_timeout_clear(&peer->new_handshake_timeout);
}

/* Should be called before a packet with authentication, whether
 * keepalive, data, or handshakem is sent, or after one is received.
 */
void wireguard_timers_any_authenticated_packet_traversal(
    struct wireguard_peer *peer) {
  if (peer->persistent_keepalive_interval) {
    mod_peer_timer(peer, &peer->persistent_keepalive_timeout,
                   KEEPALIVE_TIMEOUT * MS_PER_SEC);
  }
}

/* Should be called after a handshake response message is received and processed
 * or when getting key confirmation via the first data message.
 */
void wireguard_timers_handshake_completed(struct wireguard_peer *peer) {
  event_timeout_clear(&peer->retransmit_handshake_timeout);
  peer->handshake_attempts = 0;
  peer->sent_lastminute_handshake = false;
}

/* Should be called after a handshake initiation message is sent. */
void wireguard_timers_handshake_initiated(struct wireguard_peer *peer) {
  mod_peer_timer(peer, &peer->retransmit_handshake_timeout,
                 REKEY_TIMEOUT * MS_PER_SEC +
                     random_uint32_range(0, REKEY_TIMEOUT_JITTER_MAX_MS));
}

/* Should be called after an ephemeral key is created, which is before sending a
 * handshake response or after receiving a handshake response.
 */
void wireguard_timers_session_derived(struct wireguard_peer *peer) {
  mod_peer_timer(peer, &peer->zero_out_keypairs_timeout,
                 REJECT_AFTER_TIME * 3 * MS_PER_SEC);
}

void wireguard_timers_init(struct wireguard_peer *peer) {
  event_queue_t *evq = peer->device->evq;

  peer->retransmit_handshake_event.handler =
      wireguard_expired_retransmit_handshake;
  event_timeout_ztimer_init(&peer->retransmit_handshake_timeout, ZTIMER_MSEC,
                            evq, &peer->retransmit_handshake_event);

  peer->send_keepalive_event.handler = wireguard_expired_send_keepalive;
  event_timeout_ztimer_init(&peer->send_keepalive_timeout, ZTIMER_MSEC, evq,
                            &peer->send_keepalive_event);

  peer->persistent_keepalive_event.handler =
      wireguard_expired_send_persistent_keepalive;
  event_timeout_ztimer_init(&peer->persistent_keepalive_timeout, ZTIMER_MSEC,
                            evq, &peer->persistent_keepalive_event);

  peer->zero_out_keypairs_event.handler = wireguard_expired_zero_out_keypairs;
  event_timeout_ztimer_init(&peer->zero_out_keypairs_timeout, ZTIMER_MSEC, evq,
                            &peer->zero_out_keypairs_event);

  peer->new_handshake_event.handler = wireguard_expired_new_handshake;
  event_timeout_ztimer_init(&peer->new_handshake_timeout, ZTIMER_MSEC, evq,
                            &peer->new_handshake_event);

  peer->handshake_attempts = 0;
  peer->sent_lastminute_handshake = false;
  peer->timer_need_another_keepalive = false;
}

void wireguard_timers_stop(struct wireguard_peer *peer) { (void)peer; }
