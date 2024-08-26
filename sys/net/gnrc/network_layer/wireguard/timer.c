#include "net/wireguard/timer.h"
#include "net/netdev.h"
#include "net/sock/udp.h"
#include "net/wireguard/device.h"
#include "net/wireguard/messages.h"
#include "net/wireguard/noise.h"
#include "net/wireguard/peer.h"

static bool should_reset_peer(struct wg_peer *peer) {
  struct noise_keypair *keypair = &peer->keypairs.current_keypair;
  return keypair->valid &&
         wg_birthdate_has_expired(keypair->birthdate, REJECT_AFTER_TIME * 3);
}

static bool should_destroy_current_keypair(struct wg_peer *peer) {
  struct noise_keypair *keypair = &peer->keypairs.current_keypair;
  return keypair->valid &&
         (wg_birthdate_has_expired(keypair->birthdate, REJECT_AFTER_TIME) ||
          keypair->sending_counter >= REJECT_AFTER_MESSAGES);
}

static bool should_send_keepalive(struct wg_peer *peer) {
  return (peer->keepalive_interval > 0) &&
         ((peer->keypairs.current_keypair.valid) ||
          peer->keypairs.previous_keypair.valid) &&
         wg_birthdate_has_expired(peer->last_tx, peer->keepalive_interval);
}

static bool should_send_initiation(struct wg_peer *peer) {
  struct noise_keypair *keypair = &peer->keypairs.current_keypair;
  return (peer->last_initiation_tx == 0 || /* first time sending init*/
          wg_birthdate_has_expired(
              peer->last_initiation_tx,
              REKEY_TIMEOUT)) && /* retry sending handshake */
         (peer->send_handshake ||
          /* start new session after responder receives transport data, and the
             REJECT_AFTER_TIME dead line is sooner than the keepalive timeout */
          (keypair->valid && !keypair->initiator &&
           wg_birthdate_has_expired(keypair->birthdate,
                                    REJECT_AFTER_TIME -
                                        peer->keepalive_interval)) ||
          /* the first handshake initiation */
          (!keypair->valid && peer->active));
}

void wireguard_timer(void *arg) {
  wireguard_t *wg = (wireguard_t *)arg;
  int i;
  struct wg_peer *peer;
  bool link_up = false;
  ztimer_set(ZTIMER_MSEC, &wg->timer, TIMER_INTERVAL_MSEC);
  for (i = 0; i < MAX_PEERS_PER_DEVICE; ++i) {
    peer = &wg->peers[i];
    if (!peer->valid)
      continue;

    if (should_reset_peer(peer)) {
      wg_noise_keypairs_clear(&peer->keypairs);
      wg_noise_handshake_clear(&peer->handshake);
      /* Revert to configure endpoint if these was altered */
      memcpy(&peer->latest_endpoint, &peer->endpoint, sizeof(sock_udp_ep_t));
    }

    if (should_destroy_current_keypair(peer)) {
      wg_noise_destroy_keypair(&peer->keypairs.current_keypair);
    }

    if (should_send_keepalive(peer)) {
      wireguard_send_keepalive(peer);
    }

    if (should_send_initiation(peer)) {
      wireguard_send_handshake_initiation(peer);
    }

    if (peer->keypairs.current_keypair.valid ||
        peer->keypairs.previous_keypair.valid) {
      link_up = true;
    }
  }

  if (!link_up) {
    wg->netdev.event_callback(&wg->netdev, NETDEV_EVENT_LINK_DOWN);
  }
}
