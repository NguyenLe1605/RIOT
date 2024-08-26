#include "time_units.h"
#include "ztimer.h"

#define TIMER_INTERVAL_MSEC (400)

struct wg_peer;

void wg_timers_init(struct wg_peer *peer);
void wg_timers_stop(struct wg_peer *peer);
void wg_timers_data_sent(struct wg_peer *peer);
void wg_timers_data_received(struct wg_peer *peer);
void wg_timers_any_authenticated_packet_sent(struct wg_peer *peer);
void wg_timers_any_authenticated_packet_received(struct wg_peer *peer);
void wg_timers_handshake_initiated(struct wg_peer *peer);
void wg_timers_handshake_complete(struct wg_peer *peer);
void wg_timers_session_derived(struct wg_peer *peer);
void wg_timers_any_authenticated_packet_traversal(struct wg_peer *peer);

static inline bool wg_birthdate_has_expired(uint32_t birthday_milliseconds,
                                            uint32_t expiration_seconds) {
  return (ztimer_now(ZTIMER_MSEC) - birthday_milliseconds) >=
         expiration_seconds * MS_PER_SEC;
}

void wireguard_timer(void *arg);
