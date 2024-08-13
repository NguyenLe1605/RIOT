#include "time_units.h"
#include "ztimer.h"

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

static inline bool wg_birthdate_has_expired(uint64_t birthday_microseconds,
                                            uint64_t expiration_seconds) {
  return (int64_t)(birthday_microseconds + expiration_seconds * US_PER_SEC) <=
         (int64_t)ztimer_now(ZTIMER_USEC);
}
