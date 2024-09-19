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
 * @brief       Implementation for timer state machine for wireguard
 *
 * @author      Nguyen Le Hoang Dang <lhdnguyen2002@gmail.com>
 */

#ifndef WIREGUARD_TIMER_H
#define WIREGUARD_TIMER_H

#include "time_units.h"
#include "wireguard_peer.h"
#include "ztimer.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void wireguard_timers_init(struct wireguard_peer *peer);
void wireguard_timers_stop(struct wireguard_peer *peer);
void wireguard_timers_data_received(struct wireguard_peer *peer);
void wireguard_timers_any_authenticated_packet_sent(
    struct wireguard_peer *peer);
void wireguard_timers_any_authenticated_packet_traversal(
    struct wireguard_peer *peer);
void wireguard_timers_session_derived(struct wireguard_peer *peer);
void wireguard_timers_handshake_completed(struct wireguard_peer *peer);
void wireguard_timers_handshake_initiated(struct wireguard_peer *peer);
void wireguard_timers_data_sent(struct wireguard_peer *peer);
void wireguard_timers_any_authenticated_packet_received(
    struct wireguard_peer *peer);
static inline bool wireguard_expired_birthdate(uint32_t birthday_milliseconds,
                                               uint32_t expiration_seconds) {
  return (ztimer_now(ZTIMER_MSEC) - birthday_milliseconds) >=
         expiration_seconds * MS_PER_SEC;
}

#ifdef __cplusplus
}
#endif

#endif /* WIREGUARD_COOKIE_H */
/** @} */
