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
#include "ztimer.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

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
