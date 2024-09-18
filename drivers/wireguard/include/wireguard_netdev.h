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
 * @file
 * @brief       Netdev driver definitions for wireguard driver
 *
 * @author      Nguyen Le Hoang Dang <lhdnguyen2002@gmail.com>
 */

#ifndef WIREGUARD_NETDEV_H
#define WIREGUARD_NETDEV_H

#include "net/netdev.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Reference to the netdev device driver struct
 */
extern const netdev_driver_t wireguard_driver;

#ifdef __cplusplus
}
#endif

#endif /* WIREGUARD_NETDEV_H */
/** @} */
