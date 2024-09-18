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
 * @brief       Netdev adaptation for the wireguard driver
 *
 * @author      Nguyen Le Hoang Dang <lhdnguyen2002@gmail.com>
 * @}
 */

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>

#include "wireguard.h"
#include "wireguard_constants.h"
#include "wireguard_netdev.h"

#define ENABLE_DEBUG 0
#include "debug.h"

static int _init(netdev_t *netdev) {
  wireguard_t *dev = container_of(netdev, wireguard_t, netdev);

  /* Launch initialization of driver and device */
  DEBUG("[wireguard] netdev: initializing driver...\n");
  if (wireguard_init(dev) != 0) {
    DEBUG("[wireguard] netdev: initialization failed\n");
    return -1;
  }

  DEBUG("[wireguard] netdev: initialization successful\n");
  /* set the link to be up */
  netdev->event_callback(netdev, NETDEV_EVENT_LINK_UP);
  return 0;
}

static int _get_state(wireguard_t *dev, void *val) {
  (void)dev;
  netopt_state_t state = NETOPT_STATE_OFF;
  memcpy(val, &state, sizeof(netopt_state_t));
  return sizeof(netopt_state_t);
}

static int _get(netdev_t *netdev, netopt_t opt, void *value, size_t max_len) {
  wireguard_t *dev = (wireguard_t *)netdev;
  int result = -ENOTSUP;

  if (dev == NULL) {
    return -ENODEV;
  }

  switch (opt) {
  case NETOPT_STATE:
    assert(max_len >= sizeof(netopt_state_t));
    return _get_state(dev, value);
  case NETOPT_MAX_PDU_SIZE:
    assert(max_len >= sizeof(uint16_t));
    *((uint16_t *)value) = WIREGUARD_NETIF_MTU;
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

static int _set_state(wireguard_t *dev, netopt_state_t state) {
  (void)dev;
  switch (state) {
  case NETOPT_STATE_STANDBY:
    DEBUG("[wireguard] netdev: set NETOPT_STATE_STANDBY state\n");
    break;

  case NETOPT_STATE_IDLE:
    DEBUG("[wireguard] netdev: set NETOPT_STATE_RX state\n");
    break;

  case NETOPT_STATE_RX:
    DEBUG("[wireguard] netdev: set NETOPT_STATE_RX state\n");
    break;

  case NETOPT_STATE_TX:
    DEBUG("[wireguard] netdev: set NETOPT_STATE_TX state\n");
    break;

  case NETOPT_STATE_RESET:
    DEBUG("[wireguard] netdev: set NETOPT_STATE_RESET state\n");
    break;

  default:
    return -ENOTSUP;
  }
  return sizeof(netopt_state_t);
}

static int _set(netdev_t *netdev, netopt_t opt, const void *val, size_t len) {
  (void)len; /* unused when compiled without debug, assert empty */
  wireguard_t *dev = (wireguard_t *)netdev;
  int res = -ENOTSUP;

  if (dev == NULL) {
    return -ENODEV;
  }

  switch (opt) {
  case NETOPT_STATE:
    assert(len == sizeof(netopt_state_t));
    return _set_state(dev, *((const netopt_state_t *)val));

  default:
    break;
  }

  return res;
}

const netdev_driver_t wireguard_driver = {
    .send = NULL,
    .recv = NULL,
    .init = _init,
    .isr = NULL,
    .get = _get,
    .set = _set,
};
