/*
 * Copyright (C) 2024 NguyenLe1605
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    drivers_wireguard wireguard
 * @ingroup     drivers_netdev
 * @brief       An implementation of wireguard for RIOT
 *
 * @{
 *
 * @file
 *
 * @author      Nguyen Le Hoang Dang <lhdnguyen2002@gmail.com>
 */

#ifndef WIREGUARD_H
#define WIREGUARD_H

#include "net/gnrc/netif.h"
#include "net/netdev.h"
#include "net/sock/udp.h"
#include "wireguard_constants.h"
#include "wireguard_cookie.h"
#include "wireguard_noise.h"
#include "wireguard_peer.h"
/* Add header includes here */

#ifdef __cplusplus
extern "C" {
#endif

/* Declare the API of the driver */

/**
 * @brief   Device initialization parameters
 */
typedef struct {
  /* udp listen port */
  uint16_t listen_port;
  /* base64-encoded private key */
  const char *private_key;
} wireguard_params_t;

/**
 * @brief   Device descriptor for the driver
 */
typedef struct wireguard_device {
  netdev_t netdev; /**< Netdev parent struct */
  /** Device initialization parameters */
  wireguard_params_t *params;
  /* listening udp port */
  uint16_t listen_port;
  /* udp socket to send/recv data */
  sock_udp_t udp;
  /* network interface to dispatch IPv6 packet to device */
  gnrc_netif_t *netif;
  /* event queue for packet receiving event */
  event_queue_t *evq;
  /* static private keypairs binding to the device  */
  struct noise_static_identity static_identity;
  struct wireguard_peer peers[MAX_PEERS_PER_DEVICE];
  struct cookie_checker cookie_checker;
  /* invalid when the configured private key is not valid*/
  bool valid;
} wireguard_t;

/**
 * @brief   Setup the radio device
 *
 * @param[in] dev                       Device descriptor
 * @param[in] params                    Parameters for device initialization
 * @param[in] index                     Index of @p params in a global parameter
 * struct array. If initialized manually, pass a unique identifier instead.
 */
void wireguard_setup(wireguard_t *dev, const wireguard_params_t *params,
                     uint8_t index);

/**
 * @brief   Initialize the given device
 *
 * @param[inout] dev                    Device descriptor of the driver
 *
 * @return                  0 on success
 */
int wireguard_init(wireguard_t *dev);

#ifdef __cplusplus
}
#endif

#endif /* WIREGUARD_H */
/** @} */
