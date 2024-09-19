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
 * @brief       Device driver implementation for the wireguard
 *
 * @author      Nguyen Le Hoang Dang <lhdnguyen2002@gmail.com>
 *
 * @}
 */

#include "wireguard.h"
#include "base64.h"
#include "crypto/helper.h"
#include "net/gnrc/ipv6/nib/nc.h"
#include "net/gnrc/netif.h"
#include "net/ipv6/addr.h"
#include "net/netdev.h"
#include "net/sock/async/event.h"
#include "net/sock/udp.h"
#include "wireguard_constants.h"
#include "wireguard_cookie.h"
#include "wireguard_internal.h"
#include "wireguard_netdev.h"
#include "wireguard_noise.h"

#include "net/sock.h"
#include <stdint.h>

static bool wireguard_add_private_key(wireguard_t *dev,
                                      const uint8_t *private_key);

void wireguard_setup(wireguard_t *dev, const wireguard_params_t *params,
                     uint8_t index) {
  memset(dev, 0, sizeof(wireguard_t));
  netdev_t *netdev = (netdev_t *)dev;

  netdev->driver = &wireguard_driver;
  dev->params = (wireguard_params_t *)params;
  netdev_register(&dev->netdev, NETDEV_WIREGUARD, index);
}

int wireguard_init(wireguard_t *dev) {
  /* Initialize peripherals, gpios, setup registers, etc */
  assert(dev);
  int result;
  uint8_t private_key[NOISE_PRIVATE_KEY_LEN];
  size_t private_key_len;
  size_t key_len;
  gnrc_netif_t *iter = NULL;

  wireguard_noise_init();
  wireguard_cookie_checker_init(&dev->cookie_checker, dev);

  key_len = BASE64_PRIVATE_KEY_LEN;
  private_key_len = key_len;
  if (base64_decode(dev->params->private_key, key_len, (void *)private_key,
                    &private_key_len) != BASE64_SUCCESS ||
      private_key_len != NOISE_PRIVATE_KEY_LEN) {
    return -EINVAL;
  }

  if (!wireguard_add_private_key(dev, private_key)) {
    return -EINVAL;
  }
  crypto_secure_wipe(private_key, private_key_len);

  sock_udp_ep_t local_ep;
  dev->netif = dev->netdev.context;
  dev->evq = &dev->netif->evq[GNRC_NETIF_EVQ_INDEX_PRIO_HIGH];
  dev->listen_port = dev->params->listen_port;
  memset(&local_ep, 0, sizeof(local_ep));
  local_ep = (sock_udp_ep_t)SOCK_IPV6_EP_ANY;
  local_ep.port =
      dev->listen_port ? dev->listen_port : WIREGUARD_DEFAULT_UDP_PORT;

  /* find a free netif that is not wireguard or 0, weird behavior cause the
   * udp packet is not sent on ANY_NETIF.*/
  for (iter = gnrc_netif_iter(NULL); iter != NULL;
       iter = gnrc_netif_iter(iter)) {
    if (iter->pid > 0 && iter->pid != dev->netif->pid &&
        iter->device_type != NETDEV_WIREGUARD) {

      local_ep.netif = iter->pid;
      break;
    }
  }

  dev->params = NULL;

  if ((result = sock_udp_create(&dev->udp, &local_ep, NULL, 0)) < 0) {
    wireguard_cleanup(dev);
    return result;
  }
  sock_udp_event_init(&dev->udp, dev->evq, wireguard_recv, dev);

  /* TODO: init the timers */
  return 0;
}

void wireguard_cleanup(wireguard_t *dev) {
  assert(dev);
  /* wiping the private key */
  crypto_secure_wipe(dev->static_identity.static_public, NOISE_PUBLIC_KEY_LEN);
  crypto_secure_wipe(dev->static_identity.static_private,
                     NOISE_PRIVATE_KEY_LEN);
  dev->static_identity.has_identity = false;
}

static bool wireguard_add_private_key(wireguard_t *dev,
                                      const uint8_t *private_key) {

  assert(dev);
  wireguard_noise_set_static_identity_private_key(&dev->static_identity,
                                                  private_key);
  dev->valid = dev->static_identity.has_identity;
  if (!dev->valid) {
    crypto_secure_wipe(dev->static_identity.static_private,
                       NOISE_PRIVATE_KEY_LEN);
  } else {
    wireguard_cookie_checker_precompute_device_keys(&dev->cookie_checker);
  }
  return dev->valid;
}

int wireguard_set_endpoint(sock_udp_ep_t *endpoint, unsigned int iface,
                           sock_udp_ep_t *remote) {

  /* TODO: this whole process of adding neighbor cache is hacky */
  /* register neighbor cache entry to send data out */
  ipv6_addr_t dst;
  memcpy(&dst.u8, endpoint->addr.ipv6, sizeof(ipv6_addr_t));
  gnrc_ipv6_nib_nc_del(&dst, iface);
  memcpy(endpoint, remote, sizeof(sock_udp_ep_t));
  memcpy(&dst.u8, remote->addr.ipv6, sizeof(ipv6_addr_t));
  return gnrc_ipv6_nib_nc_set(&dst, iface, NULL, 0);
}
