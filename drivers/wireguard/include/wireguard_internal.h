
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
 * @brief       Internal implementation of wireguard
 *
 * @{
 *
 * @file
 *
 * @author      Nguyen Le Hoang Dang <lhdnguyen2002@gmail.com>
 */

#ifndef WIREGUARD_INTERNAL_H
#define WIREGUARD_INTERNAL_H

#include "net/gnrc/pkt.h"
#include "wireguard.h"
#include "wireguard_peer.h"
/* Add header includes here */

#ifdef __cplusplus
extern "C" {
#endif

int wireguard_send(wireguard_t *dev, gnrc_pktsnip_t *pkt);
void wireguard_cleanup(wireguard_t *dev);
int wireguard_send_handshake_initiation(struct wireguard_peer *peer);
int wireguard_send_handshake_response(struct wireguard_peer *peer);
uint32_t wireguard_generate_unique_index(wireguard_t *dev);
int wireguard_set_endpoint(sock_udp_ep_t *endpoint, unsigned int iface,
                           sock_udp_ep_t *remote);
int wireguard_send_keepalive(struct wireguard_peer *peer);
#ifdef __cplusplus
}
#endif

#endif /* WIREGUARD_INTERNAL_H */
/** @} */
