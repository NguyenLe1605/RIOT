/*
 * Copyright (C) 2024 NguyenLe1605
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       An example on how to use wireguard
 *
 * @author      Nguyen Le Hoang Dang <lhdnguyen2002@gmail.com>
 *
 * @}
 */

#include "container.h"
#include "gnrc_netif_wireguard.h"
#include "net/gnrc/netif.h"
#include "net/ipv6/addr.h"
#include "net/sock.h"
#include "net/sock/udp.h"
#include "wireguard.h"
#include "wireguard_constants.h"
#include "ztimer.h"
#include <stdio.h>

static char wg_netif_stack[WIREGUARD_NETIF_STACKSIZE];
static gnrc_netif_t wg_netif;
static wireguard_t wg_dev;

int main(void) {
  int res;
  sock_udp_t sock;
  sock_udp_ep_t remote;
  uint8_t peer_idx;
  wireguard_params_t param = {
      .listen_port = 0,
      .private_key = "yOvAL8A5/kEEMoTC7ZSrJejUETQgIUS6f5DIt7amMW0=",
  };
  wireguard_setup(&wg_dev, &param, 0);
  gnrc_netif_t *bind_netif = gnrc_netif_get_by_pid(5);
  assert(bind_netif);
  ipv6_addr_t bind_addr = (ipv6_addr_t){
      {0x20, 0x01, 0x0d, 0xb8, 0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
  res = gnrc_netif_ipv6_addr_add(bind_netif, &bind_addr, 64, 0);
  assert(res >= 0);
  res = gnrc_netif_wireguard_create(
      &wg_netif, wg_netif_stack, sizeof(wg_netif_stack), WIREGUARD_NETIF_PRIO,
      "wg_netif", &wg_dev.netdev);
  (void)res;

  ipv6_addr_t addr =
      (ipv6_addr_t){{0xfd, 00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}};
  res = gnrc_netif_wireguard_add_ipv6_addr(&wg_netif, &addr, 8);

  wireguard_netif_peer_t peer;
  gnrc_netif_wireguard_peer_init(&peer);
  wireguard_netif_allowed_ip_t allowed_ips[] = {
      {.addr = {{0xfd, 00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
       .pfx_len = 128}};
  peer.public_key = "hU13oEYGMDx6efqyUt8MpSNFF/ROpRxiYVvtdF0ijFE=";
  peer.preshared_key = NULL;
  peer.allowed_ips = allowed_ips;
  peer.allowed_ips_len = ARRAY_SIZE(allowed_ips);
  peer.endpoint = (sock_udp_ep_t){
      .port = WIREGUARD_DEFAULT_UDP_PORT,
      .family = AF_INET6,
      .addr.ipv6 = {0x20, 0x01, 0x0d, 0xb8, 0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    2},
  };
  peer.persistent_keepalive = 0;
  res = gnrc_netif_wireguard_add_peer(&wg_netif, &peer, &peer_idx);
  assert(res >= 0);
  assert(wg_dev.peers[peer_idx].valid);
  assert(peer_idx != WIREGUARD_INVALID_INDEX);

  // res = gnrc_netif_wireguard_connect(&wg_netif, peer_idx);
  // assert(res >= 0);

  sock_udp_ep_t server = {
      .port = 12345,
      .family = AF_INET6,
      // .netif = wg_netif.pid,
      .addr = {{0xfd, 00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}},
  };

  remote = (sock_udp_ep_t){
      .port = 12345,
      .family = AF_INET6,
      .netif = wg_netif.pid,
      .addr.ipv6 = {0xfd, 00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};

  // ztimer_sleep(ZTIMER_MSEC, 3000);
  if (sock_udp_create(&sock, &server, NULL, 0) < 0) {
    printf("can not create sock\n");
    return 0;
  }

  if (sock_udp_send(&sock, "hello\n", sizeof("hello\n"), &remote) < 0) {
    printf("could not send\n");
    return -1;
  }
  uint8_t buf[64];
  memset(buf, 0, sizeof(buf));
  if (sock_udp_recv(&sock, buf, sizeof(buf), SOCK_NO_TIMEOUT, &remote) < 0) {
    printf("could not receive\n");
    return -1;
  }
  printf("%s\n", buf);

  puts("Generated RIOT application: 'wireguard_example'");
  return 0;
}
