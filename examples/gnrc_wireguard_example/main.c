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
 * @brief       Example for wireguard interface
 *
 * @author      NguyenLe1605 <lhdnguyen2002@gmail.com>
 *
 * @}
 */

#include "container.h"
#include "msg.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netif/conf.h"
#include "net/ipv6/addr.h"
#include "net/sock.h"
#include "net/sock/udp.h"
#include "net/wireguard.h"
#include "net/wireguard/device.h"
#include "net/wireguard/peer.h"
#include "shell.h"
#include "tiny_strerror.h"
#include <stdio.h>

static char buffer[64];
static msg_t queue[8];
#define MAIN_QUEUE_SIZE (8)
// static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

static char wg_netif_stack[THREAD_STACKSIZE_DEFAULT];
static gnrc_netif_t wg_netif;
static wireguard_t wg_dev;

static sock_udp_t sock;
static sock_udp_ep_t remote = {.port = 12345,
                               .family = AF_INET6,
                               .addr.ipv6 = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x34,
                                             0x64, 0x5f, 0xe1, 0x69, 0xf4, 0x93,
                                             0xd7}};

// int usend(int argc, char **argv) {
//   (void)argc;
//   (void)argv;
//   int res = 0;
//   if ((res = sock_udp_recv(&server, buffer, sizeof(buffer) - 1,
//   SOCK_NO_TIMEOUT,
//                            &remote)) < 0) {
//     puts("Error while receiving");
//   }
//   printf("Received message: \"");
//   for (int i = 0; i < res; i++) {
//     printf("%c", buffer[i]);
//   }
//   return res;
// }

// static const shell_command_t shell_commands[] = {
//     {"udpse", "send udp packets", usend}, {NULL, NULL, NULL}};

int main(void) {
  puts("Generated RIOT application: 'gnrc_wireguard_example'");

  (void)remote;
  (void)buffer;
  (void)queue;
  uint8_t key[] = "yOvAL8A5/kEEMoTC7ZSrJejUETQgIUS6f5DIt7amMW0=";
  int res;
  uint8_t peer_idx = WIREGUARD_INVALID_INDEX;
  /* set up the wireguard device and network interface */
  wireguard_params_t param = {
      .bind_netif = 5, .listen_port = 51280, .private_key = key};
  wireguard_setup(&wg_dev, &param);
  res = gnrc_netif_wireguard_create(&wg_netif, wg_netif_stack,
                                    sizeof(wg_netif_stack), GNRC_NETIF_PRIO,
                                    "wg_netif", &wg_dev.netdev);
  assert(wg_dev.valid);

  ipv6_addr_t addr =
      (ipv6_addr_t){{0xfd, 00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}};
  res = gnrc_netif_wireguard_add_ipv6_addr(&wg_netif, &addr, 32);

  wireguard_netif_peer_t peer;
  gnrc_netif_wireguard_peer_init(&peer);
  peer.public_key = "hU13oEYGMDx6efqyUt8MpSNFF/ROpRxiYVvtdF0ijFE=";
  peer.public_key_len = strlen(peer.public_key);
  peer.preshared_key = NULL;
  peer.preshared_key = NULL;
  peer.allowed_ip = (ipv6_addr_t){{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x34, 0x64,
                                   0x5f, 0xe1, 0x69, 0xf4, 0x93, 0xd7}};

  peer.pfx_len = 128;
  peer.remote = (sock_udp_ep_t){
      .port = 51280,
      .family = AF_INET6,
      .addr.ipv6 = {0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc0, 0x6c, 0x35,
                    0xff, 0xfe, 0x27, 0xf2, 0xd2},
      .netif = 5,
  };

  res = gnrc_netif_wireguard_add_peer(&wg_netif, &peer, &peer_idx);
  if (res < 0) {
    puts(tiny_strerror(res));
  }
  assert(res >= 0);
  assert(wg_dev.peers[peer_idx].valid);
  assert(peer_idx != WIREGUARD_INVALID_INDEX);

  res = gnrc_netif_wireguard_connect(&wg_netif, peer_idx);
  assert(res >= 0);
  // assert(memcpy(&p->latest_endpoint, &p->endpoint, sizeof(sock_udp_ep_t)));

  res = gnrc_netif_wireguard_peer_is_up(&wg_netif, peer_idx, NULL, NULL);
  assert(res < 0);

  sock_udp_ep_t server = {
      .port = 12345,
      .family = AF_INET6,
      // .netif = wg_netif.pid,
      .addr = {{0xfd, 00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}},
  };

  if (sock_udp_create(&sock, &server, NULL, 0) < 0) {
    printf("can not create sock\n");
    return 0;
  }
  if (sock_udp_send(&sock, "fuck u", sizeof("fuck u"), &remote) < 0) {
    return -1;
  }
  /* start shell */
  // msg_init_queue(_main_msg_queue, 8);
  // puts("All up, running the shell now");
  // char line_buf[SHELL_DEFAULT_BUFSIZE];
  // shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

  printf("end of main\n");
  return 0;
}
