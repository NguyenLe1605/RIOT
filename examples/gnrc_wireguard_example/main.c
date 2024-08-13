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

#include "base64.h"
#include "msg.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netif/ipv6.h"
#include "net/ipv6/addr.h"
#include "net/netif.h"
#include "net/sock.h"
#include "net/sock/udp.h"
#include "net/wireguard.h"
#include "net/wireguard/device.h"
#include "net/wireguard/messages.h"
#include "shell.h"
#include "ztimer.h"
#include <stdio.h>

static char buffer[64];
static msg_t queue[8];
#define MAIN_QUEUE_SIZE (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];
static uint8_t privkey[NOISE_PRIVATE_KEY_LEN] = {0};
static sock_udp_t sock;
static sock_udp_ep_t remote = {.port = 12345,
                               .family = AF_INET6,
                               .addr.ipv6 = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x84,
                                             0x2b, 0x16, 0xff, 0xfe, 0x72, 0xa8,
                                             0x40}};

int usend(int argc, char **argv) {
  (void)argc;
  (void)argv;
  int res = 0;
  if (sock_udp_send(&sock, "fuck u", sizeof("fuck u"), &remote) < 0) {
    return -1;
  }
  if ((res = sock_udp_recv(&sock, buffer, sizeof(buffer) - 1, SOCK_NO_TIMEOUT,
                           &remote)) < 0) {
    puts("Error while receiving");
  }
  printf("Received message: \"");
  for (int i = 0; i < res; i++) {
    printf("%c", buffer[i]);
  }
  return res;
}

static const shell_command_t shell_commands[] = {
    {"udpse", "send udp packets", usend}, {NULL, NULL, NULL}};

int main(void) {
  puts("Generated RIOT application: 'gnrc_wireguard_example'");

  (void)remote;
  (void)buffer;
  (void)queue;
  char key[] = "8BU1giso23adjCk93dnpLJnK788bRAtpZxs8d+Jo+Vg=";
  size_t len = sizeof(key);
  int res;

  if (base64_decode(key, sizeof(key), (void *)privkey, &len) !=
          BASE64_SUCCESS ||
      len != NOISE_PRIVATE_KEY_LEN) {
    printf("fuck, len: %d\n", len);
    return 0;
  }

  printf("yay, len: %d\n", len);
  wireguard_params_t param = {
      .bind_netif = 5, .listen_port = 51515, .privkey = privkey};
  gnrc_netif_t *netif = gnrc_netif_wireguard_create(&param);

  // ipv6_addr_t addr =
  //     (ipv6_addr_t){{32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}};
  // res = gnrc_netif_ipv6_addr_add(netif, &addr, 32,
  //                                GNRC_NETIF_IPV6_ADDRS_FLAGS_STATE_VALID);
  res = 0;
  assert(res >= 0);
  assert(netif != NULL);
  sock_udp_ep_t server = {
      .port = 12345,
      .family = AF_INET6,
      .netif = netif->pid,
  };

  if (sock_udp_create(&sock, &server, NULL, 0) < 0) {
    return 0;
  }
  /* start shell */
  msg_init_queue(_main_msg_queue, 8);
  puts("All up, running the shell now");
  char line_buf[SHELL_DEFAULT_BUFSIZE];
  shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

  // while (1) {
  //   // int res;
  //   ztimer_sleep(ZTIMER_SEC, 1);
  //   if (sock_udp_send(&sock, "fuck u", sizeof("fuck u"), &remote) < 0) {
  //     break;
  //   }
  //   // if ((res = sock_udp_recv(&sock, buffer, sizeof(buffer) - 1,
  //   // SOCK_NO_TIMEOUT,
  //   //                          &remote)) < 0) {
  //   //   puts("Error while receiving");
  //   // } else if (res == 0) {
  //   //   puts("No data received");
  //   // } else {
  //   //   buffer[res] = '\0';
  //   //   printf("Recvd: %s\n", buffer);
  //   // }
  // }

  printf("end of main\n");
  return 0;
}
