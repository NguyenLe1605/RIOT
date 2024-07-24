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
 * @brief       ev
 *
 * @author      NguyenLe1605 <lhdnguyen2002@gmail.com>
 *
 * @}
 */

#include "assert.h"
#include "cpu_conf.h"
#include "event.h"
#include "event/callback.h"
#include "event/periodic_callback.h"
#include "msg.h"
#include "mutex.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netif/conf.h"
#include "net/gnrc/netif/hdr.h"
#include "net/gnrc/netreg.h"
#include "net/gnrc/nettype.h"
#include "net/gnrc/pktbuf.h"
#include "net/ipv6/addr.h"
#include "net/netdev.h"
#include "net/sock.h"
#include "net/sock/async/event.h"
#include "net/sock/async/types.h"
#include "net/sock/udp.h"
#include "sched.h"
#include "shell.h"
#include "thread.h"
#include "thread_config.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ENABLE_DEBUG 1
#include "debug.h"

#define MAIN_QUEUE_SIZE (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

#ifdef MODULE_GNRC_SIXLOWPAN
#define NETTYPE GNRC_NETTYPE_SIXLOWPAN
#elif defined(MODULE_GNRC_IPV6)
#define NETTYPE GNRC_NETTYPE_IPV6
#else
#define NETTYPE GNRC_NETTYPE_UNDEF
#endif

static kernel_pid_t _pid = KERNEL_PID_UNDEF;
static char _msg_stack[THREAD_STACKSIZE_DEFAULT];
static event_queue_t _queue;
static sock_udp_t _sock_udp;
static sock_udp_ep_t remote;
static mutex_t _tunnel_mtx;
static kernel_pid_t _send_pid = KERNEL_PID_UNDEF;
kernel_pid_t _netif_pid = KERNEL_PID_UNDEF;

/* define the netif */
static char _snd_stack[THREAD_STACKSIZE_DEFAULT];

static char _stack[THREAD_STACKSIZE_DEFAULT];

static gnrc_netif_t _netif;
static gnrc_nettype_t _nettype = NETTYPE;
static thread_t *_netif_thread;

static void *_event_loop(void *arg);
static void _on_sock_udp_evt(sock_udp_t *sock, sock_async_flags_t type,
                             void *arg);
static void *_send_udp_loop(void *arg);
static int _netif_init(gnrc_netif_t *netif);
static int _netif_send(gnrc_netif_t *netif, gnrc_pktsnip_t *pkt);
static gnrc_pktsnip_t *_netif_recv(gnrc_netif_t *netif);
static void send(void *arg);
static event_callback_t cb = EVENT_CALLBACK_INIT(send, &remote);

static const gnrc_netif_ops_t _ops = {
    .init = _netif_init,
    .send = _netif_send,
    .recv = _netif_recv,
    .get = gnrc_netif_get_from_netdev,
    .set = gnrc_netif_set_from_netdev,
    .msg_handler = NULL,
};

static inline int _netdev_init(netdev_t *dev) {
  (void)dev;

  char addr[] = "02:42:a2:40:90:9c";
  uint8_t out[GNRC_NETIF_L2ADDR_MAXLEN];
  int res = gnrc_netif_addr_from_str(addr, out);
  assert(res > 0);
  memcpy(_netif.l2addr, out, res);
  /* signal link UP */
  dev->event_callback(dev, NETDEV_EVENT_LINK_UP);

  return 0;
}

static inline int _netdev_get(netdev_t *dev, netopt_t opt, void *value,
                              size_t max_len) {
  (void)dev;
  int res = -ENOTSUP;

  switch (opt) {
  case NETOPT_ADDRESS:
    assert(max_len >= GNRC_NETIF_L2ADDR_MAXLEN);
    memcpy(value, _netif.l2addr, GNRC_NETIF_L2ADDR_MAXLEN);
    res = GNRC_NETIF_L2ADDR_MAXLEN;
    break;
  case NETOPT_ADDR_LEN:
  case NETOPT_SRC_LEN:
    assert(max_len == sizeof(uint16_t));
    *((uint16_t *)value) = GNRC_NETIF_L2ADDR_MAXLEN;
    res = sizeof(uint16_t);
    break;
  case NETOPT_MAX_PDU_SIZE:
    assert(max_len >= sizeof(uint16_t));
    *((uint16_t *)value) = 1280;
    res = sizeof(uint16_t);
    break;
  case NETOPT_PROTO:
    assert(max_len == sizeof(gnrc_nettype_t));
    *((gnrc_nettype_t *)value) = _nettype;
    res = sizeof(gnrc_nettype_t);
    break;
  case NETOPT_DEVICE_TYPE:
    assert(max_len == sizeof(uint16_t));
    *((uint16_t *)value) = NETDEV_TYPE_ETHERNET;
    res = sizeof(uint16_t);
    break;
  default:
    break;
  }

  return res;
}

static inline int _netdev_set(netdev_t *dev, netopt_t opt, const void *value,
                              size_t val_len) {
  (void)dev;
  int res = -ENOTSUP;

  switch (opt) {
  case NETOPT_PROTO:
    assert(val_len == sizeof(_nettype));
    memcpy(&_nettype, value, sizeof(_nettype));
    res = sizeof(_nettype);
    break;
  default:
    break;
  }

  return res;
}

static const netdev_driver_t _dummy_driver = {
    .send = NULL,
    .recv = NULL,
    .init = _netdev_init,
    .isr = NULL,
    .get = _netdev_get,
    .set = _netdev_set,
};

static netdev_t _dummy = {.driver = &_dummy_driver};

extern int udp_send(int argc, char **argv);

static const shell_command_t shell_commands[] = {
    {"udpse", "send udp packets", udp_send}, {NULL, NULL, NULL}};

int main(void) {
  puts("Generated RIOT application: 'evqueue_netif'");
  _pid = thread_create(_msg_stack, sizeof(_msg_stack), THREAD_PRIORITY_MAIN - 1,
                       THREAD_CREATE_STACKTEST, _event_loop, NULL, "wg");
  msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
  char line_buf[SHELL_DEFAULT_BUFSIZE];
  shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
  return 0;
}

static void *_event_loop(void *arg) {
  (void)arg;
  mutex_init(&_tunnel_mtx);
  sock_udp_ep_t local;
  memset(&local, 0, sizeof(sock_udp_ep_t));

  local.family = AF_INET6;
  local.netif = SOCK_ADDR_ANY_NETIF;
  local.port = 41414;
  int res = sock_udp_create(&_sock_udp, &local, NULL, 0);
  if (res < 0) {
    DEBUG("wg: can not create sock: %d\n", res);
    return 0;
  }

  event_queue_init(&_queue);
  sock_udp_event_init(&_sock_udp, &_queue, _on_sock_udp_evt, NULL);

  _send_pid =
      thread_create(_snd_stack, sizeof(_snd_stack), THREAD_PRIORITY_MAIN - 1,
                    THREAD_CREATE_STACKTEST, _send_udp_loop, NULL, "wg_send");
  gnrc_netif_create(&_netif, _stack, sizeof(_stack), GNRC_NETIF_PRIO, "netif",
                    &_dummy, &_ops);
  ipv6_addr_t ip;
  ipv6_addr_t *r = ipv6_addr_from_str(&ip, "fe80::1880:5eff:feed:6e49");
  assert(r != NULL);
  gnrc_netif_ipv6_addr_add(&_netif, &ip, 64,
                           GNRC_NETIF_IPV6_ADDRS_FLAGS_STATE_VALID);
  _netif_pid = _netif.pid;
  event_loop(&_queue);

  return 0;
}

// static void _callback(void *arg) {
//   (void)arg;
//   event_callback_t cb = EVENT_CALLBACK_INIT(send, &remote);
//   event_post(&_queue, &cb.super);
// }

static void *_send_udp_loop(void *arg) {
  (void)arg;
  // event_periodic_callback_t cb;
  // event_periodic_callback_create(&cb, ZTIMER_SEC, 5, &_queue, send, &remote);
  return 0;
}

static void _on_sock_udp_evt(sock_udp_t *sock, sock_async_flags_t type,
                             void *arg) {
  (void)arg;
  if (type & SOCK_ASYNC_MSG_RECV) {
    void *stackbuf;
    void *bufctx = NULL;
    sock_udp_ep_t peer;
    sock_udp_aux_rx_t aux_in = {.flags = SOCK_AUX_GET_LOCAL};
    ssize_t res =
        sock_udp_recv_buf_aux(sock, &stackbuf, &bufctx, 0, &remote, &aux_in);
    if (res < 0) {
      DEBUG("wg: udp recv failure: %" PRIdSIZE "\n", res);
      return;
    }
    if (!memcmp(stackbuf, "handshake\n", sizeof("handshake"))) {

      // tunnel_mtx for wireguard
      mutex_lock(&_tunnel_mtx);
      memcpy(&peer, &remote, sizeof(sock_udp_ep_t));
      mutex_unlock(&_tunnel_mtx);

      sock_udp_send(sock, "handcc\n", sizeof("handcc\n"), &peer);
    } else if (!memcmp(stackbuf, "transport\n", sizeof("tranpsort\n"))) {
      printf("transported");
    }
    printf("wtf\n");
  }
}

static int _netif_init(gnrc_netif_t *netif) {
  (void)netif;

  int res = gnrc_netif_default_init(netif);
  if (res < 0) {
    return res;
  }

  /* save the threads context pointer, so we can set its flags */
  _netif_thread = thread_get_active();

#if IS_USED(MODULE_GNRC_NETIF_6LO)
  /* we disable fragmentation for this device, as the L2CAP layer takes care
   * of this */
  _netif.sixlo.max_frag_size = 0;
#endif /* IS_USED(MODULE_GNRC_NETIF_6LO) */
  res = 0;

  return res;
}

// TODO: investigate the extra send function
static int _netif_send(gnrc_netif_t *netif, gnrc_pktsnip_t *pkt) {
  (void)netif;
  event_post(&_queue, &cb.super);
  event_callback_oneshot(&cb, &_queue, send, &remote);
  printf("Fuck yeah\n");
  gnrc_pktbuf_release(pkt);
  return 0;
}

static gnrc_pktsnip_t *_netif_recv(gnrc_netif_t *netif) {
  (void)netif;
  return NULL;
}

static void send(void *arg) {
  (void)arg;
  sock_udp_ep_t *peer = (sock_udp_ep_t *)arg;
  sock_udp_send(&_sock_udp, "Nhi\n", sizeof("Nhi\n"), peer);
}
