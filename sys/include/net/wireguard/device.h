#ifndef _WIREGUARD_DEVICE_H_
#define _WIREGUARD_DEVICE_H_

#include "event.h"
#include "messages.h"
#include "net/gnrc/netif.h"
#include "net/ipv6/addr.h"
#include "net/netdev.h"
#include "net/sock/udp.h"
#include "noise.h"
#include "peer.h"
#include "sched.h"
#include "ztimer/periodic.h"
#include <stdint.h>

#define COOKIE_SECRET_MAX_AGE (120)

typedef struct wg_device {
  // network interface for receiving and dispatching IPv6 packet to wireguard
  // thread
  // TODO: change to netif later if need more generic interface
  gnrc_netif_t *netif;
  kernel_pid_t netif_pid;
  // dummy device to config dummy ethernet
  netdev_t *dev;
  // queue to handle event of receiving and sending packet
  event_queue_t *evqueue;
  kernel_pid_t wg_pid;
  // running thread of the wireguard protocol
  thread_t *wg_thread;
  // udp socket
  sock_udp_t udp;
  uint16_t listening_port;

  bool valid;
  // // static pub/priv keypair - TODO: choose the right abstraction
  // uint8_t public_key[NOISE_PUBLIC_KEY_LEN];
  // uint8_t private_key[NOISE_PRIVATE_KEY_LEN];
  struct noise_static_identity static_identity;

  uint8_t cookie_secret[NOISE_HASH_LEN];
  uint32_t cookie_secret_millis;

  // Precalculated
  uint8_t label_cookie_key[NOISE_SYMMETRIC_KEY_LEN];
  uint8_t label_mac1_key[NOISE_SYMMETRIC_KEY_LEN];

  // List of peers associated with this device
  // use siphash to identify the peer
  struct wg_peer peers[MAX_PEERS_PER_DEVICE];

  // periodic timer to clean up the key
  ztimer_periodic_t timer;

} wg_device_t;

bool wg_device_init(wg_device_t *device, const uint8_t *privkey);
bool wg_peer_init(wg_device_t *device, struct wg_peer *peer,
                  const uint8_t *pubkey, const uint8_t *preshared_key);
struct wg_peer *peer_lookup_by_allowed_ip(wg_device_t *device,
                                          const ipv6_addr_t *ipaddr);
struct wg_peer *peer_alloc(wg_device_t *device);
struct wg_peer *peer_lookup_by_pubkey(wg_device_t *device,
                                      const uint8_t *pubkey);
uint8_t lookup_index_for_peer(wg_device_t *device, struct wg_peer *peer);
struct wg_peer *peer_lookup_by_index(wg_device_t *device, uint8_t index);
struct wg_peer *peer_lookup_by_receiver(wg_device_t *device, uint32_t receiver);
struct wg_peer *peer_lookup_by_handshake(wg_device_t *device,
                                         uint32_t receiver);

#endif
