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

typedef struct {
  // Required: private key of this WireGuard network must be
  // NOISE_PRIVATE_KEY_LEN long interface
  const uint8_t *privkey;
  // Required: What UDP port to listen on
  uint16_t listen_port;
  // Optional: restrict send/receive of encapsulated WireGuard traffic to this
  // network interface only (NULL to use routing table)
  uint16_t bind_netif;
} wireguard_params_t;

typedef struct wg_device {
  netdev_t netdev;
  /* netif to send udp packet */
  uint16_t bind_netif;
  struct noise_static_identity static_identity;
  uint16_t listen_port;

  // network interface for receiving and dispatching IPv6 packet to wireguard
  // thread
  // TODO: change to netif later if need more generic interface
  gnrc_netif_t *netif;
  kernel_pid_t netif_pid;
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

} wireguard_t;

void wireguard_setup(wireguard_t *dev, wireguard_params_t *param);
int wireguard_init(wireguard_t *dev);

bool wg_device_init(wireguard_t *device, const uint8_t *privkey);
bool wg_peer_init(wireguard_t *device, struct wg_peer *peer,
                  const uint8_t *pubkey, const uint8_t *preshared_key);
struct wg_peer *peer_lookup_by_allowed_ip(wireguard_t *device,
                                          const ipv6_addr_t *ipaddr);
struct wg_peer *peer_alloc(wireguard_t *device);
struct wg_peer *peer_lookup_by_pubkey(wireguard_t *device,
                                      const uint8_t *pubkey);
uint8_t lookup_index_for_peer(wireguard_t *device, struct wg_peer *peer);
struct wg_peer *peer_lookup_by_index(wireguard_t *device, uint8_t index);
struct wg_peer *peer_lookup_by_receiver(wireguard_t *device, uint32_t receiver);
struct wg_peer *peer_lookup_by_handshake(wireguard_t *device,
                                         uint32_t receiver);

#endif
