#ifndef _WIREGUARD_DEVICE_H_
#define _WIREGUARD_DEVICE_H_

#include "messages.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/pkt.h"
#include "net/ipv6/addr.h"
#include "net/netdev.h"
#include "net/sock/udp.h"
#include "net/wireguard/cookie.h"
#include "noise.h"
#include "peer.h"
#include <stdint.h>

#define COOKIE_SECRET_MAX_AGE (120)
#define WIREGUARD_DEFAULT_PORT (51820)
#define MAX_NUM_OF_HANSHAKE (MAX_PEERS_PER_DEVICE * 2)

typedef struct {
  /* Required: What UDP port to listen on */
  uint16_t listen_port;
  /* Optional: restrict send/receive of encapsulated WireGuard traffic to this
  network interface only (0 to use routing table) */
  uint16_t bind_netif;
  const uint8_t *private_key;
} wireguard_params_t;

typedef struct wg_device {
  netdev_t netdev;
  /* netif to send udp packet */
  uint16_t bind_netif;
  struct noise_static_identity static_identity;
  uint16_t listen_port;

  /* network interface for receiving and dispatching IPv6 packet to wireguard
   * thread */
  gnrc_netif_t *netif;

  struct cookie_checker cookie_checker;
  /* udp socket */
  sock_udp_t udp;
  /* valid when the private key is successfully added */
  bool valid;

  /* List of peers associated with this device */
  struct wg_peer peers[MAX_PEERS_PER_DEVICE];

  /* periodic timer to do the timer state machine */
  ztimer_t timer;

  /* total number of handshake packets that is being handled */
  uint8_t num_handshake;
  wireguard_params_t *param;
} wireguard_t;

void wireguard_setup(wireguard_t *dev, wireguard_params_t *param);
int wireguard_init(wireguard_t *dev);

/* This is used as the output function for the Wireguard netif The addr here
 * is the one inside the VPN which we use to lookup the correct peer/endpoint */
int wireguard_send(wireguard_t *device, gnrc_pktsnip_t *pkt,
                   const ipv6_addr_t *addr);

int wireguard_send_handshake_initiation(struct wg_peer *peer);
int wireguard_send_handshake_response(struct wg_peer *peer);
int wireguard_send_cookie_reply(wireguard_t *wg, uint8_t *buf, size_t len,
                                sock_udp_ep_t *remote, uint32_t index);
int wireguard_send_keepalive(struct wg_peer *peer);
#endif
