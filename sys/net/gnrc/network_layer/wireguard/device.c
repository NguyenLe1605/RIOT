#include "net/wireguard/device.h"
#include "base64.h"
#include "blake2.h"
#include "container.h"
#include "crypto/helper.h"
#include "iolist.h"
#include "net/af.h"
#include "net/gnrc/netif/hdr.h"
#include "net/gnrc/nettype.h"
#include "net/gnrc/pkt.h"
#include "net/gnrc/pktbuf.h"
#include "net/ipv6/addr.h"
#include "net/netdev.h"
#include "net/netopt.h"
#include "net/sock.h"
#include "net/sock/async.h"
#include "net/sock/async/types.h"
#include "net/sock/udp.h"
#include "net/wireguard.h"
#include "net/wireguard/crypto.h"
#include "net/wireguard/messages.h"
#include "net/wireguard/noise.h"
#include "net/wireguard/peer.h"
#include "random.h"
#include "ztimer.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ENABLE_DEBUG 1
#include "debug.h"

#define REPLAY_WINDOW_SIZE (32)
// For HMAC calculation
#define WG_BLAKE2S_BLOCK_SIZE (64)
#define COOKIE_NONCE_LEN (24)

static const netdev_driver_t wireguard_driver;

static void wireguard_cleanup(wireguard_t *wg) {
  crypto_secure_wipe(wg->static_identity.static_public, NOISE_PUBLIC_KEY_LEN);
  crypto_secure_wipe(wg->static_identity.static_private, NOISE_PRIVATE_KEY_LEN);
  wg->static_identity.has_identity = false;
}

static void _receive(sock_udp_t *sock, sock_async_flags_t type, void *arg) {
  if (!(type & SOCK_ASYNC_MSG_RECV)) {
    return;
  }
  void *stackbuf;
  void *buf_ctx = NULL;
  sock_udp_ep_t remote;
  wireguard_t *wg = (wireguard_t *)arg;
  (void)wg;
  ssize_t res = sock_udp_recv_buf(sock, &stackbuf, &buf_ctx, 0, &remote);
  if (res < 0) {
    printf("wireguard: udp recv failure: %" PRIdSIZE "\n", res);
    return;
  }

  /* TODO: implement decrypt the packet */

  /* allocate netif header */
  gnrc_pktsnip_t *if_snip = gnrc_netif_hdr_build(NULL, 0, NULL, 0);
  if (if_snip == NULL) {
    return;
  }

  /* add device PID to the netif header */
  gnrc_netif_hdr_set_netif(if_snip->data, wg->netif);
  /* allocate payload */
  gnrc_pktsnip_t *payload =
      gnrc_pktbuf_add(if_snip, NULL, res, GNRC_NETTYPE_IPV6);

  if (payload == NULL) {
    gnrc_pktbuf_release(if_snip);
    return;
  }

  memcpy(payload->data, stackbuf, res);
  /* finally dispatch the receive packet to GNRC */
  if (!gnrc_netapi_dispatch_receive(payload->type, GNRC_NETREG_DEMUX_CTX_ALL,
                                    payload)) {
    gnrc_pktbuf_release(payload);
  }

  printf("recv len: %d\n", res);
  for (int i = 0; i < res; i++) {
    printf("%d, ", ((uint8_t *)stackbuf)[i]);
  }
  printf("\n");
  return;
}

static int _get(netdev_t *dev, netopt_t opt, void *value, size_t max_len) {
  (void)dev;
  int result = -ENOTSUP;
  switch (opt) {
  case NETOPT_MAX_PDU_SIZE:
    assert(max_len >= sizeof(uint16_t));
    *((uint16_t *)value) = WG_MTU;
    result = sizeof(uint16_t);
    break;
  case NETOPT_DEVICE_TYPE:
    assert(max_len == sizeof(uint16_t));
    *((uint16_t *)value) = NETDEV_TYPE_WIREGUARD;
    result = sizeof(uint16_t);
    break;
  case NETOPT_PROTO:
    assert(max_len == sizeof(gnrc_nettype_t));
    *((gnrc_nettype_t *)value) = GNRC_NETTYPE_IPV6;
    result = sizeof(gnrc_nettype_t);
    break;
  default:
    break;
  }
  return result;
}

static int _send(netdev_t *dev, const iolist_t *pkt) {
  (void)pkt;
  DEBUG("hello\n");
  wireguard_t *wg = container_of(dev, wireguard_t, netdev);
  /* TODO: remove this with actual routing to peer */
  sock_udp_ep_t remote = {
      .port = 12345,
      .family = AF_INET6,
      .addr.ipv6 = {0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x84, 0x2b, 0x16,
                    0xff, 0xfe, 0x72, 0xa8, 0x40},
  };
  if (sock_udp_send(&wg->udp, pkt->iol_base, pkt->iol_len, &remote) < 0) {
    puts("Error sending message");
    return -1;
  }
  return 0;
}

int _set(netdev_t *dev, netopt_t opt, const void *value, size_t len) {
  (void)dev;
  (void)opt;
  (void)value;
  (void)len;
  /* TODO: add option to set encryption key and ipv6 address */
  return -ENOTSUP;
}

/* a gnrc_netif_default_init must be called before */
static int _init(netdev_t *dev) {
  assert(dev);
  wireguard_t *wg;
  sock_udp_ep_t local_ep;
  int result;

  result = 0;
  wg = container_of(dev, wireguard_t, netdev);
  if (!wg->static_identity.has_identity) {
    /* the private key during set up is not valid */
    wireguard_cleanup(wg);
    return -EINVAL;
  }

  wg_noise_init();

  /* initalize the udp port, with the preconfigured bind-netif */
  local_ep = (sock_udp_ep_t)SOCK_IPV6_EP_ANY;
  local_ep.port = wg->listen_port;
  local_ep.netif = wg->bind_netif ? wg->bind_netif : SOCK_ADDR_ANY_NETIF;

  if ((result = sock_udp_create(&wg->udp, &local_ep, NULL, 0)) < 0) {
    wireguard_cleanup(wg);
    return result;
  }

  /* set callback to handle receiving UDP packet */
  sock_udp_set_cb(&wg->udp, _receive, (void *)wg);
  wg->netif = (gnrc_netif_t *)dev->context;
  /* set the link to be up */
  dev->event_callback(dev, NETDEV_EVENT_LINK_UP);

  return result;
}

void wireguard_setup(wireguard_t *dev, wireguard_params_t *param) {
  assert(param);
  DEBUG("testing\n");
  netdev_t *netdev = &dev->netdev;
  wg_noise_set_static_identity_private_key(&dev->static_identity,
                                           param->privkey);
  dev->listen_port = param->listen_port;
  dev->bind_netif = param->bind_netif;
  netdev->driver = &wireguard_driver;
  netdev_register(netdev, NETDEV_WIREGUARD, 0);
}

static const netdev_driver_t wireguard_driver = {
    .init = _init,
    .get = _get,
    .send = _send,
    .set = _set,
};

// TODO: refactor it to peer.h

// wg_peer_t *peer_alloc(wg_device_t *device) {
//   int i;
//   wg_peer_t *result = NULL;
//   wg_peer_t *tmp;
//   for (i = 0; i < WG_MAX_PEERS; ++i) {
//     tmp = &device->peers[i];
//     if (!tmp->valid) {
//       result = tmp;
//       break;
//     }
//   }
//   return result;
// }
//
// wg_peer_t *peer_lookup_by_pubkey(wg_device_t *device, const uint8_t
// *pubkey)
// {
//   int i;
//   wg_peer_t *result = NULL;
//   wg_peer_t *tmp;
//   for (i = 0; i < WG_MAX_PEERS; ++i) {
//     tmp = &device->peers[i];
//     if (crypto_equals(tmp->pubkey, pubkey, WG_PUBLIC_KEY_LEN)) {
//       result = tmp;
//       break;
//     }
//   }
//   return result;
// }
//
// // TODO: considering remove it later for better peer acknowledge its
// position
// // inside the container
// uint8_t lookup_index_for_peer(wg_device_t *device, wg_peer_t *peer) {
//   uint8_t result = 0xFF;
//   uint8_t i;
//   for (i = 0; i < WG_MAX_PEERS; ++i) {
//     if (peer == &device->peers[i]) {
//       result = i;
//       break;
//     }
//   }
//   return result;
// }
//
// wg_peer_t *peer_lookup_by_index(wg_device_t *device, uint8_t index) {
//   wg_peer_t *result = NULL;
//   if (index < WG_MAX_PEERS && device->peers[index].valid) {
//     result = &device->peers[index];
//   }
//   return result;
// }
//
// wg_peer_t *peer_lookup_by_receiver(wg_device_t *device, uint32_t receiver)
// {
//   wg_peer_t *result = NULL;
//   wg_peer_t *tmp;
//   int x;
//   for (x = 0; x < WG_MAX_PEERS; x++) {
//     tmp = &device->peers[x];
//     if (!tmp->valid) {
//       continue;
//     }
//     if ((tmp->curr_keypair.valid &&
//          (tmp->curr_keypair.local_index == receiver)) ||
//         (tmp->next_keypair.valid &&
//          (tmp->next_keypair.local_index == receiver)) ||
//         (tmp->prev_keypair.valid &&
//          (tmp->prev_keypair.local_index == receiver))) {
//       result = tmp;
//       break;
//     }
//   }
//   return result;
// }
//
// wg_peer_t *peer_lookup_by_handshake(wg_device_t *device, uint32_t receiver)
// {
//   wg_peer_t *result = NULL;
//   wg_peer_t *tmp;
//   int x;
//   for (x = 0; x < WG_MAX_PEERS; x++) {
//     tmp = &device->peers[x];
//     if (!tmp->valid) {
//       continue;
//     }
//     if (tmp->handshake.valid && tmp->handshake.initiator &&
//         (tmp->handshake.local_index == receiver)) {
//       result = tmp;
//       break;
//     }
//   }
//   return result;
// }
//
// bool wg_expired(uint32_t birthday_millis, uint32_t valid_seconds) {
//   uint32_t diff = ztimer_now(ZTIMER_MSEC) - birthday_millis;
//   return (diff >= valid_seconds * 1000);
// }
//
// bool wg_check_replay(wg_keypair_t *keypair, uint64_t seq) {
//   // Implementation of sliding windows algorithm from appendix C
//   // https://datatracker.ietf.org/doc/html/rfc2401
//   uint32_t diff;
//
//   // wireguard packet start from 0, but the algorithm requires to start
//   from 1 seq++; if (seq == 0) // first == 0 or wrapped
//     return false;
//
//   if (seq > keypair->replay_counter) {
//     diff = seq - keypair->replay_counter;
//     if (diff < REPLAY_WINDOW_SIZE) { // In Window
//       keypair->replay_bitmap <<= diff;
//       keypair->replay_bitmap |= 1;
//     } else {
//       keypair->replay_bitmap = 1;
//     }
//
//     keypair->replay_counter = seq;
//     return true;
//   }
//
//   diff = keypair->replay_counter - seq;
//   if (diff > REPLAY_WINDOW_SIZE) // Too old or wrapped
//     return false;
//
//   if (keypair->replay_bitmap & (1UL << diff)) // already seen
//     return false;
//   keypair->replay_bitmap |= (1UL << diff); // mark as seen
//
//   return true; // out of order but not replay packet
// }
//
// wg_keypair_t *get_keypair_for_idx(wg_peer_t *peer, uint32_t idx) {
//   if (peer->curr_keypair.valid && peer->curr_keypair.local_index == idx) {
//     return &peer->curr_keypair;
//   } else if (peer->next_keypair.valid &&
//              peer->next_keypair.local_index == idx) {
//     return &peer->next_keypair;
//   } else if (peer->prev_keypair.valid &&
//              peer->prev_keypair.local_index == idx) {
//     return &peer->prev_keypair;
//   }
//   return NULL;
// }
//
// bool wg_validate_mac1(wg_device_t *device, const uint8_t *data, size_t len,
//                       const uint8_t *mac1) {
//   bool result = false;
//   uint8_t calculated[WG_COOKIE_LEN];
//   mac(calculated, data, len, device->label_mac1_key, WG_SESSION_KEY_LEN);
//   if (crypto_equals(calculated, mac1, WG_MAC_LEN)) {
//     result = true;
//   }
//   return result;
// }
//
// bool wg_validate_mac2(wg_device_t *device, const uint8_t *data, size_t len,
//                       uint8_t *source_addr_port, size_t source_length,
//                       const uint8_t *mac2) {
//   bool result = false;
//   uint8_t cookie[WG_COOKIE_LEN];
//   uint8_t calculated[WG_COOKIE_LEN];
//
//   generate_peer_cookie(device, cookie, source_addr_port, source_length);
//
//   mac(calculated, data, len, cookie, WG_COOKIE_LEN);
//   if (crypto_equals(calculated, mac2, WG_COOKIE_LEN)) {
//     result = true;
//   }
//   return result;
// }
//
