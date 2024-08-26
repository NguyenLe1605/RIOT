#include "net/wireguard.h"
#include "assert.h"
#include "base64.h"
#include "container.h"
#include "crypto/helper.h"
#include "iolist.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netif/conf.h"
#include "net/gnrc/netif/flags.h"
#include "net/gnrc/netif/internal.h"
#include "net/gnrc/netif/ipv6.h"
#include "net/gnrc/nettype.h"
#include "net/gnrc/pkt.h"
#include "net/ipv6/addr.h"
#include "net/ipv6/hdr.h"
#include "net/netdev.h"
#include "net/netif.h"
#include "net/sock.h"
#include "net/sock/async.h"
#include "net/sock/async/types.h"
#include "net/sock/udp.h"
#include "net/wireguard/crypto.h"
#include "net/wireguard/device.h"
#include "net/wireguard/messages.h"
#include "net/wireguard/noise.h"
#include "net/wireguard/peer.h"
#include "ztimer.h"
#include "ztimer/periodic.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define ENABLE_DEBUG 0
#include "debug.h"

static int wireguard_netif_lookup_peer(gnrc_netif_t *netif, uint8_t peer_idx,
                                       struct wg_peer **out) {
  assert(netif);
  assert(netif->dev);
  wireguard_t *wg = container_of(netif->dev, wireguard_t, netdev);
  struct wg_peer *peer = NULL;
  int result = 0;
  if (wg->valid) {
    peer = peer_lookup_by_index(wg->peers, peer_idx);
    if (peer) {
      result = 0;
    } else {
      result = -EINVAL;
    }
  } else {
    result = -EINVAL;
  }
  *out = peer;
  return result;
}

static int _netif_init(gnrc_netif_t *netif) {
  int res = gnrc_netif_default_init(netif);
  if (res < 0) {
    return res;
  }
#if IS_USED(MODULE_GNRC_NETIF_6LO)
  /* we disable fragmentation for this device, as the public network interface
   * will handle it of this */
  netif.sixlo.max_frag_size = 0;
#endif /* IS_USED(MODULE_GNRC_NETIF_6LO) */
  netif->flags = 0;
  netif->l2addr_len = 0;
  /* TODO: set up for get and set retval to be all 0 */
  /* TODO: set up option to set the encryption key */

  netif->ipv6.mtu = WIREGUARD_MTU;

  res = 0;

  return res;
}

static int _netif_send(gnrc_netif_t *netif, gnrc_pktsnip_t *pkt) {
  assert(netif);
  assert(netif->dev);
  int res = 0;
  ipv6_hdr_t *hdr;
  ipv6_addr_t addr;
  wireguard_t *wg = container_of(netif->dev, wireguard_t, netdev);
  if (pkt == NULL) {
    DEBUG("_send_wireguard: pkt was NULL\n");
    return -EINVAL;
  }
  if (pkt->type != GNRC_NETTYPE_NETIF) {
    DEBUG("_send_wireguard: first header is not generic netif header\n");
    return -EBADMSG;
  }

  if (pkt->next == NULL || pkt->next->type != GNRC_NETTYPE_IPV6) {
    DEBUG("_send_wireguard: second header is not ipv6 header\n");
    return -EBADMSG;
  }

  /* write protect `pkt` to set `pkt->next` */
  gnrc_pktsnip_t *tmp = gnrc_pktbuf_start_write(pkt);
  if (!tmp) {
    DEBUG("_send_wireguard: no write access to pkt\n");
    gnrc_pktbuf_release(pkt);
    return -ENOMEM;
  }
  pkt = tmp;
  tmp = gnrc_pktbuf_start_write(pkt->next);
  if (!tmp) {
    DEBUG("_send_wireguard: no write access to pkt->next\n");
    gnrc_pktbuf_release(pkt);
    return -ENOMEM;
  }
  pkt->next = tmp;
  hdr = (ipv6_hdr_t *)pkt->next->data;
  addr = hdr->dst;
  // /* merge snippets to store the ipv6 packet uniformly in one buffer */
  // res = gnrc_pktbuf_merge(pkt->next);
  // if (res < 0) {
  //   DEBUG("_send_wireguard: failed to merge pktbuf\n");
  //   gnrc_pktbuf_release(pkt);
  //   return res;
  // }
  wireguard_send(wg, pkt->next, &addr);
  if (gnrc_netif_netdev_legacy_api(netif)) {
    /* only for legacy drivers we need to release pkt here */
    gnrc_pktbuf_release(pkt);
  }
  return res;
}

static gnrc_pktsnip_t *_netif_recv(gnrc_netif_t *netif) {
  (void)netif;
  return NULL;
}

static const gnrc_netif_ops_t wireguard_ops = {
    .init = _netif_init,
    .send = _netif_send,
    .recv = _netif_recv,
    .get = gnrc_netif_get_from_netdev,
    .set = gnrc_netif_set_from_netdev,
    .msg_handler = NULL,
};

/* spawn the netif thread that handle wireguard connection and configure only 1
 * peer to the wireguard interface, and set up the network device also
 * */
int gnrc_netif_wireguard_create(gnrc_netif_t *netif, char *stack, int stacksize,
                                char priority, char *name, netdev_t *dev) {
  return gnrc_netif_create(netif, stack, stacksize, priority, name, dev,
                           &wireguard_ops);
}

void gnrc_netif_wireguard_peer_init(wireguard_netif_peer_t *peer) {
  assert(peer);
  memset(peer, 0, sizeof(wireguard_netif_peer_t));
  /* caller must provide public key */
  peer->public_key = NULL;
  peer->remote = (sock_udp_ep_t)SOCK_IPV6_EP_ANY;
  peer->remote.port = WIREGUARD_DEFAULT_PORT;
  peer->keep_alive = WIREGUARD_KEEPALIVE_DEFAULT;
  peer->allowed_ip = (ipv6_addr_t)IPV6_ADDR_UNSPECIFIED;
  peer->pfx_len = 0;
  peer->preshared_key = NULL;
  memset(peer->greatest_timestamp, 0, sizeof(peer->greatest_timestamp));
}

int gnrc_netif_wireguard_add_peer(gnrc_netif_t *netif,
                                  wireguard_netif_peer_t *peer,
                                  uint8_t *peer_idx) {
  assert(netif);
  assert(netif->dev);
  assert(peer);
  uint8_t public_key[NOISE_PUBLIC_KEY_LEN];
  size_t public_key_len = peer->public_key_len;
  wireguard_t *wg = container_of(netif->dev, wireguard_t, netdev);
  /* ptr to the peer array */
  struct wg_peer *peers = wg->peers;
  struct wg_peer *p = NULL;
  if (base64_decode(peer->public_key, peer->public_key_len, public_key,
                    &public_key_len) != BASE64_SUCCESS ||
      public_key_len != NOISE_PUBLIC_KEY_LEN) {
    return -EINVAL;
  }
  /* see if peer is already registered */
  p = peer_lookup_by_pubkey(peers, public_key);
  if (!p) {
    p = peer_alloc(peers);
    if (!p) {
      return -ENOMEM;
    }
    if (!wireguard_peer_init(wg, p, public_key, peer->preshared_key)) {
      return -EINVAL;
    }
    p->endpoint = peer->remote;
    p->latest_endpoint = p->endpoint;
    if (peer->keep_alive == WIREGUARD_KEEPALIVE_DEFAULT) {
      p->keepalive_interval = KEEPALIVE_TIMEOUT;
    } else {
      p->keepalive_interval = peer->keep_alive;
    }
    peer_add_ip(p, &peer->allowed_ip, peer->pfx_len);
    memcpy(p->handshake.greatest_timestamp, peer->greatest_timestamp,
           sizeof(peer->greatest_timestamp));
  }

  if (peer_idx) {
    if (p) {
      *peer_idx = p->peer_idx;
    } else {
      *peer_idx = WIREGUARD_INVALID_INDEX;
    }
  }

  return 0;
}

int gnrc_netif_wireguard_remove_peer(gnrc_netif_t *netif, uint8_t peer_idx) {
  struct wg_peer *peer;
  int result = wireguard_netif_lookup_peer(netif, peer_idx, &peer);
  if (result >= 0) {
    peer_remove(peer);
    result = 0;
  }

  return result;
}

int gnrc_netif_wireguard_update_endpoint(gnrc_netif_t *netif, uint8_t peer_idx,
                                         const ipv6_addr_t *ip, uint16_t port) {
  struct wg_peer *peer;
  int result = wireguard_netif_lookup_peer(netif, peer_idx, &peer);
  if (result >= 0) {
    memcpy(&peer->endpoint.addr.ipv6, ip, sizeof(ipv6_addr_t));
    peer->endpoint.port = port;
    result = 0;
  }

  return result;
}

/* Try and connect the given peer */
int gnrc_netif_wireguard_connect(gnrc_netif_t *netif, uint8_t peer_idx) {
  struct wg_peer *peer;
  int result = wireguard_netif_lookup_peer(netif, peer_idx, &peer);
  if (result >= 0) {
    /* check if a valid ip and port have been set */
    if (!ipv6_addr_is_unspecified((ipv6_addr_t *)peer->endpoint.addr.ipv6) &&
        peer->endpoint.port > 0) {
      /* Set the flag to indictate we want to actively connect */
      peer->active = true;
      peer->latest_endpoint = peer->endpoint;
      result = 0;
    } else {
      result = -EINVAL;
    }
  }
  return result;
}

int gnrc_netif_wireguard_disconnect(gnrc_netif_t *netif, uint8_t peer_idx) {
  struct wg_peer *peer;
  int result = wireguard_netif_lookup_peer(netif, peer_idx, &peer);
  if (result >= 0) {
    /* Set the flag to indictate we want to actively connect */
    peer->active = true;
    wg_noise_keypairs_clear(&peer->keypairs);
    result = 0;
  }
  return result;
}

int gnrc_netif_wireguard_peer_is_up(gnrc_netif_t *netif, uint8_t peer_idx,
                                    ipv6_addr_t *current_ip,
                                    uint16_t *current_port) {
  struct wg_peer *peer;
  int result = wireguard_netif_lookup_peer(netif, peer_idx, &peer);
  if (result >= 0) {
    if ((peer->keypairs.current_keypair.is_valid) ||
        (peer->keypairs.previous_keypair.is_valid)) {
      result = 0;
    } else {
      result = -ENOKEY;
    }
    if (current_ip) {
      memcpy(current_ip, &peer->latest_endpoint.addr.ipv6, sizeof(ipv6_addr_t));
    }
    if (current_port) {
      *current_port = peer->latest_endpoint.port;
    }
  }
  return result;
}
