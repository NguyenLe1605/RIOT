#include "gnrc_netif_wireguard.h"
#include "base64.h"
#include "event.h"
#include "net/netdev.h"
#include "random.h"
#include "wireguard.h"
#include "wireguard_constants.h"
#include "wireguard_internal.h"
#include <string.h>

#define ENABLE_DEBUG 1
#include "debug.h"

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

  netif->ipv6.mtu = WIREGUARD_NETIF_MTU;

  res = 0;

  DEBUG("[wireguad-gnrc-netif] init: Initialization successful\n");
  return res;
}

static int _netif_send(gnrc_netif_t *netif, gnrc_pktsnip_t *pkt) {
  assert(netif);
  assert(netif->dev);
  int res = 0;
  wireguard_t *wg = container_of(netif->dev, wireguard_t, netdev);
  if (pkt == NULL) {
    DEBUG("[wireguard-gnrc-netif] send: pkt was NULL\n");
    return -EINVAL;
  }
  if (pkt->type != GNRC_NETTYPE_NETIF) {
    DEBUG("[wireguard-gnrc-netif] send: first header is not generic netif "
          "header\n");
    return -EBADMSG;
  }

  if (pkt->next == NULL || pkt->next->type != GNRC_NETTYPE_IPV6) {
    DEBUG("[wireguard-gnrc-netif] send: second header is not ipv6 header\n");
    return -EBADMSG;
  }

  /* write protect `pkt` to set `pkt->next` */
  gnrc_pktsnip_t *tmp = gnrc_pktbuf_start_write(pkt);
  if (!tmp) {
    DEBUG("[wireguard-gnrc-netif] send: no write access to pkt\n");
    gnrc_pktbuf_release(pkt);
    return -ENOMEM;
  }
  pkt = tmp;
  tmp = gnrc_pktbuf_start_write(pkt->next);
  if (!tmp) {
    DEBUG("[wireguard-gnrc-netif] send: no write access to pkt->next\n");
    gnrc_pktbuf_release(pkt);
    return -ENOMEM;
  }
  pkt->next = tmp;
  // hdr = (ipv6_hdr_t *)pkt->next->data;
  // addr = hdr->dst;
  DEBUG("[wireguard-gnrc-netif] send: sending packet to wireguard device\n");
  wireguard_send(wg, pkt->next);
  if (gnrc_netif_netdev_legacy_api(netif)) {
    /* only for legacy drivers we need to release pkt here */
    gnrc_pktbuf_release(pkt);
  }
  return res;
}

static const gnrc_netif_ops_t wireguard_ops = {
    .init = _netif_init,
    .send = _netif_send,
    .recv = NULL,
    .get = gnrc_netif_get_from_netdev,
    .set = gnrc_netif_set_from_netdev,
    .msg_handler = NULL,
};

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
  peer->endpoint = (sock_udp_ep_t)SOCK_IPV6_EP_ANY;
  peer->endpoint.port = WIREGUARD_DEFAULT_UDP_PORT;
  peer->persistent_keepalive = 0;
  peer->allowed_ips = NULL;
  peer->allowed_ips_len = 0;
  peer->preshared_key = NULL;
}

int gnrc_netif_wireguard_add_peer(gnrc_netif_t *netif,
                                  wireguard_netif_peer_t *peer,
                                  uint8_t *peer_idx) {
  assert(netif);
  assert(netif->dev);
  assert(peer);
  int i;
  wireguard_netif_allowed_ip_t *ip;
  uint8_t public_key[NOISE_PUBLIC_KEY_LEN];
  size_t public_key_len = BASE64_PUBLIC_KEY_LEN;
  size_t netif_pubkey_len = strnlen(peer->public_key, BASE64_PUBLIC_KEY_LEN);
  if (peer->allowed_ips_len > MAX_SRC_IPS || peer->allowed_ips_len < 0) {
    return -EINVAL;
  }

  wireguard_t *wg = container_of(netif->dev, wireguard_t, netdev);

  int result;
  struct wireguard_peer *peers = wg->peers;
  struct wireguard_peer *p = NULL;
  if (base64_decode(peer->public_key, netif_pubkey_len, public_key,
                    &public_key_len) != BASE64_SUCCESS ||
      public_key_len != NOISE_PUBLIC_KEY_LEN) {
    return -EINVAL;
  }
  /* see if peer is already registered */
  p = wireguard_peer_lookup_by_pubkey(peers, public_key);
  if (!p) {
    /* add endpoint to the entry cache */
    if ((result = wireguard_set_endpoint(&peer->endpoint, netif->pid,
                                         &peer->endpoint)) < 0) {
      return result;
    }
    p = wireguard_peer_alloc(peers);
    if (!p) {
      return -ENOMEM;
    }
    if (!wireguard_peer_init(wg, p, public_key, peer->preshared_key)) {
      return -EINVAL;
    }
    p->endpoint = peer->endpoint;
    p->latest_endpoint = p->endpoint;
    p->persistent_keepalive_interval = peer->persistent_keepalive;
    for (i = 0; i < peer->allowed_ips_len; i++) {
      ip = peer->allowed_ips + i;
      wireguard_peer_add_ip(p, &ip->addr, ip->pfx_len);
    }
  }

  if (peer_idx) {
    if (p) {
      *peer_idx = p->peer_idx;
    } else {
      *peer_idx = WIREGUARD_INVALID_INDEX;
    }
  }
  DEBUG("[wireguard] add peer sucessfully at index : %d\n", p->peer_idx);

  return 0;
}

static int wireguard_netif_lookup_peer(gnrc_netif_t *netif, uint8_t peer_idx,
                                       struct wireguard_peer **out) {
  assert(netif);
  assert(netif->dev);
  wireguard_t *wg = container_of(netif->dev, wireguard_t, netdev);
  struct wireguard_peer *peer = NULL;
  int result = 0;
  if (wg->valid) {
    peer = wireguard_peer_lookup_by_index(wg->peers, peer_idx);
    if (peer) {
      result = 0;
    } else {
      result = -EINVAL;
    }
  } else {
    result = -ENODEV;
  }
  *out = peer;
  return result;
}

int gnrc_netif_wireguard_connect(gnrc_netif_t *netif, uint8_t peer_idx) {
  struct wireguard_peer *peer;
  int result = wireguard_netif_lookup_peer(netif, peer_idx, &peer);
  if (result < 0) {
    return result;
  }

  if (peer->active) {
    return result;
  }

  /* check if a valid ip and port have been set */
  if (!ipv6_addr_is_unspecified((ipv6_addr_t *)peer->endpoint.addr.ipv6) &&
      peer->endpoint.port > 0) {
    wireguard_sched_handshake_init(peer, false);
  }
  return result;
}

uint32_t wireguard_generate_unique_index(wireguard_t *wg) {
  /* generate 32-bit random index that has not been used by any valid handshake
   * or key */
  struct wireguard_peer *peers = wg->peers;
  uint32_t result;
  int i;
  struct wireguard_peer *peer = NULL;
  bool existing = false;
  do {
    do {
      result = random_uint32();
    } while (result == 0 || result == 0xFFFFFFFF);
    /* check if the index has been existed or not for the whole device */
    for (i = 0; i < MAX_PEERS_PER_DEVICE; ++i) {
      peer = &peers[i];
      if (peer->valid) {
        existing |= peer->keypairs.current_keypair.valid &&
                    result == peer->keypairs.current_keypair.local_index;
        existing |= peer->keypairs.previous_keypair.valid &&
                    result == peer->keypairs.previous_keypair.local_index;
        existing |= peer->keypairs.next_keypair.valid &&
                    result == peer->keypairs.next_keypair.local_index;
        existing |= peer->handshake.handshaking &&
                    result == peer->handshake.local_index;
      }
    }
  } while (existing);
  return result;
}
