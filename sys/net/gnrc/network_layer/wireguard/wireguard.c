#include "net/wireguard.h"
#include "assert.h"
#include "base64.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netif/conf.h"
#include "net/gnrc/pkt.h"
#include "net/ipv6/addr.h"
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
#include <stdlib.h>

#define ENABLE_DEBUG 0
#include "debug.h"

#define WG_TIMER_MSECS 400

// static int wg_send(gnrc_netif_t *netif, gnrc_pktsnip_t *pkt);
// static void wg_receive(sock_udp_t *sock, sock_async_flags_t flags, void
// *arg); static bool wg_periodic_cleanup(void *arg);
// // static int wg_send_to_peer(gnrc_netif_t *netif, gnrc_pktsnip_t *pkt,
// //                            const ipv6_addr_t *ipaddr, wg_peer_t *peer);
//
// static uint8_t wg_peer_idx = -1;
// static char wg_netif_stack[THREAD_STACKSIZE_DEFAULT];
// static gnrc_netif_t wg_netif;
// static netdev_t wg_dev;
// static const gnrc_netif_ops_t ops = {
//     .init = wg_init,
// };
//
// void wg_setup(void) {
//   wg_ifpeer_t peer;
//   wg_config_t wg;
//   int res;
//
//   // set up ipaddrv6
//   // ipv6_addr_t addr = IPV6_ADDR_UNSPECIFIED;
//
//   // set up wg init configuration
//   wg.privkey = "I love u";
//   wg.listen_port = 16;
//   wg.bind_netif = NULL;
//   wg_dev.context = &wg;
//
//   // set up the new netif
//   // TODO: put is somewhere else, is it plausible???
//   res = gnrc_netif_create(&wg_netif, wg_netif_stack, sizeof(wg_netif_stack),
//                           GNRC_NETIF_PRIO, "wg_netif", &wg_dev, &ops);
//   // TODO: add better error handling later
//   assert(res >= 0);
//
//   // TODO:  add ipv6 later
//
//   // setup peer;
//   wg_ifpeer_init(&peer);
//   peer.pubkey = "cDfetaDFWnbxts2Pbz4vFYreikPEEVhTlV/sniIEBjo=";
//   peer.preshared_key = NULL;
//   peer.allowed_ip = (ipv6_addr_t)IPV6_ADDR_UNSPECIFIED;
//
//   // TODO: add some fake addres later
//   peer.ep.addr = (ipv6_addr_t)IPV6_ADDR_UNSPECIFIED;
//   peer.ep.port = 12345;
//
//   // TODO: find the allowed all ipv6 address in the rfc
//   res = wg_add_ifpeer(&wg_netif, &peer, &wg_peer_idx);
//   if (wg_peer_idx != WG_INVALID_INDEX &&
//       !ipv6_addr_is_unspecified(&peer.ep.addr)) {
//     wg_connect(&wg_netif, WG_INVALID_INDEX);
//   }
// }
//
// static const gnrc_netif_ops_t wg_ops = {
//     .init = wg_init,
//     .send = wg_send,
// };
//
// int wg_init(gnrc_netif_t *netif) {
//   int result;
//   wg_config_t *conf;
//   wg_device_t *device;
//   sock_udp_ep_t local_ep;
//   uint8_t privkey[NOISE_PRIVATE_KEY_LEN];
//   size_t privkey_len = sizeof(privkey);
//   size_t inlen;
//   netdev_t *dev;
//
//   dev = netif->dev;
//
//   assert(netif != NULL);
//   assert(dev != NULL);
//   assert(dev->context != NULL);
//
//   // init the noise
//   wg_noise_init();
//
//   // TODO: should we reinit if it fails???
//   if (!netif || !dev || !dev->context) {
//     return -EINVAL;
//   }
//
//   // replace context with the wireguard device
//   conf = (wg_config_t *)dev->context;
//   dev->context = NULL;
//
//   inlen = strlen(conf->privkey);
//   if (base64_decode(conf->privkey, inlen, privkey, &privkey_len) !=
//           BASE64_SUCCESS ||
//       privkey_len != NOISE_PRIVATE_KEY_LEN) {
//     return -EINVAL;
//   }
//
//   local_ep = (sock_udp_ep_t)SOCK_IPV6_EP_ANY;
//   local_ep.port = conf->listen_port;
//   if (conf->bind_netif) {
//     if ((local_ep.netif = netif_get_id(&conf->bind_netif->netif)) < 0) {
//       local_ep.netif = SOCK_ADDR_ANY_NETIF;
//     }
//   }
//
//   // TODO: malloc for now, depend on the design and number of allocated
//   netif,
//   // change to static, does calloc dies after out of scope
//   device = (wg_device_t *)calloc(1, sizeof(wg_device_t));
//   if (!device) {
//     return -ENOMEM;
//   }
//
//   if ((result = sock_udp_create(&device->udp, &local_ep, NULL, 0)) < 0) {
//     // TODO: rm this free if use static memory later
//     free(device);
//     return result;
//   }
//
//   // TODO: do we need to enable checksum of some kind??
//
// #if IS_USED(MODULE_GNRC_NETIF_6LO)
//   // we disable fragmentation for this device, as the tunneling udp socket
//   will
//   // handle this
//   netif.sixlo.max_frag_size = 0;
// #endif /* IS_USED(MODULE_GNRC_NETIF_6LO) */
//   device->netif = netif;
//
//   // Per-wireguard netif/device setup
//   uint32_t t1 = ztimer_now(ZTIMER_MSEC);
//   if (!wg_device_init(device, privkey)) {
//     sock_udp_close(&device->udp);
//     // TODO: rm this free if use static memory later
//     free(device);
//     device = NULL;
//     return -EINVAL;
//   }
//   uint32_t t2 = ztimer_now(ZTIMER_MSEC);
//   printf("Device init took %" PRIi32 "ms\r\n", (t2 - t1));
//
//   // TODO: add code to set up the netdev
//   netif->dev->context = device;
//   // We set up no state flags here - caller should set them
//   // TODO: where is the linkup flag set
//   netif->flags = 0;
//   netif->l2addr_len = 0;
//   // TODO: is is the right configuraton for the MTU
//   netif->ipv6.mtu = WG_MTU;
//   // set up the function for sending packet on the netif
//   netif->ops = &wg_ops;
//   sock_udp_set_cb(&device->udp, wg_receive, device);
//
//   // Start a periodic timer for this wireguard device
//   ztimer_periodic_init(ZTIMER_MSEC, &device->timer, wg_periodic_cleanup,
//   device,
//                        WG_TIMER_MSECS);
//   ztimer_periodic_start(&device->timer);
//
//   return 0;
// }

// static int wg_send(gnrc_netif_t *netif, gnrc_pktsnip_t *pkt) {
//   wg_device_t *device = (wg_device_t *)netif->dev->context;
//   // extract the IPv6 packet from pktsnip
//   gnrc_pktsnip_t *tmp_pkt;
//   ipv6_hdr_t *ipv6_hdr;
//
//   // TODO: handle unicast packet for now, multicast packets will be done
//   later
//   // TODO: this is maybe incorrect comeback later,
//   if (pkt->type != GNRC_NETTYPE_IPV6) {
//     DEBUG("ipv6: unexpected packet type\n");
//     gnrc_pktbuf_release(pkt);
//     return -EINVAL;
//   }
//   tmp_pkt = gnrc_pktbuf_start_write(pkt);
//   if (tmp_pkt == NULL) {
//     DEBUG("ipv6: unable to get write access to IPv6 header, dropping
//     packet\n"); gnrc_pktbuf_release(pkt); return -EINVAL;
//   }
//   pkt = tmp_pkt;
//   ipv6_hdr = pkt->data;
//
//   // send to peer that matches dest IP
//   wg_peer_t *peer = peer_lookup_by_allowed_ip(device, &ipv6_hdr->src);
//   if (peer) {
//     return wg_send_to_peer(netif, pkt, &ipv6_hdr->src, peer);
//   } else {
//     // TODO: send icmp error
//     return -ENOKEY;
//   }
// }
//
// static void wg_receive(sock_udp_t *sock, sock_async_flags_t flags, void *arg)
// {
//   (void)sock;
//   (void)flags;
//   (void)arg;
//   return;
// }
//
// // destroy keypair periodically
// static bool wg_periodic_cleanup(void *arg) {
//   (void)arg;
//   return true;
// }
//
// static int wg_send_to_peer(gnrc_netif_t *netif, gnrc_pktsnip_t *pkt,
//                            const ipv6_addr_t *ipaddr, wg_peer_t *peer) {
//   // send ip packet over the interface, require packet encryption
//   struct msg_transport_data *hdr;
//   int result;
//   size_t unpadded_len;
//   size_t padded_len;
//   size_t header_len = 16;
//   uint8_t *dst;
//   uint32_t now;
//   wg_keypair_t *keypair = &peer->curr_keypair;
//
//   // Note: We may not be able to use the current keypair if we haven't
//   received
//   // data, may need to resort to using previous keypair
//   if (keypair->valid && (!keypair->initiator) && (keypair->last_rx == 0)) {
//     keypair = &peer->prev_keypair;
//   }
//
//   if (!(keypair->valid && (keypair->initiator || keypair->last_rx != 0))) {
//     // TODO: send ICMP error
//     return -ENOKEY;
//   }
//
//   return 0;
// }
