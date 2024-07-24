#include "net/sock/tcp.h"
#include "net/af.h"
#include "net/ipv6/addr.h"
#include <stdio.h>

sock_tcp_t sock;
#define SOCK_QUEUE_LEN (1U)

sock_tcp_t sock_queue[SOCK_QUEUE_LEN];
uint8_t buf[128];

int tcp_server(int argc, char **argv) {
  (void)argc;
  (void)argv;
  sock_tcp_ep_t local = SOCK_IPV6_EP_ANY;
  sock_tcp_queue_t queue;

  local.port = 12345;

  if (sock_tcp_listen(&queue, &local, sock_queue, SOCK_QUEUE_LEN, 0) < 0) {
    puts("Error creating listening queue");
    return 1;
  }
  puts("Listening on port 12345");
  while (1) {
    sock_tcp_t *sock;

    if (sock_tcp_accept(&queue, &sock, SOCK_NO_TIMEOUT) < 0) {
      puts("Error accepting new sock");
    } else {
      int read_res = 0;

      puts("Reading data");
      while (read_res >= 0) {
        read_res = sock_tcp_read(sock, &buf, sizeof(buf), SOCK_NO_TIMEOUT);
        if (read_res <= 0) {
          puts("Disconnected");
          break;
        } else {
          int write_res;
          printf("Read: \"");
          for (int i = 0; i < read_res; i++) {
            printf("%c", buf[i]);
          }
          puts("\"");
          if ((write_res = sock_tcp_write(sock, &buf, read_res)) < 0) {
            puts("Errored on write, finished server loop");
            break;
          }
        }
      }
      sock_tcp_disconnect(sock);
    }
  }
  sock_tcp_stop_listen(&queue);
  return 0;
}

int tcp_send(int argc, char **argv) {
  (void)argc;
  (void)argv;
  int res;
  sock_tcp_ep_t remote = SOCK_IPV6_EP_ANY;
  puts("fuck u\n");

  remote.port = 12345;
  ipv6_addr_from_str((ipv6_addr_t *)&remote.addr, "fe80::1880:5eff:feed:6e49");
  if (sock_tcp_connect(&sock, &remote, 0, 0) < 0) {
    puts("Error connecting sock");
    return 1;
  }
  puts("Sending \"Hello!\"");
  if ((res = sock_tcp_write(&sock, "Hello!", sizeof("Hello!"))) < 0) {
    puts("Errored on write");
  } else {
    if ((res = sock_tcp_read(&sock, &buf, sizeof(buf), SOCK_NO_TIMEOUT)) <= 0) {
      puts("Disconnected");
    }
    printf("Read: \"");
    for (int i = 0; i < res; i++) {
      printf("%c", buf[i]);
    }
    puts("\"");
  }
  sock_tcp_disconnect(&sock);
  return res;
}
