// Copyright (c) 2013-2023 Cesanta Software Limited
// SPDX-License-Identifier: GPL-2.0-only or commercial

#include "mip.h"
#if defined(MIP_USER_CONFIG)
#include MIP_USER_CONFIG
#endif
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MIP_LOG(x) \
  printf x;        \
  putchar('\n')
#define MIP_ERROR(x) MIP_LOG(x)
#define MIP_INFO(x) MIP_LOG(x)
#define MIP_DEBUG(x) MIP_LOG(x)
#define MIP_VERBOSE(x) MIP_LOG(x)

#define MIP_EPHEMERAL_PORT_BASE 32768
#define PDIFF(a, b) ((size_t) (((char *) (b)) - ((char *) (a))))

#ifndef MIP_TCP_KEEPALIVE_MS
#define MIP_TCP_KEEPALIVE_MS 45000  // TCP keep-alive period, ms
#endif

#define MIP_TCP_ACK_MS 150  // Timeout for ACKing

#define MIP_U32(a, b, c, d)                                        \
  (((uint32_t) ((a) &255) << 24) | ((uint32_t) ((b) &255) << 16) | \
   ((uint32_t) ((c) &255) << 8) | (uint32_t) ((d) &255))

// For printing IPv4 addresses: printf("%d.%d.%d.%d\n", MIP_IPADDR_PARTS(&ip))
#define MIP_U8P(ADDR) ((uint8_t *) (ADDR))
#define MIP_IPADDR_PARTS(ADDR) \
  MIP_U8P(ADDR)[0], MIP_U8P(ADDR)[1], MIP_U8P(ADDR)[2], MIP_U8P(ADDR)[3]
#define mip_htons(x) mip_ntohs(x)
#define mip_htonl(x) mip_ntohl(x)

#pragma pack(push, 1)

struct str {
  const char *ptr;
  size_t len;
};

struct lcp {
  uint8_t addr, ctrl, proto[2], code, id, len[2];
};

struct eth {
  uint8_t dst[6];  // Destination MAC address
  uint8_t src[6];  // Source MAC address
  uint16_t type;   // Ethernet type
};

struct ip {
  uint8_t ver;    // Version
  uint8_t tos;    // Unused
  uint16_t len;   // Length
  uint16_t id;    // Unused
  uint16_t frag;  // Fragmentation
  uint8_t ttl;    // Time to live
  uint8_t proto;  // Upper level protocol
  uint16_t csum;  // Checksum
  uint32_t src;   // Source IP
  uint32_t dst;   // Destination IP
};

struct ip6 {
  uint8_t ver;      // Version
  uint8_t opts[3];  // Options
  uint16_t len;     // Length
  uint8_t proto;    // Upper level protocol
  uint8_t ttl;      // Time to live
  uint8_t src[16];  // Source IP
  uint8_t dst[16];  // Destination IP
};

struct icmp {
  uint8_t type;
  uint8_t code;
  uint16_t csum;
};

struct arp {
  uint16_t fmt;    // Format of hardware address
  uint16_t pro;    // Format of protocol address
  uint8_t hlen;    // Length of hardware address
  uint8_t plen;    // Length of protocol address
  uint16_t op;     // Operation
  uint8_t sha[6];  // Sender hardware address
  uint32_t spa;    // Sender protocol address
  uint8_t tha[6];  // Target hardware address
  uint32_t tpa;    // Target protocol address
};

struct tcp {
  uint16_t sport;  // Source port
  uint16_t dport;  // Destination port
  uint32_t seq;    // Sequence number
  uint32_t ack;    // Acknowledgement number
  uint8_t off;     // Data offset
  uint8_t flags;   // TCP flags
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
  uint16_t win;   // Window
  uint16_t csum;  // Checksum
  uint16_t urp;   // Urgent pointer
};

struct udp {
  uint16_t sport;  // Source port
  uint16_t dport;  // Destination port
  uint16_t len;    // UDP length
  uint16_t csum;   // UDP checksum
};

struct dhcp {
  uint8_t op, htype, hlen, hops;
  uint32_t xid;
  uint16_t secs, flags;
  uint32_t ciaddr, yiaddr, siaddr, giaddr;
  uint8_t hwaddr[208];
  uint32_t magic;
  uint8_t options[32];
};

#pragma pack(pop)

struct pkt {
  struct str raw;  // Raw packet data
  struct str pay;  // Payload data
  struct eth *eth;
  struct llc *llc;
  struct arp *arp;
  struct ip *ip;
  struct ip6 *ip6;
  struct icmp *icmp;
  struct tcp *tcp;
  struct udp *udp;
  struct dhcp *dhcp;
};

struct mip_if *s_ifs;  // List of interfaces

///////////////////////////////// Socket API ///////////////////////////////
struct sock {
  struct sock *next;            // Next in s_socks
  int no;                       // Socket number
  int type;                     // SOCK_STREAM or SOCK_DGRAM
  int flags;                    // flags set by setsockopt(), SO_*
  struct sockaddr_in loc, rem;  // Local and remote addresses
  char *recv_buf;               // Receive buffer
  int size, len;                // Receive buffer size and bytes stored
  unsigned is_listening : 1;    // Socket is listening
  unsigned is_inbound : 1;      // Socket is inbound (accepted)
  unsigned is_outbound : 1;     // Socket is outbound
  unsigned is_connecting : 1;   // Socket is outbound, and is connecting
  unsigned is_readable : 1;     // Socket is readable
  unsigned is_error : 1;        // Socket has error
  uint32_t seq, ack;            // TCP seq/ack counters
  uint64_t timer;               // TCP keep-alive / ACK timer
  uint8_t mac[6];               // Peer MAC address
  uint8_t ttype;                // Timer type. 0: ack, 1: keep-alive
#define MIP_TTYPE_KEEPALIVE 0   // Connection is idle for long, send keepalive
#define MIP_TTYPE_ACK 1         // Peer sent us data, we have to ack it soon
  uint8_t tmiss;                // Number of keep-alive misses
  // struct mip_iobuf raw;         // For TLS only. Incoming raw data
};

static int s_next_sock_no = 7;  // Next socket number
static struct sock *s_socks;    // List of opened sockets

static int set_errno_and_return(int r) {
  if (r) errno = r, r = -1;  // On error, set errno and return code to -1
  return r;
}

int socket(int domain, int type, int protocol) {
  struct sock *s = NULL;
  if (domain == AF_INET && (s = calloc(1, sizeof(*s))) != NULL) {
    s->no = s_next_sock_no++;
    s->type = type;
    s->next = s_socks;
    s_socks = s;
  } else {
    errno = ENOMEM;
  }
  (void) protocol;
  return s == NULL ? -1 : s->no;
}

struct sock **mip_find(int sock) {
  struct sock **s = &s_socks;
  while (*s && (*s)->no != sock) s = &(*s)->next;
  return s;
}

int mip_close(int sock) {
  struct sock **s = mip_find(sock);
  if (*s) *s = (*s)->next;
  return *s ? 0 : -1;
}

int listen(int sock, int backlog) {
  (void) sock, (void) backlog;
  return 0;
}

int getsockname(int sock, struct sockaddr *addr, socklen_t *len) {
  (void) sock, (void) addr, (void) len;
  return -1;
}

int getpeername(int sock, struct sockaddr *addr, socklen_t *len) {
  (void) sock, (void) addr, (void) len;
  return -1;
}

ssize_t send(int sock, const void *buf, size_t len, int flags) {
  (void) sock, (void) buf, (void) len, (void) flags;
  return -1;
}

ssize_t recv(int sock, void *buf, size_t len, int flags) {
  (void) sock, (void) buf, (void) len, (void) flags;
  return -1;
}

ssize_t sendto(int sock, const void *buf, size_t len, int flags,
               const struct sockaddr *addr, socklen_t slen) {
  (void) sock, (void) buf, (void) len, (void) flags, (void) addr, (void) slen;
  return -1;
}

ssize_t recvfrom(int sock, void *buf, size_t len, int flags,
                 struct sockaddr *addr, socklen_t *slen) {
  (void) sock, (void) buf, (void) len, (void) flags, (void) addr, (void) slen;
  return -1;
}

int setsockopt(int sock, int lev, int opt, const void *val, socklen_t len) {
  (void) sock, (void) lev, (void) opt, (void) val, (void) len;
  return 0;
}

int accept(int sock, struct sockaddr *addr, socklen_t *len) {
  (void) sock, (void) addr, (void) len;
  return -1;
}

int connect(int sock, const struct sockaddr *addr, socklen_t len) {
  (void) sock, (void) addr, (void) len;
  return -1;
}

int bind(int sock, const struct sockaddr *addr, socklen_t len) {
  struct sock *s = NULL;
  if (len == sizeof(struct sockaddr_in) && (s = *mip_find(sock)) != NULL) {
    memcpy(&s->loc, addr, len);
    s->is_listening = 1;
  }
  return set_errno_and_return(s == NULL ? EINVAL : 0);
}

static void mip_poll(struct mip_if *, uint64_t);
int poll(struct pollfd fds[], nfds_t nfds, int timeout) {
  volatile uint64_t now = mip_millis(), until = now + timeout;
  while (mip_millis() < until) {
    mip_poll(s_ifs, mg_millis());
    for (int i = 0; i < nfds; i++) {
      struct sock *s = *mip_find(fds[i].fd);
      if (s->is_readable) fds[i].revents |= POLLIN;
      if (s->is_error) fds[i].revents |= POLLERR;
    }
  }
  // usleep(timeout * 1000);
  MIP_DEBUG(("n: %d, t: %d", nfds, timeout));
  return -1;
}
////////////////////////////////// End of socket API ////////////////////////

uint32_t mip_ntohl(uint32_t net) {
  uint8_t data[4] = {0, 0, 0, 0};
  memcpy(&data, &net, sizeof(data));
  return (((uint32_t) data[3]) << 0) | (((uint32_t) data[2]) << 8) |
         (((uint32_t) data[1]) << 16) | (((uint32_t) data[0]) << 24);
}

uint16_t mip_ntohs(uint16_t net) {
  uint8_t data[2] = {0, 0};
  memcpy(&data, &net, sizeof(data));
  return (uint16_t) ((uint16_t) data[1] | (((uint16_t) data[0]) << 8));
}

static void mkpay(struct pkt *pkt, void *p) {
  pkt->pay.ptr = (char *) p;
  pkt->pay.len = (size_t) (&pkt->raw.ptr[pkt->raw.len] - (char *) p);
}

static uint32_t csumup(uint32_t sum, const void *buf, size_t len) {
  const uint8_t *p = (const uint8_t *) buf;
  for (size_t i = 0; i < len; i++) sum += i & 1 ? p[i] : (uint32_t) (p[i] << 8);
  return sum;
}

static uint16_t csumfin(uint32_t sum) {
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return mip_htons(~sum & 0xffff);
}

static uint16_t ipcsum(const void *buf, size_t len) {
  uint32_t sum = csumup(0, buf, len);
  return csumfin(sum);
}

static size_t ether_output(struct mip_if *ifp, size_t len) {
  size_t min = 64;  // Pad short frames to 64 bytes (minimum Ethernet size)
  if (len < min) memset(ifp->tx_buf + len, 0, min - len), len = min;
  // mip_hexdump(ifp->tx_buf, len);
  size_t n = ifp->driver->tx(ifp->tx_buf, len, ifp);
  if (n == len) ifp->nsent++;
  return n;
}

static void arp_ask(struct mip_if *ifp, uint32_t ip) {
  struct eth *eth = (struct eth *) ifp->tx_buf;
  struct arp *arp = (struct arp *) (eth + 1);
  memset(eth->dst, 255, sizeof(eth->dst));
  memcpy(eth->src, ifp->mac, sizeof(eth->src));
  eth->type = mip_htons(0x806);
  memset(arp, 0, sizeof(*arp));
  arp->fmt = mip_htons(1), arp->pro = mip_htons(0x800), arp->hlen = 6,
  arp->plen = 4;
  arp->op = mip_htons(1), arp->tpa = ip, arp->spa = ifp->ip;
  memcpy(arp->sha, ifp->mac, sizeof(arp->sha));
  ether_output(ifp, PDIFF(eth, arp + 1));
}

static void onstatechange(struct mip_if *ifp) {
  if (ifp->state == MIP_STATE_READY) {
    MIP_INFO(("READY, IP: %d.%d.%d.%d", MIP_IPADDR_PARTS(&ifp->ip)));
    MIP_INFO(("       GW: %d.%d.%d.%d", MIP_IPADDR_PARTS(&ifp->gw)));
    if (ifp->lease_expire > ifp->now) {
      MIP_INFO(
          ("       Lease: %lld sec", (ifp->lease_expire - ifp->now) / 1000));
    }
    arp_ask(ifp, ifp->gw);
  } else if (ifp->state == MIP_STATE_UP) {
    MIP_ERROR(("Link up"));
    srand((unsigned int) mip_millis());
  } else if (ifp->state == MIP_STATE_DOWN) {
    MIP_ERROR(("Link down"));
  }
}

static struct ip *tx_ip(struct mip_if *ifp, uint8_t *mac_dst, uint8_t proto,
                        uint32_t ip_src, uint32_t ip_dst, size_t plen) {
  struct eth *eth = (struct eth *) ifp->tx_buf;
  struct ip *ip = (struct ip *) (eth + 1);
  memcpy(eth->dst, mac_dst, sizeof(eth->dst));
  memcpy(eth->src, ifp->mac, sizeof(eth->src));  // Use our MAC
  eth->type = mip_htons(0x800);
  memset(ip, 0, sizeof(*ip));
  ip->ver = 0x45;   // Version 4, header length 5 words
  ip->frag = 0x40;  // Don't fragment
  ip->len = mip_htons((uint16_t) (sizeof(*ip) + plen));
  ip->ttl = 64;
  ip->proto = proto;
  ip->src = ip_src;
  ip->dst = ip_dst;
  ip->csum = ipcsum(ip, sizeof(*ip));
  return ip;
}

static void tx_udp(struct mip_if *ifp, uint8_t *mac_dst, uint32_t ip_src,
                   uint16_t sport, uint32_t ip_dst, uint16_t dport,
                   const void *buf, size_t len) {
  struct ip *ip =
      tx_ip(ifp, mac_dst, 17, ip_src, ip_dst, len + sizeof(struct udp));
  struct udp *udp = (struct udp *) (ip + 1);
  // MIP_DEBUG(("UDP XX LEN %d %d", (int) len, (int) ifp->tx.len));
  udp->sport = sport;
  udp->dport = dport;
  udp->len = mip_htons((uint16_t) (sizeof(*udp) + len));
  udp->csum = 0;
  uint32_t cs = csumup(0, udp, sizeof(*udp));
  cs = csumup(cs, buf, len);
  cs = csumup(cs, &ip->src, sizeof(ip->src));
  cs = csumup(cs, &ip->dst, sizeof(ip->dst));
  cs += (uint32_t) (ip->proto + sizeof(*udp) + len);
  udp->csum = csumfin(cs);
  memmove(udp + 1, buf, len);
  // MIP_DEBUG(("UDP LEN %d %d", (int) len, (int) ifp->frame_len));
  ether_output(ifp, sizeof(struct eth) + sizeof(*ip) + sizeof(*udp) + len);
}

static void tx_dhcp(struct mip_if *ifp, uint8_t *mac_dst, uint32_t ip_src,
                    uint32_t ip_dst, uint8_t *opts, size_t optslen) {
  struct dhcp dhcp = {1, 1, 6, 0, 0, 0, 0, 0, 0, 0, 0, {0}, 0, {0}};
  dhcp.magic = mip_htonl(0x63825363);
  memcpy(&dhcp.hwaddr, ifp->mac, sizeof(ifp->mac));
  memcpy(&dhcp.xid, ifp->mac + 2, sizeof(dhcp.xid));
  memcpy(&dhcp.options, opts, optslen);
  tx_udp(ifp, mac_dst, ip_src, mip_htons(68), ip_dst, mip_htons(67), &dhcp,
         sizeof(dhcp));
}

static void tx_dhcp_request(struct mip_if *ifp, uint8_t *mac_dst,
                            uint32_t ip_src, uint32_t ip_dst) {
  uint8_t opts[] = {
      53, 1, 3,                 // Type: DHCP request
      55, 2, 1,   3,            // GW and mask
      12, 3, 'm', 'i', 'p',     // Host name: "mip"
      54, 4, 0,   0,   0,   0,  // DHCP server ID
      50, 4, 0,   0,   0,   0,  // Requested IP
      255                       // End of options
  };
  memcpy(opts + 14, &ip_dst, sizeof(ip_dst));
  memcpy(opts + 20, &ip_src, sizeof(ip_src));
  tx_dhcp(ifp, mac_dst, ip_src, ip_dst, opts, sizeof(opts));
}

static void tx_dhcp_discover(struct mip_if *ifp) {
  uint8_t mac[6] = {255, 255, 255, 255, 255, 255};
  uint8_t opts[] = {
      53, 1, 1,     // Type: DHCP discover
      55, 2, 1, 3,  // Parameters: ip, mask
      255           // End of options
  };
  tx_dhcp(ifp, mac, 0, 0xffffffff, opts, sizeof(opts));
  MIP_DEBUG(("DHCP discover sent"));
}

static struct sock *getpeer(struct pkt *pkt, bool lsn) {
  struct sock *s = NULL;
  for (s = s_socks; s != NULL; s = s->next) {
    if (s->type == SOCK_DGRAM && pkt->udp && s->loc.sin_port == pkt->udp->dport)
      break;
    if (s->type == SOCK_STREAM && pkt->tcp &&
        s->loc.sin_port == pkt->tcp->dport && lsn == s->is_listening &&
        (lsn || s->rem.sin_port == pkt->tcp->sport))
      break;
  }
  return s;
}

static void rx_arp(struct mip_if *ifp, struct pkt *pkt) {
  if (pkt->arp->op == mip_htons(1) && pkt->arp->tpa == ifp->ip) {
    // ARP request. Make a response, then send
    // MIP_DEBUG(("ARP op %d %M: %M", mip_ntohs(pkt->arp->op), mip_print_ip4,
    //          &pkt->arp->spa, mip_print_ip4, &pkt->arp->tpa));
    struct eth *eth = (struct eth *) ifp->tx_buf;
    struct arp *arp = (struct arp *) (eth + 1);
    memcpy(eth->dst, pkt->eth->src, sizeof(eth->dst));
    memcpy(eth->src, ifp->mac, sizeof(eth->src));
    eth->type = mip_htons(0x806);
    *arp = *pkt->arp;
    arp->op = mip_htons(2);
    memcpy(arp->tha, pkt->arp->sha, sizeof(pkt->arp->tha));
    memcpy(arp->sha, ifp->mac, sizeof(pkt->arp->sha));
    arp->tpa = pkt->arp->spa;
    arp->spa = ifp->ip;
    MIP_DEBUG(("ARP: tell %d.%d.%d.%d we're %d.%d.%d.%d",
               MIP_IPADDR_PARTS(&arp->tpa), MIP_IPADDR_PARTS(&ifp->ip)));
    ether_output(ifp, PDIFF(eth, arp + 1));
  } else if (pkt->arp->op == mip_htons(2)) {
    if (memcmp(pkt->arp->tha, ifp->mac, sizeof(pkt->arp->tha)) != 0) return;
    if (pkt->arp->spa == ifp->gw) {
      // Got response for the GW ARP request. Set ifp->gwmac
      memcpy(ifp->gwmac, pkt->arp->sha, sizeof(ifp->gwmac));
    } else {
#if 0
      struct mip_connection *c = getpeer(ifp->mgr, pkt, false);
      if (c != NULL && c->is_arplooking) {
        struct connstate *s = (struct connstate *) (c + 1);
        memcpy(s->mac, pkt->arp->sha, sizeof(s->mac));
        MIP_DEBUG(("%lu ARP resolved %M -> %M", c->id, mip_print_ip4, &c->rem.ip,
                  mip_print_mac, s->mac));
        c->is_arplooking = 0;
      }
#endif
    }
  }
}

static void rx_icmp(struct mip_if *ifp, struct pkt *pkt) {
  // MIP_DEBUG(("ICMP %d", (int) len));
  if (pkt->icmp->type == 8 && pkt->ip != NULL && pkt->ip->dst == ifp->ip) {
    size_t hlen = sizeof(struct eth) + sizeof(struct ip) + sizeof(struct icmp);
    size_t space = ifp->tx_len - hlen, plen = pkt->pay.len;
    if (plen > space) plen = space;
    struct ip *ip = tx_ip(ifp, pkt->eth->src, 1, ifp->ip, pkt->ip->src,
                          sizeof(struct icmp) + plen);
    struct icmp *icmp = (struct icmp *) (ip + 1);
    memset(icmp, 0, sizeof(*icmp));        // Set csum to 0
    memcpy(icmp + 1, pkt->pay.ptr, plen);  // Copy RX payload to TX
    icmp->csum = ipcsum(icmp, sizeof(*icmp) + plen);
    ether_output(ifp, hlen + plen);
  }
}

static void rx_dhcp_client(struct mip_if *ifp, struct pkt *pkt) {
  uint32_t ip = 0, gw = 0, mask = 0;
  uint8_t *p = pkt->dhcp->options,
          *end = (uint8_t *) &pkt->raw.ptr[pkt->raw.len];
  if (end < (uint8_t *) (pkt->dhcp + 1)) return;
  while (p + 1 < end && p[0] != 255) {  // Parse options
    if (p[0] == 1 && p[1] == sizeof(ifp->mask) && p + 6 < end) {  // Mask
      memcpy(&mask, p + 2, sizeof(mask));
    } else if (p[0] == 3 && p[1] == sizeof(ifp->gw) && p + 6 < end) {  // GW
      memcpy(&gw, p + 2, sizeof(gw));
      ip = pkt->dhcp->yiaddr;
    } else if (p[0] == 51 && p[1] == 4 && p + 6 < end) {  // Lease
      uint32_t lease = 0;
      memcpy(&lease, p + 2, sizeof(lease));
      ifp->lease_expire = ifp->now + mip_ntohl(lease) * 1000;
    }
    p += p[1] + 2;
  }
  if (ip && mask && gw && ifp->ip == 0) {
    memcpy(ifp->gwmac, pkt->eth->src, sizeof(ifp->gwmac));
    ifp->ip = ip, ifp->gw = gw, ifp->mask = mask;
    ifp->state = MIP_STATE_READY;
    onstatechange(ifp);
    tx_dhcp_request(ifp, pkt->eth->src, ip, pkt->dhcp->siaddr);
    uint64_t rand;
    mip_random(&rand, sizeof(rand));
    srand((unsigned int) (rand + mip_millis()));
  }
}

// Simple DHCP server that assigns a next IP address: ifp->ip + 1
static void rx_dhcp_server(struct mip_if *ifp, struct pkt *pkt) {
  uint8_t op = 0, *p = pkt->dhcp->options,
          *end = (uint8_t *) &pkt->raw.ptr[pkt->raw.len];
  if (end < (uint8_t *) (pkt->dhcp + 1)) return;
  // struct dhcp *req = pkt->dhcp;
  struct dhcp res = {2, 1, 6, 0, 0, 0, 0, 0, 0, 0, 0, {0}, 0, {0}};
  res.yiaddr = ifp->ip;
  ((uint8_t *) (&res.yiaddr))[3]++;                // Offer our IP + 1
  while (p + 1 < end && p[0] != 255) {             // Parse options
    if (p[0] == 53 && p[1] == 1 && p + 2 < end) {  // Message type
      op = p[2];
    }
    p += p[1] + 2;
  }
  if (op == 1 || op == 3) {         // DHCP Discover or DHCP Request
    uint8_t msg = op == 1 ? 2 : 5;  // Message type: DHCP OFFER or DHCP ACK
    uint8_t opts[] = {
        53, 1, msg,                 // Message type
        1,  4, 0,   0,   0,   0,    // Subnet mask
        54, 4, 0,   0,   0,   0,    // Server ID
        12, 3, 'm', 'i', 'p',       // Host name: "mip"
        51, 4, 255, 255, 255, 255,  // Lease time
        255                         // End of options
    };
    memcpy(&res.hwaddr, pkt->dhcp->hwaddr, 6);
    memcpy(opts + 5, &ifp->mask, sizeof(ifp->mask));
    memcpy(opts + 11, &ifp->ip, sizeof(ifp->ip));
    memcpy(&res.options, opts, sizeof(opts));
    res.magic = pkt->dhcp->magic;
    res.xid = pkt->dhcp->xid;
    // memcpy(ifp->gwmac, pkt->eth->src, sizeof(ifp->gwmac));
    tx_udp(ifp, pkt->eth->src, ifp->ip, mip_htons(67),
           op == 1 ? ~0U : res.yiaddr, mip_htons(68), &res, sizeof(res));
  }
}

static void rx_udp(struct mip_if *ifp, struct pkt *pkt) {
  (void) ifp, (void) pkt;
#if 0
  struct mip_connection *c = getpeer(ifp->mgr, pkt, true);
  if (c == NULL) {
    // No UDP listener on this port. Should send ICMP, but keep silent.
  } else if (c != NULL) {
    c->rem.port = pkt->udp->sport;
    c->rem.ip = pkt->ip->src;
    if (c->recv.len >= MIP_MAX_RECV_SIZE) {
      mip_error(c, "max_recv_buf_size reached");
    } else if (c->recv.size - c->recv.len < pkt->pay.len &&
               !mip_iobuf_resize(&c->recv, c->recv.len + pkt->pay.len)) {
      mip_error(c, "oom");
    } else {
      memcpy(&c->recv.buf[c->recv.len], pkt->pay.ptr, pkt->pay.len);
      c->recv.len += pkt->pay.len;
      mip_call(c, MIP_EV_READ, &pkt->pay.len);
    }
  }
#endif
}

static size_t tx_tcp(struct mip_if *ifp, uint8_t *dst_mac, uint32_t dst_ip,
                     uint8_t flags, uint16_t sport, uint16_t dport,
                     uint32_t seq, uint32_t ack, const void *buf, size_t len) {
  struct ip *ip =
      tx_ip(ifp, dst_mac, 6, ifp->ip, dst_ip, sizeof(struct tcp) + len);
  struct tcp *tcp = (struct tcp *) (ip + 1);
  memset(tcp, 0, sizeof(*tcp));
  if (buf != NULL && len) memmove(tcp + 1, buf, len);
  tcp->sport = sport;
  tcp->dport = dport;
  tcp->seq = seq;
  tcp->ack = ack;
  tcp->flags = flags;
  tcp->win = mip_htons(8192);
  tcp->off = (uint8_t) (sizeof(*tcp) / 4 << 4);
  uint32_t cs = 0;
  uint16_t n = (uint16_t) (sizeof(*tcp) + len);
  uint8_t pseudo[] = {0, ip->proto, (uint8_t) (n >> 8), (uint8_t) (n & 255)};
  cs = csumup(cs, tcp, n);
  cs = csumup(cs, &ip->src, sizeof(ip->src));
  cs = csumup(cs, &ip->dst, sizeof(ip->dst));
  cs = csumup(cs, pseudo, sizeof(pseudo));
  tcp->csum = csumfin(cs);
  MIP_DEBUG(("TCP %d.%d.%d.%d:%hu -> %d.%d.%d.%d:%hu fl %x len %d",
             MIP_IPADDR_PARTS(&ip->src), mip_ntohs(tcp->sport),
             MIP_IPADDR_PARTS(&ip->dst), mip_ntohs(tcp->dport), tcp->flags,
             (int) len));
  return ether_output(ifp, PDIFF(ifp->tx_buf, tcp + 1) + len);
}

static size_t tx_tcp_pkt(struct mip_if *ifp, struct pkt *pkt, uint8_t flags,
                         uint32_t seq, const void *buf, size_t len) {
  uint32_t delta = (pkt->tcp->flags & (TH_SYN | TH_FIN)) ? 1 : 0;
  return tx_tcp(ifp, pkt->eth->src, pkt->ip->src, flags, pkt->tcp->dport,
                pkt->tcp->sport, seq,
                mip_htonl(mip_ntohl(pkt->tcp->seq) + delta), buf, len);
}

static void settmout(struct sock *s, uint8_t type) {
  struct mip_if *ifp = s_ifs;
  // struct connstate *s = (struct connstate *) (c + 1);
  unsigned n = type == MIP_TTYPE_ACK ? MIP_TCP_ACK_MS : MIP_TCP_KEEPALIVE_MS;
  s->timer = ifp->now + n;
  s->ttype = type;
  MIP_VERBOSE(("%d %d -> %llx", s->no, type, s->timer));
}

static void rx_tcp(struct mip_if *ifp, struct pkt *pkt) {
  struct sock *s = getpeer(pkt, false);
#if 1
  MIP_INFO(("%d %hhu %d", s ? s->no : 0, pkt->tcp->flags, (int) pkt->pay.len));
#endif
  if (s != NULL && s->is_connecting && pkt->tcp->flags & (TH_SYN | TH_ACK)) {
    s->seq = mip_ntohl(pkt->tcp->ack), s->ack = mip_ntohl(pkt->tcp->seq) + 1;
    tx_tcp_pkt(ifp, pkt, TH_ACK, pkt->tcp->ack, NULL, 0);
    s->is_connecting = 0;  // Client connected
    s->is_readable = 1;    // Let poll() know
    settmout(s, MIP_TTYPE_KEEPALIVE);
  } else if (s != NULL && s->is_connecting) {
    tx_tcp_pkt(ifp, pkt, TH_RST | TH_ACK, pkt->tcp->ack, NULL, 0);
  } else if (s != NULL && pkt->tcp->flags & TH_RST) {
    s->is_readable = s->is_error = 1;
    // mip_error(s, "peer RST");  // RFC-1122 4.2.2.13
  } else if (s != NULL) {
#if 0
    MIP_DEBUG(("%lu %d %M:%hu -> %M:%hu", c->id, (int) pkt->raw.len,
              mip_print_ip4, &pkt->ip->src, mip_ntohs(pkt->tcp->sport),
              mip_print_ip4, &pkt->ip->dst, mip_ntohs(pkt->tcp->dport)));
    mip_hexdump(pkt->pay.buf, pkt->pay.len);
#endif
    s->tmiss = 0;                         // Reset missed keep-alive counter
    if (s->ttype == MIP_TTYPE_KEEPALIVE)  // Advance keep-alive timer
      settmout(s,
               MIP_TTYPE_KEEPALIVE);  // unless a former ACK timeout is pending
    // TODO
    // read_conn(c, pkt);  // Override timer with ACK timeout if needed
  } else if ((s = getpeer(pkt, true)) == NULL) {
    tx_tcp_pkt(ifp, pkt, TH_RST | TH_ACK, pkt->tcp->ack, NULL, 0);
  } else if (pkt->tcp->flags & TH_RST) {
    if (s->is_inbound) s->is_readable = s->is_error = 1;
    // mip_error(c, "peer RST");  // RFC-1122 4.2.2.13
    // ignore RST if not connected
  } else if (pkt->tcp->flags & TH_SYN) {
    // Use peer's source port as ISN, in order to recognise the handshake
    uint32_t isn = mip_htonl((uint32_t) mip_ntohs(pkt->tcp->sport));
    tx_tcp_pkt(ifp, pkt, TH_SYN | TH_ACK, isn, NULL, 0);
  } else if (pkt->tcp->flags & TH_FIN) {
    tx_tcp_pkt(ifp, pkt, TH_FIN | TH_ACK, pkt->tcp->ack, NULL, 0);
  } else if (mip_htonl(pkt->tcp->ack) == mip_htons(pkt->tcp->sport) + 1U) {
    s->is_readable = 1;  // New inbound connection
    MIP_DEBUG(("AAAAA"));
    // accept_conn(s, pkt);
  } else if (!s->is_inbound) {  // no peer
    tx_tcp_pkt(ifp, pkt, TH_RST | TH_ACK, pkt->tcp->ack, NULL, 0);
  } else {
    // MIP_DEBUG(("dropped silently.."));
  }
}

static void rx_ip(struct mip_if *ifp, struct pkt *pkt) {
  if (pkt->ip->proto == 1) {
    pkt->icmp = (struct icmp *) (pkt->ip + 1);
    if (pkt->pay.len < sizeof(*pkt->icmp)) return;
    mkpay(pkt, pkt->icmp + 1);
    rx_icmp(ifp, pkt);
  } else if (pkt->ip->proto == 17) {
    pkt->udp = (struct udp *) (pkt->ip + 1);
    if (pkt->pay.len < sizeof(*pkt->udp)) return;
    mkpay(pkt, pkt->udp + 1);
    MIP_DEBUG(("UDP %d.%d.%d.%d:%hu -> %d.%d.%d.%d:%hu len %d",
               MIP_IPADDR_PARTS(&pkt->ip->src), mip_ntohs(pkt->udp->sport),
               MIP_IPADDR_PARTS(&pkt->ip->dst), mip_ntohs(pkt->udp->dport),
               (int) pkt->pay.len));
    if (pkt->udp->dport == mip_htons(68)) {
      pkt->dhcp = (struct dhcp *) (pkt->udp + 1);
      mkpay(pkt, pkt->dhcp + 1);
      rx_dhcp_client(ifp, pkt);
    } else if (ifp->enable_dhcp_server && pkt->udp->dport == mip_htons(67)) {
      pkt->dhcp = (struct dhcp *) (pkt->udp + 1);
      mkpay(pkt, pkt->dhcp + 1);
      rx_dhcp_server(ifp, pkt);
    } else {
      rx_udp(ifp, pkt);
    }
  } else if (pkt->ip->proto == 6) {
    pkt->tcp = (struct tcp *) (pkt->ip + 1);
    if (pkt->pay.len < sizeof(*pkt->tcp)) return;
    mkpay(pkt, pkt->tcp + 1);
    uint16_t iplen = mip_ntohs(pkt->ip->len);
    uint16_t off = (uint16_t) (sizeof(*pkt->ip) + ((pkt->tcp->off >> 4) * 4U));
    if (iplen >= off) pkt->pay.len = (size_t) (iplen - off);
    MIP_DEBUG(("TCP %d.%d.%d.%d:%hu -> %d.%d.%d.%d:%hu len %u",
               MIP_IPADDR_PARTS(&pkt->ip->src), mip_ntohs(pkt->tcp->sport),
               MIP_IPADDR_PARTS(&pkt->ip->dst), mip_ntohs(pkt->tcp->dport),
               (int) pkt->pay.len));
    rx_tcp(ifp, pkt);
  }
}

static void rx_ip6(struct mip_if *ifp, struct pkt *pkt) {
  // MIP_DEBUG(("IP %d", (int) len));
  if (pkt->ip6->proto == 1 || pkt->ip6->proto == 58) {
    pkt->icmp = (struct icmp *) (pkt->ip6 + 1);
    if (pkt->pay.len < sizeof(*pkt->icmp)) return;
    mkpay(pkt, pkt->icmp + 1);
    rx_icmp(ifp, pkt);
  } else if (pkt->ip6->proto == 17) {
    pkt->udp = (struct udp *) (pkt->ip6 + 1);
    if (pkt->pay.len < sizeof(*pkt->udp)) return;
    // MIP_DEBUG(("  UDP %u %u -> %u", len, mip_htons(udp->sport),
    // mip_htons(udp->dport)));
    mkpay(pkt, pkt->udp + 1);
  }
}

static void mip_rx(struct mip_if *ifp, void *buf, size_t len) {
  const uint8_t broadcast[] = {255, 255, 255, 255, 255, 255};
  struct pkt pkt;
  memset(&pkt, 0, sizeof(pkt));
  pkt.raw.ptr = (char *) buf;
  pkt.raw.len = len;
  pkt.eth = (struct eth *) buf;
  if (pkt.raw.len < sizeof(*pkt.eth)) return;  // Truncated - runt?
  if (memcmp(pkt.eth->dst, ifp->mac, sizeof(pkt.eth->dst)) != 0 &&
      memcmp(pkt.eth->dst, broadcast, sizeof(pkt.eth->dst)) != 0) {
    // Not for us. Drop silently
  } else if (pkt.eth->type == mip_htons(0x806)) {
    pkt.arp = (struct arp *) (pkt.eth + 1);
    if (sizeof(*pkt.eth) + sizeof(*pkt.arp) > pkt.raw.len) return;  // Truncated
    rx_arp(ifp, &pkt);
  } else if (pkt.eth->type == mip_htons(0x86dd)) {
    pkt.ip6 = (struct ip6 *) (pkt.eth + 1);
    if (pkt.raw.len < sizeof(*pkt.eth) + sizeof(*pkt.ip6)) return;  // Truncated
    if ((pkt.ip6->ver >> 4) != 0x6) return;                         // Not IP
    mkpay(&pkt, pkt.ip6 + 1);
    rx_ip6(ifp, &pkt);
  } else if (pkt.eth->type == mip_htons(0x800)) {
    pkt.ip = (struct ip *) (pkt.eth + 1);
    if (pkt.raw.len < sizeof(*pkt.eth) + sizeof(*pkt.ip)) return;  // Truncated
    // Truncate frame to what IP header tells us
    if ((size_t) mip_ntohs(pkt.ip->len) + sizeof(struct eth) < pkt.raw.len) {
      pkt.raw.len = (size_t) mip_ntohs(pkt.ip->len) + sizeof(struct eth);
    }
    if (pkt.raw.len < sizeof(*pkt.eth) + sizeof(*pkt.ip)) return;  // Truncated
    if ((pkt.ip->ver >> 4) != 4) return;                           // Not IP
    mkpay(&pkt, pkt.ip + 1);
    rx_ip(ifp, &pkt);
  } else {
    MIP_DEBUG(("  Unknown eth type %x", mip_htons(pkt.eth->type)));
    // mip_hexdump(buf, len >= 16 ? 16 : len);
  }
}

// t: expiration time, prd: period, now: current time. Return true if expired
static bool mip_timer_expired(uint64_t *t, uint64_t prd, uint64_t now) {
  if (now + prd < *t) *t = 0;                    // Time wrapped? Reset timer
  if (*t == 0) *t = now + prd;                   // Firt poll? Set expiration
  if (*t > now) return false;                    // Not expired yet, return
  *t = (now - *t) > prd ? now + prd : *t + prd;  // Next expiration time
  return true;                                   // Expired, return true
}

static void mip_poll(struct mip_if *ifp, uint64_t uptime_ms) {
  if (ifp == NULL || ifp->driver == NULL) return;
  bool expired_1000ms = mip_timer_expired(&ifp->timer_1000ms, 1000, uptime_ms);
  ifp->now = uptime_ms;

  // Handle physical interface up/down status
  if (expired_1000ms && ifp->driver->up) {
    bool up = ifp->driver->up(ifp);
    bool current = ifp->state != MIP_STATE_DOWN;
    if (up != current) {
      ifp->state = up == false               ? MIP_STATE_DOWN
                   : ifp->enable_dhcp_client ? MIP_STATE_UP
                                             : MIP_STATE_READY;
      if (!up && ifp->enable_dhcp_client) ifp->ip = 0;
      onstatechange(ifp);
    }
  }
  if (ifp->state == MIP_STATE_DOWN) return;

  // If IP not configured, send DHCP
  if (ifp->ip == 0 && expired_1000ms) tx_dhcp_discover(ifp);

  // Read data from the network
  if (ifp->driver->rx != NULL) {  // Polling driver. We must call it
    size_t len =
        ifp->driver->rx(ifp->recv_queue.buf, ifp->recv_queue.size, ifp);
    if (len > 0) mip_rx(ifp, ifp->recv_queue.buf, len);
  } else {  // Interrupt-based driver. Fills recv queue itself
    char *buf;
    size_t len = mip_queue_next(&ifp->recv_queue, &buf);
    if (len > 0) {
      mip_rx(ifp, buf, len);
      mip_queue_del(&ifp->recv_queue, len);
    }
  }

#if 0
  // Process timeouts
  for (struct mip_connection *c = ifp->mgr->conns; c != NULL; c = c->next) {
    if (c->is_udp || c->is_listening) continue;
    if (c->is_connecting || c->is_resolving) continue;
    struct connstate *s = (struct connstate *) (c + 1);
    if (uptime_ms > s->timer) {
      if (s->ttype == MIP_TTYPE_ACK) {
        MIP_DEBUG(("%lu ack %x %x", c->id, s->seq, s->ack));
        tx_tcp(ifp, s->mac, c->rem.ip, TH_ACK, c->loc.port, c->rem.port,
               mip_htonl(s->seq), mip_htonl(s->ack), "", 0);
      } else {
        if (s->tmiss++ > 2) {
          mip_error(c, "keepalive");
        } else {
          MIP_DEBUG(("%lu keepalive", c->id));
          tx_tcp(ifp, s->mac, c->rem.ip, TH_ACK, c->loc.port, c->rem.port,
                 mip_htonl(s->seq - 1), mip_htonl(s->ack), "", 0);
        }
      }
      settmout(c, MIP_TTYPE_KEEPALIVE);
    }
  }
#endif
}

size_t mip_driver_rx(void *buf, size_t len, struct mip_if *ifp) {
  (void) buf, (void) len, (void) ifp;
  return 0;
}

#if 0
static void send_syn(struct mip_connection *c) {
  struct connstate *s = (struct connstate *) (c + 1);
  uint32_t isn = mip_htonl((uint32_t) mip_ntohs(c->loc.port));
  struct mip_if *ifp = (struct mip_if *) c->mgr->priv;
  tx_tcp(ifp, s->mac, c->rem.ip, TH_SYN, c->loc.port, c->rem.port, isn, 0, NULL,
         0);
}

static struct mip_connection *accept_conn(struct mip_connection *lsn,
                                         struct pkt *pkt) {
  struct mip_connection *c = mip_alloc_conn(lsn->mgr);
  struct connstate *s = (struct connstate *) (c + 1);
  s->seq = mip_ntohl(pkt->tcp->ack), s->ack = mip_ntohl(pkt->tcp->seq);
  memcpy(s->mac, pkt->eth->src, sizeof(s->mac));
  settmout(c, MIP_TTYPE_KEEPALIVE);
  c->rem.ip = pkt->ip->src;
  c->rem.port = pkt->tcp->sport;
  MIP_DEBUG(("%lu accepted %M", c->id, mip_print_ip_port, &c->rem));
  LIST_ADD_HEAD(struct mip_connection, &lsn->mgr->conns, c);
  c->is_accepted = 1;
  c->is_hexdumping = lsn->is_hexdumping;
  c->pfn = lsn->pfn;
  c->loc = lsn->loc;
  c->pfn_data = lsn->pfn_data;
  c->fn = lsn->fn;
  c->fn_data = lsn->fn_data;
  mip_call(c, MIP_EV_OPEN, NULL);
  mip_call(c, MIP_EV_ACCEPT, NULL);
  return c;
}

long mip_io_send(struct mip_connection *c, const void *buf, size_t len) {
  struct mip_if *ifp = (struct mip_if *) c->mgr->priv;
  struct connstate *s = (struct connstate *) (c + 1);
  size_t max_headers_len = 14 + 24 /* max IP */ + 60 /* max TCP */;
  if (len + max_headers_len > ifp->tx_len) len = ifp->tx.len - max_headers_len;
  if (tx_tcp(ifp, s->mac, c->rem.ip, TH_PUSH | TH_ACK, c->loc.port, c->rem.port,
             mip_htonl(s->seq), mip_htonl(s->ack), buf, len) > 0) {
    s->seq += (uint32_t) len;
    if (s->ttype == MIP_TTYPE_ACK) settmout(c, MIP_TTYPE_KEEPALIVE);
  } else {
    return MIP_IO_ERR;
  }
  return (long) len;
}

long mip_io_recv(struct mip_connection *c, void *buf, size_t len) {
  struct connstate *s = (struct connstate *) (c + 1);
  if (s->raw.len == 0) return MIP_IO_WAIT;
  if (len > s->raw.len) len = s->raw.len;
  memcpy(buf, s->raw.buf, len);
  mip_iobuf_del(&s->raw, 0, len);
  MIP_DEBUG(("%lu", len));
  return (long) len;
}

static void read_conn(struct mip_connection *c, struct pkt *pkt) {
  struct connstate *s = (struct connstate *) (c + 1);
  struct mip_iobuf *io = c->is_tls ? &s->raw : &c->recv;
  uint32_t seq = mip_ntohl(pkt->tcp->seq);
  s->raw.align = c->recv.align;
  if (pkt->tcp->flags & TH_FIN) {
    s->ack = mip_htonl(pkt->tcp->seq) + 1, s->seq = mip_htonl(pkt->tcp->ack);
    c->is_closing = 1;
  } else if (pkt->pay.len == 0) {
    // TODO(cpq): handle this peer's ACK
  } else if (seq != s->ack) {
    uint32_t ack = (uint32_t) (mip_htonl(pkt->tcp->seq) + pkt->pay.len);
    if (s->ack == ack) {
      MIP_VERBOSE(("ignoring duplicate pkt"));
    } else {
      // TODO(cpq): peer sent us SEQ which we don't expect. Retransmit rather
      // than close this connection
      mip_error(c, "SEQ != ACK: %x %x %x", seq, s->ack, ack);
    }
  } else if (io->size - io->len < pkt->pay.len &&
             !mip_iobuf_resize(io, io->len + pkt->pay.len)) {
    mip_error(c, "oom");
  } else {
    // Copy TCP payload into the IO buffer. If the connection is plain text, we
    // copy to c->recv. If the connection is TLS, this data is encrypted,
    // therefore we copy that encrypted data to the s->raw iobuffer instead,
    // and then call mip_tls_recv() to decrypt it. NOTE: mip_tls_recv() will
    // call back mip_io_recv() which grabs raw data from s->raw
    memcpy(&io->buf[io->len], pkt->pay.ptr, pkt->pay.len);
    io->len += pkt->pay.len;

    MIP_DEBUG(("%lu SEQ %x -> %x", c->id, mip_htonl(pkt->tcp->seq), s->ack));
    // Advance ACK counter
    s->ack = (uint32_t) (mip_htonl(pkt->tcp->seq) + pkt->pay.len);
#if 0
    // Send ACK immediately
    MIP_DEBUG(("  imm ACK", c->id, mip_htonl(pkt->tcp->seq), s->ack));
    tx_tcp((struct mip_if *) c->mgr->priv, c->rem.ip, TH_ACK, c->loc.port,
           c->rem.port, mip_htonl(s->seq), mip_htonl(s->ack), "", 0);
#else
    // if not already running, setup a timer to send an ACK later
    if (s->ttype != MIP_TTYPE_ACK) settmout(c, MIP_TTYPE_ACK);
#endif

    if (c->is_tls) {
      // TLS connection. Make room for decrypted data in c->recv
      io = &c->recv;
      if (io->size - io->len < pkt->pay.len &&
          !mip_iobuf_resize(io, io->len + pkt->pay.len)) {
        mip_error(c, "oom");
      } else {
        // Decrypt data directly into c->recv
        long n = mip_tls_recv(c, &io->buf[io->len], io->size - io->len);
        if (n == MIP_IO_ERR) {
          mip_error(c, "TLS recv error");
        } else if (n > 0) {
          // Decrypted successfully - trigger MIP_EV_READ
          io->len += (size_t) n;
          mip_call(c, MIP_EV_READ, &n);
        }
      }
    } else {
      // Plain text connection, data is already in c->recv, trigger MIP_EV_READ
      mip_call(c, MIP_EV_READ, &pkt->pay.len);
    }
  }
}




int mip_mkpipe(struct mip_mgr *m, mip_event_handler_t fn, void *d, bool udp) {
  (void) m, (void) fn, (void) d, (void) udp;
  MIP_ERROR(("Not implemented"));
  return -1;
}

void mip_connect_resolved(struct mip_connection *c) {
  struct mip_if *ifp = (struct mip_if *) c->mgr->priv;
  c->is_resolving = 0;
  if (ifp->eport < MIP_EPHEMERAL_PORT_BASE) ifp->eport = MIP_EPHEMERAL_PORT_BASE;
  c->loc.ip = ifp->ip;
  c->loc.port = mip_htons(ifp->eport++);
  //MIP_DEBUG(("%lu %d.%d.%d.%d -> %d.%d.%d.%d", c->id, mip_print_ip_port, &c->loc, mip_print_ip_port,
  //          &c->rem));
  mip_call(c, MIP_EV_RESOLVE, NULL);
  if (((c->rem.ip & ifp->mask) == (ifp->ip & ifp->mask))) {
    // If we're in the same LAN, fire an ARP lookup. TODO(cpq): handle this!
    MIP_DEBUG(("%lu ARP lookup...", c->id));
    arp_ask(ifp, c->rem.ip);
    c->is_arplooking = 1;
  } else {
    struct connstate *s = (struct connstate *) (c + 1);
    memcpy(s->mac, ifp->gwmac, sizeof(ifp->gwmac));
    if (c->is_udp) {
      mip_call(c, MIP_EV_CONNECT, NULL);
    } else {
      send_syn(c);
      c->is_connecting = 1;
    }
  }
}

bool mip_open_listener(struct mip_connection *c, const char *url) {
  c->loc.port = mip_htons(mip_url_port(url));
  return true;
}

#if 0
static void write_conn(struct mip_connection *c) {
  long len = c->is_tls ? mip_tls_send(c, c->send.buf, c->send.len)
                       : mip_io_send(c, c->send.buf, c->send.len);
  if (len > 0) {
    mip_iobuf_del(&c->send, 0, (size_t) len);
    mip_call(c, MIP_EV_WRITE, &len);
  }
}

static void close_conn(struct mip_connection *c) {
  struct connstate *s = (struct connstate *) (c + 1);
  mip_iobuf_free(&s->raw);  // For TLS connections, release raw data
  if (c->is_udp == false && c->is_listening == false) {  // For TCP conns,
    struct mip_if *ifp =
        (struct mip_if *) c->mgr->priv;  // send TCP FIN
    tx_tcp(ifp, s->mac, c->rem.ip, TH_FIN | TH_ACK, c->loc.port, c->rem.port,
           mip_htonl(s->seq), mip_htonl(s->ack), NULL, 0);
  }
  mip_close_conn(c);
}

static bool can_write(struct mip_connection *c) {
  return c->is_connecting == 0 && c->is_resolving == 0 && c->send.len > 0 &&
         c->is_tls_hs == 0 && c->is_arplooking == 0;
}

void mip_mgr_poll(struct mip_mgr *mgr, int ms) {
  struct mip_connection *c, *tmp;
  uint64_t now = MIP_MILLIS();
  mip_poll((struct mip_if *) mgr->priv, now);
  mip_timer_poll(&mgr->timers, now);
  for (c = mgr->conns; c != NULL; c = tmp) {
    tmp = c->next;
    mip_call(c, MIP_EV_POLL, &now);
    MIP_VERBOSE(("%lu .. %c%c%c%c%c", c->id, c->is_tls ? 'T' : 't',
                c->is_connecting ? 'C' : 'c', c->is_tls_hs ? 'H' : 'h',
                c->is_resolving ? 'R' : 'r', c->is_closing ? 'C' : 'c'));
    if (c->is_tls_hs) mip_tls_handshake(c);
    if (can_write(c)) write_conn(c);
    if (c->is_draining && c->send.len == 0) c->is_closing = 1;
    if (c->is_closing) close_conn(c);
  }
  (void) ms;
}

bool mip_send(struct mip_connection *c, const void *buf, size_t len) {
  struct mip_if *ifp = (struct mip_if *) c->mgr->priv;
  bool res = false;
  if (ifp->ip == 0 || ifp->state != MIP_STATE_READY) {
    mip_error(c, "net down");
  } else if (c->is_udp) {
    struct connstate *s = (struct connstate *) (c + 1);
    tx_udp(ifp, s->mac, ifp->ip, c->loc.port, c->rem.ip, c->rem.port, buf, len);
    res = true;
  } else {
    res = mip_iobuf_add(&c->send, c->send.len, buf, len);
  }
  return res;
}
#endif
#endif

void mip_free(struct mip_if *ifp) {
  (void) ifp;
#if 0
  free(ifp->recv_queue.buf);
  free((char *) ifp->tx_buf);
#endif
}

void mip_init(struct mip_if *ifp) {
  // If MAC address is not set, make a random one
  if (ifp->mac[0] == 0 && ifp->mac[1] == 0 && ifp->mac[2] == 0 &&
      ifp->mac[3] == 0 && ifp->mac[4] == 0 && ifp->mac[5] == 0) {
    ifp->mac[0] = 0x02;  // Locally administered, unicast
    mip_random(&ifp->mac[1], sizeof(ifp->mac) - 1);
    MIP_INFO(("MAC not set. Generated random: %02x:%02x:%02x:%02x:%02x:%02x",
              ifp->mac[0], ifp->mac[1], ifp->mac[2], ifp->mac[3], ifp->mac[4],
              ifp->mac[5]));
  }

  if (ifp->driver->init && !ifp->driver->init(ifp)) {
    MIP_ERROR(("driver init failed"));
  } else {
    size_t framesize = 1540;
    ifp->tx_buf = (uint8_t *) calloc(1, framesize), ifp->tx_len = framesize;
    ifp->recv_queue.size = ifp->driver->rx ? framesize : 8192;
    ifp->recv_queue.buf = (char *) calloc(1, ifp->recv_queue.size);
    ifp->timer_1000ms = mip_millis();
    // mgr->priv = ifp;
    // ifp->mgr = mgr;
    //  mgr->extraconnsize = sizeof(struct connstate);
    if (ifp->ip == 0) ifp->enable_dhcp_client = true;
    memset(ifp->gwmac, 255, sizeof(ifp->gwmac));  // Set to broadcast
    mip_random(&ifp->eport, sizeof(ifp->eport));  // Random from 0 to 65535
    ifp->eport |= MIP_EPHEMERAL_PORT_BASE;        // Random from
                                            // MIP_EPHEMERAL_PORT_BASE to 65535
    ifp->next = s_ifs;
    s_ifs = ifp;
  }
}

// This function executes in interrupt context, thus it should copy data
// somewhere fast. Note that newlib's malloc is not thread safe, thus use
// our lock-free queue with preallocated buffer to copy data and return asap
void mip_qwrite(void *buf, size_t len, struct mip_if *ifp) {
  char *p;
  if (mip_queue_book(&ifp->recv_queue, &p, len) >= len) {
    memcpy(p, buf, len);
    mip_queue_add(&ifp->recv_queue, len);
    ifp->nrecv++;
  } else {
    ifp->ndrop++;
  }
}

#if defined(__GNUC__) || defined(__clang__)
#define MG_MEMORY_BARRIER() __sync_synchronize()
#elif defined(_MSC_VER) && _MSC_VER >= 1700
#define MG_MEMORY_BARRIER() MemoryBarrier()
#elif !defined(MG_MEMORY_BARRIER)
#define MG_MEMORY_BARRIER()
#endif

// Every message in a queue is prepended by a 32-bit message length (ML).
// If ML is 0, then it is the end, and reader must wrap to the beginning.
//
//  Queue when q->tail <= q->head:
//  |----- free -----| ML | message1 | ML | message2 |  ----- free ------|
//  ^                ^                               ^                   ^
// buf              tail                            head                len
//
//  Queue when q->tail > q->head:
//  | ML | message2 |----- free ------| ML | message1 | 0 |---- free ----|
//  ^               ^                 ^                                  ^
// buf             head              tail                               len

void mip_queue_init(struct mip_queue *q, char *buf, size_t size) {
  q->size = size;
  q->buf = buf;
  q->head = q->tail = 0;
}

static size_t mip_queue_read_len(struct mip_queue *q) {
  uint32_t n = 0;
  MG_MEMORY_BARRIER();
  memcpy(&n, q->buf + q->tail, sizeof(n));
  assert(q->tail + n + sizeof(n) <= q->size);
  return n;
}

static void mip_queue_write_len(struct mip_queue *q, size_t len) {
  uint32_t n = (uint32_t) len;
  memcpy(q->buf + q->head, &n, sizeof(n));
  MG_MEMORY_BARRIER();
}

size_t mip_queue_book(struct mip_queue *q, char **buf, size_t len) {
  size_t space = 0, hs = sizeof(uint32_t) * 2;  // *2 is for the 0 marker
  if (q->head >= q->tail && q->head + len + hs <= q->size) {
    space = q->size - q->head - hs;  // There is enough space
  } else if (q->head >= q->tail && q->tail > hs) {
    mip_queue_write_len(q, 0);  // Not enough space ahead
    q->head = 0;                // Wrap head to the beginning
  }
  if (q->head + hs + len < q->tail) space = q->tail - q->head - hs;
  if (buf != NULL) *buf = q->buf + q->head + sizeof(uint32_t);
  return space;
}

size_t mip_queue_next(struct mip_queue *q, char **buf) {
  size_t len = 0;
  if (q->tail != q->head) {
    len = mip_queue_read_len(q);
    if (len == 0) {  // Zero (head wrapped) ?
      q->tail = 0;   // Reset tail to the start
      if (q->head > q->tail) len = mip_queue_read_len(q);  // Read again
    }
  }
  if (buf != NULL) *buf = q->buf + q->tail + sizeof(uint32_t);
  assert(q->tail + len <= q->size);
  return len;
}

void mip_queue_add(struct mip_queue *q, size_t len) {
  assert(len > 0);
  mip_queue_write_len(q, len);
  assert(q->head + sizeof(uint32_t) * 2 + len <= q->size);
  q->head += len + sizeof(uint32_t);
}

void mip_queue_del(struct mip_queue *q, size_t len) {
  q->tail += len + sizeof(uint32_t);
  assert(q->tail + sizeof(uint32_t) <= q->size);
}
