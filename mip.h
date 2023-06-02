// Copyright (c) 2013-2023 Cesanta Software Limited
// SPDX-License-Identifier: GPL-2.0-only or commercial

#ifndef MIP_H
#define MIP_H

#include <stdbool.h>    // For bool
#include <stddef.h>     // For size_t
#include <stdint.h>     // For uint_xxxx
#include <sys/types.h>  // For ssize_t

/////////////////////////////     BSD socket API     ////////////////////////
typedef unsigned socklen_t;
typedef int nfds_t;

struct sockaddr {
  char dummy;
};

struct in_addr {
  uint32_t s_addr;
};

struct sockaddr_in {
  uint8_t sin_family;
  uint16_t sin_port;
  struct in_addr sin_addr;
};

struct pollfd {
  int fd;
  short events, revents;
};

enum { POLLERR = 1, POLLHUP = 2, POLLIN = 4, POLLOUT = 8 };
enum { AF_INET = 1, AF_INET6 = 2 };
enum { IPPROTO_TCP = 6, IPPROTO_UDP = 17 };
enum { SOCK_STREAM = 1, SOCK_DGRAM = 2, SOL_SOCKET = 3 };
enum { TCP_NODELAY = 1, SO_BLOCKING = 3, SO_KEEPALIVE = 4, SO_REUSEADDR = 8 };

int socket(int domain, int type, int protocol);
int getsockname(int sock, struct sockaddr *, socklen_t *);
int getpeername(int sock, struct sockaddr *, socklen_t *);
ssize_t send(int sock, const void *buf, size_t len, int flags);
ssize_t recv(int sock, void *buf, size_t len, int flags);
ssize_t sendto(int sock, const void *buf, size_t len, int flags,
               const struct sockaddr *addr, socklen_t);
ssize_t recvfrom(int sock, void *buf, size_t len, int flags,
                 struct sockaddr *addr, socklen_t *);
int setsockopt(int sock, int lev, int opt, const void *val, socklen_t);
int accept(int sock, struct sockaddr *, socklen_t *);
int connect(int sock, const struct sockaddr *, socklen_t);
int bind(int sock, const struct sockaddr *, socklen_t);
int listen(int sock, int);
int poll(struct pollfd fds[], nfds_t nfds, int timeout);
int mip_close(int sock);
#define closesocket(x) mip_close(x)

//////////     Single producer, single consumer non-blocking queue //////////
// Producer:
//    char *buf;
//    while (mip_queue_book(q, &buf) < len) WAIT();  // Wait for space
//    memcpy(buf, my_data, len);   // Copy data to the queue
//    mip_queue_add(q, len);
//
// Consumer:
//    char *buf;
//    while ((len = mip_queue_get(q, &buf)) == 0) WAIT();
//    mip_hexdump(buf, len); // Handle message
//    mip_queue_del(q, len);
//
struct mip_queue {
  char *buf;
  size_t size;
  volatile size_t tail;
  volatile size_t head;
};

void mip_queue_init(struct mip_queue *, char *, size_t);        // Init queue
size_t mip_queue_book(struct mip_queue *, char **buf, size_t);  // Reserve space
void mip_queue_add(struct mip_queue *, size_t);      // Add new message
size_t mip_queue_next(struct mip_queue *, char **);  // Get oldest message
void mip_queue_del(struct mip_queue *, size_t);      // Delete oldest message

/////////////////////////////     MIP API   /////////////////////////////////

struct mip_if;  // MIP network interface

struct mip_driver {
  bool (*init)(struct mip_if *);                         // Init driver
  size_t (*tx)(const void *, size_t, struct mip_if *);   // Transmit frame
  size_t (*rx)(void *buf, size_t len, struct mip_if *);  // Receive frame
  bool (*up)(struct mip_if *);                           // Up/down status
};

// Network interface
struct mip_if {
  uint8_t mac[6];             // MAC address. Must be set to a valid MAC
  uint32_t ip, mask, gw;      // IP address, mask, default gateway
  bool enable_dhcp_client;    // Enable DCHP client
  bool enable_dhcp_server;    // Enable DCHP server
  struct mip_driver *driver;  // Low level driver
  void *driver_data;          // Driver-specific data
  // struct mip_mgr *mgr;              // Mongoose event manager
  struct mip_queue recv_queue;  // Receive queue
  uint8_t *tx_buf;              // Buffer for output frames
  size_t tx_len;                // Size of the output buffer

  // Internal state, user can use it but should not change it
  struct mip_if *next;      // Next in the list
  uint8_t gwmac[6];         // Router's MAC
  uint64_t now;             // Current time
  uint64_t timer_1000ms;    // 1000 ms timer: for DHCP and link state
  uint64_t lease_expire;    // Lease expiration time
  uint16_t eport;           // Next ephemeral port
  volatile uint32_t ndrop;  // Number of received, but dropped frames
  volatile uint32_t nrecv;  // Number of received frames
  volatile uint32_t nsent;  // Number of transmitted frames
  volatile uint32_t nerr;   // Number of driver errors
  uint8_t state;            // Current state
#define MIP_STATE_DOWN 0    // Interface is down
#define MIP_STATE_UP 1      // Interface is up
#define MIP_STATE_READY 2   // Interface is up and has IP
};

void mip_init(struct mip_if *);
void mip_free(struct mip_if *);
// void mip_set_debug_fn(struct mip_if *, void (*fn)(int lev, const char *));
//  void mip_qwrite(void *buf, size_t len, struct mip_if *ifp);
//  size_t mip_qread(void *buf, struct mip_if *ifp);
//   conveniency rx function for IRQ-driven drivers
//  size_t mip_driver_rx(void *buf, size_t len, struct mip_if *ifp);

extern struct mip_driver mip_driver_stm32;
extern struct mip_driver mip_driver_w5500;
extern struct mip_driver mip_driver_tm4c;
extern struct mip_driver mip_driver_stm32h;
extern struct mip_driver mip_driver_imxrt;

// Drivers that require SPI, can use this SPI abstraction
struct mip_spi {
  void *spi;                        // Opaque SPI bus descriptor
  void (*begin)(void *);            // SPI begin: slave select low
  void (*end)(void *);              // SPI end: slave select high
  uint8_t (*txn)(void *, uint8_t);  // SPI transaction: write 1 byte, read reply
};

//////////////////////////////      MIP HAL    //////////////////////////////
uint64_t mip_millis(void);
void mip_random(void *buf, size_t len);

#endif  // MIP_H
