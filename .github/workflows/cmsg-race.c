/* Demonstrates the bind-before-options race avahi's socket.c has on BSD
 * kernels (NetBSD, FreeBSD, macOS): UDP control messages are built when a
 * datagram is queued to the socket, with the options set at that moment,
 * and a multicast datagram is queued to every socket bound to the port.
 *
 *   cmsg-race late    bind 5353, wait, then set IP_PKTINFO/IP_RECVTTL
 *                     (avahi's order, window widened to WAIT seconds)
 *   cmsg-race early   set the options, then bind (the fix)
 *
 * The program joins 224.0.0.251 and sends its own multicast datagrams
 * from a second socket during the wait, so it needs no other traffic.
 * Prints one line per datagram; exits 1 if any datagram arrived without
 * the requested control messages. On Linux both modes print all-present,
 * because Linux builds control messages at recvmsg(). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define WAIT 3
#define COUNT 10
#define RECV_TIMEOUT 10   /* seconds without traffic before giving up */

static void set_recv_options(int fd) {
    int yes = 1;
#ifdef IP_PKTINFO
    if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &yes, sizeof(yes)) < 0) { perror("IP_PKTINFO"); exit(2); }
#elif defined(IP_RECVDSTADDR)
    if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &yes, sizeof(yes)) < 0) { perror("IP_RECVDSTADDR"); exit(2); }
#endif
#ifdef IP_RECVTTL
    if (setsockopt(fd, IPPROTO_IP, IP_RECVTTL, &yes, sizeof(yes)) < 0) { perror("IP_RECVTTL"); exit(2); }
#endif
}

/* A minimal DNS query header (id 0, no questions) to 224.0.0.251:5353,
 * looped back by the kernel to every local socket on the port. */
static void send_traffic(int count) {
    int sfd, i;
    unsigned char yes = 1;
    unsigned char hdr[12] = { 0 };
    struct sockaddr_in to;

    if ((sfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) { perror("socket"); exit(2); }
    if (setsockopt(sfd, IPPROTO_IP, IP_MULTICAST_LOOP, &yes, sizeof(yes)) < 0) { perror("IP_MULTICAST_LOOP"); exit(2); }
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(5353);
    to.sin_addr.s_addr = inet_addr("224.0.0.251");
    for (i = 0; i < count; i++) {
        if (sendto(sfd, hdr, sizeof(hdr), 0, (struct sockaddr *) &to, sizeof(to)) < 0) perror("sendto");
        usleep(1000000 / 2);
    }
    close(sfd);
}

int main(int argc, char *argv[]) {
    int fd, yes = 1, early, n, missing = 0;
    struct sockaddr_in local;

    if (argc != 2 || (strcmp(argv[1], "late") && strcmp(argv[1], "early"))) {
        fprintf(stderr, "usage: %s late|early\n", argv[0]);
        return 2;
    }
    early = !strcmp(argv[1], "early");

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) { perror("socket"); return 2; }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) { perror("SO_REUSEADDR"); return 2; }
#ifdef SO_REUSEPORT
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes)) < 0) { perror("SO_REUSEPORT"); return 2; }
#endif
    if (early)
        set_recv_options(fd);

    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = htons(5353);
    if (bind(fd, (struct sockaddr *) &local, sizeof(local)) < 0) { perror("bind"); return 2; }

    {
        struct ip_mreq mreq;
        memset(&mreq, 0, sizeof(mreq));
        mreq.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);
        if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) { perror("IP_ADD_MEMBERSHIP"); return 2; }
    }

    /* avahi's order: the socket is bound and receiving multicast copies
     * before the options are set. The sleep widens that window, and the
     * sender below supplies the datagrams that queue up in it. */
    printf("%s: bound; sending %d multicast datagrams over %d s before the options are set\n", argv[1], WAIT * 2, WAIT);
    send_traffic(WAIT * 2);
    if (!early)
        set_recv_options(fd);

    {
        struct timeval tv = { RECV_TIMEOUT, 0 };
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) { perror("SO_RCVTIMEO"); return 2; }
    }

    for (n = 0; n < COUNT; n++) {
        char buf[9000];
        size_t aux[1024 / sizeof(size_t)];
        struct sockaddr_in from;
        struct iovec io = { buf, sizeof(buf) };
        struct msghdr msg;
        struct cmsghdr *c;
        int have_addr = 0, have_ttl = 0;
        ssize_t l;

        memset(&msg, 0, sizeof(msg));
        msg.msg_name = &from; msg.msg_namelen = sizeof(from);
        msg.msg_iov = &io; msg.msg_iovlen = 1;
        msg.msg_control = aux; msg.msg_controllen = sizeof(aux);
        if ((l = recvmsg(fd, &msg, 0)) < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("no datagram for %d s; %d received so far\n", RECV_TIMEOUT, n);
                break;
            }
            perror("recvmsg"); return 2;
        }
        for (c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
            if (c->cmsg_level != IPPROTO_IP) continue;
#ifdef IP_PKTINFO
            if (c->cmsg_type == IP_PKTINFO) have_addr = 1;
#endif
#ifdef IP_RECVDSTADDR
            if (c->cmsg_type == IP_RECVDSTADDR) have_addr = 1;
#endif
#ifdef IP_RECVTTL
            if (c->cmsg_type == IP_RECVTTL) have_ttl = 1;
#endif
#ifdef IP_TTL
            if (c->cmsg_type == IP_TTL) have_ttl = 1;
#endif
        }
        printf("datagram %2d from %s %5zd bytes  addr cmsg: %s  ttl cmsg: %s\n", n + 1,
               inet_ntoa(from.sin_addr), l, have_addr ? "yes" : "NO", have_ttl ? "yes" : "NO");
        if (!have_addr || !have_ttl) missing++;
    }
    if (n == 0) {
        printf("%s: no mDNS traffic on this host, nothing to show\n", argv[1]);
        return 3;
    }
    printf("%s: %d of %d datagrams without the requested control messages\n", argv[1], missing, n);
    return missing ? 1 : 0;
}
