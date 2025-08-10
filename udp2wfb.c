
/*
 * udp2wfb.c
 *
 * Receive UDP payloads and inject them as raw 802.11 Data frames using libpcap
 * with a Radiotap header that sets HT MCS index and flags (GI/BW/LDPC/STBC).
 *
 * Usage:
 *   sudo ./udp2wfb <listen_ip> <port> <ifaces_csv> <mcs_idx> <gi> <bw> <ldpc> <stbc>
 *
 *   listen_ip   : IP address to bind UDP socket (e.g., 0.0.0.0)
 *   port        : UDP port to listen
 *   ifaces_csv  : comma-separated list of monitor-mode wlan interfaces (e.g., wlan0mon,wlan1mon)
 *   mcs_idx     : HT MCS index (0..31 typical)
 *   gi          : 0=long GI, 1=short GI
 *   bw          : channel width: 20, 40, 20L, 20U
 *   ldpc        : 0=BCC, 1=LDPC
 *   stbc        : number of STBC streams (0..3)
 *
 * Compile:
 *   gcc -O2 -Wall -o udp2wfb udp2wfb.c -lpcap
 *
 * Notes:
 * - Interfaces must already be in monitor mode and support radiotap injection.
 * - Whether the NIC actually honors MCS/GI/BW/LDPC/STBC is driver-dependent.
 * - No FEC/aggregation/QoS here; pure mirror transmit to all interfaces.
 */

#define _GNU_SOURCE
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <signal.h>

#define MAX_UDP_PAYLOAD   2000
#define MAX_INTERFACES    16
#define MAX_FRAME_SIZE    4096

/* Radiotap bit 19 => MCS field present */
#define RADIOTAP_PRESENT_MCS   (1u << 19)

/* Radiotap MCS-known bits (based on radiotap spec) */
#define MCS_KNOWN_BW    0x01  /* bandwidth field is known */
#define MCS_KNOWN_MCS   0x02  /* MCS index is known */
#define MCS_KNOWN_GI    0x04  /* guard interval is known */
#define MCS_KNOWN_FMT   0x08  /* HT format known (mixed/greenfield) - not used */
#define MCS_KNOWN_FEC   0x10  /* FEC type known */
#define MCS_KNOWN_STBC  0x20  /* STBC known */
/* (Ness bits omitted) */

/* Radiotap MCS-flags bits */
#define MCS_FLAGS_BW_MASK  0x03  /* 0=20,1=40,2=20L,3=20U */
#define MCS_FLAGS_SGI      0x04  /* Short GI */
#define MCS_FLAGS_HTGF     0x08  /* HT Greenfield (we keep 0 = mixed) */
#define MCS_FLAGS_LDPC     0x10  /* LDPC if set, else BCC */
#define MCS_FLAGS_STBC_SHIFT 5   /* bits 5..6 = STBC streams count (0..3) */

/* Minimal radiotap header + MCS fields (3 bytes) */
struct __attribute__((__packed__)) radiotap_ht_mcs {
    uint8_t  it_version;   /* 0 */
    uint8_t  it_pad;       /* 0 */
    uint16_t it_len;       /* total header length */
    uint32_t it_present;   /* bitmap of present fields */
    /* --- fields follow in order indicated by present --- */
    uint8_t  mcs_known;
    uint8_t  mcs_flags;
    uint8_t  mcs_index;
};

/* Minimal 802.11 Data frame header (no QoS, ToDS/FromDS=0) */
struct __attribute__((__packed__)) dot11_hdr {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seq_ctrl;
};

static volatile int g_running = 1;

static void on_sigint(int signo) {
    (void)signo;
    g_running = 0;
}

static void mac_set(uint8_t mac[6], uint8_t a0,uint8_t a1,uint8_t a2,uint8_t a3,uint8_t a4,uint8_t a5){
    mac[0]=a0; mac[1]=a1; mac[2]=a2; mac[3]=a3; mac[4]=a4; mac[5]=a5;
}

/* Build radiotap header with HT MCS fields */
size_t build_radiotap(uint8_t *buf, uint8_t mcs_idx, int gi, const char* bw_str, int ldpc, int stbc)
{
    struct radiotap_ht_mcs rt;
    memset(&rt, 0, sizeof(rt));
    rt.it_version = 0;
    rt.it_pad = 0;

    rt.it_len = htons(sizeof(rt)); /* total header length */
    rt.it_present = htonl(RADIOTAP_PRESENT_MCS);

    /* MCS known fields: BW, MCS, GI, FEC, STBC */
    rt.mcs_known = (uint8_t)(MCS_KNOWN_BW | MCS_KNOWN_MCS | MCS_KNOWN_GI | MCS_KNOWN_FEC | MCS_KNOWN_STBC);

    uint8_t flags = 0;

    /* BW mapping */
    if (strcmp(bw_str, "20") == 0) {
        flags |= 0; /* 20 MHz -> 0 */
    } else if (strcmp(bw_str, "40") == 0) {
        flags |= 1; /* 40 MHz -> 1 */
    } else if (strcasecmp(bw_str, "20L") == 0) {
        flags |= 2; /* 20 MHz lower -> 2 */
    } else if (strcasecmp(bw_str, "20U") == 0) {
        flags |= 3; /* 20 MHz upper -> 3 */
    } else {
        /* default: 20 MHz */
        flags |= 0;
    }

    if (gi) flags |= MCS_FLAGS_SGI;
    if (ldpc) flags |= MCS_FLAGS_LDPC;

    if (stbc < 0) stbc = 0;
    if (stbc > 3) stbc = 3;
    flags |= (uint8_t)(stbc << MCS_FLAGS_STBC_SHIFT);

    rt.mcs_flags = flags;
    rt.mcs_index = mcs_idx;

    memcpy(buf, &rt, sizeof(rt));
    return sizeof(rt);
}

/* Build a minimal 802.11 data header; addr1=broadcast, addr2/addr3 fixed */
size_t build_dot11(uint8_t *buf, uint16_t seq)
{
    struct dot11_hdr h = {0};
    /* Frame Control: Type=Data (0b10), Subtype=0, ToDS=0, FromDS=0 */
    /* FC format: |prot|type|subtype|toDS|fromDS|moreFrag|retry|pwrMgmt|moreData|wep|order| */
    h.frame_control = htons(0x0008); /* Data */
    h.duration = 0;

    /* Broadcast to receiver; source arbitrary locally administered MAC */
    mac_set(h.addr1, 0xff,0xff,0xff,0xff,0xff,0xff);
    mac_set(h.addr2, 0x02,0x11,0x22,0x33,0x44,0x55);
    mac_set(h.addr3, 0x02,0x11,0x22,0x33,0x44,0x55);

    /* Sequence control: upper 12 bits sequence number, lower 4 bits fragment number (0) */
    h.seq_ctrl = htons((uint16_t)((seq & 0x0fff) << 4));

    memcpy(buf, &h, sizeof(h));
    return sizeof(h);
}

/* Open all pcap handles for given interface list */
size_t open_pcap_handles(const char* ifaces_csv, pcap_t* handles[], char errbuf[PCAP_ERRBUF_SIZE], int immediate)
{
    char *csv = strdup(ifaces_csv);
    if (!csv) return 0;

    size_t count = 0;
    char *saveptr = NULL;
    for (char *tok = strtok_r(csv, ",", &saveptr); tok && count < MAX_INTERFACES; tok = strtok_r(NULL, ",", &saveptr)) {
        pcap_t *p = pcap_create(tok, errbuf);
        if (!p) {
            fprintf(stderr, "pcap_create(%s): %s\n", tok, errbuf);
            continue;
        }
        if (pcap_set_immediate_mode(p, immediate) != 0) {
            /* Not fatal */
        }
        if (pcap_activate(p) != 0) {
            fprintf(stderr, "pcap_activate(%s): %s\n", tok, pcap_geterr(p));
            pcap_close(p);
            continue;
        }
        handles[count++] = p;
        fprintf(stderr, "Opened %s for injection\n", tok);
    }
    free(csv);
    return count;
}

/* Send one payload as an 802.11 frame (radiotap + dot11 + payload) to ALL handles (mirror) */
int mirror_send(pcap_t* handles[], size_t n_handles,
                uint8_t mcs_idx, int gi, const char* bw,
                int ldpc, int stbc,
                const uint8_t* payload, size_t payload_len,
                uint16_t seq)
{
    uint8_t frame[MAX_FRAME_SIZE];
    size_t pos = 0;

    if (payload_len + 64 > sizeof(frame)) {
        fprintf(stderr, "Payload too large\n");
        return -1;
    }

    /* Radiotap */
    pos += build_radiotap(frame + pos, mcs_idx, gi, bw, ldpc, stbc);

    /* 802.11 header */
    pos += build_dot11(frame + pos, seq);

    /* Copy payload */
    memcpy(frame + pos, payload, payload_len);
    pos += payload_len;

    /* Inject to all interfaces */
    int rc = 0;
    for (size_t i = 0; i < n_handles; ++i) {
        if (!handles[i]) continue;
        int ret = pcap_inject(handles[i], frame, pos);
        if (ret < 0) {
            fprintf(stderr, "pcap_inject[%zu]: %s\n", i, pcap_geterr(handles[i]));
            rc = -1; /* continue but report error */
        }
    }
    return rc;
}

int main(int argc, char** argv)
{
    if (argc != 9) {
        fprintf(stderr, "Usage: %s <listen_ip> <port> <ifaces_csv> <mcs_idx> <gi> <bw> <ldpc> <stbc>\n", argv[0]);
        fprintf(stderr, "Example: sudo %s 0.0.0.0 5600 wlan0mon,wlan1mon 5 1 40 1 0\n", argv[0]);
        fprintf(stderr, "  bw: 20 | 40 | 20L | 20U\n");
        return 1;
    }

    const char* listen_ip = argv[1];
    int port = atoi(argv[2]);
    const char* ifaces_csv = argv[3];
    int mcs_idx = atoi(argv[4]);
    int gi = atoi(argv[5]);
    const char* bw = argv[6];
    int ldpc = atoi(argv[7]);
    int stbc = atoi(argv[8]);

    /* Open UDP socket for receiving payloads */
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        perror("socket");
        return 2;
    }
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_aton(listen_ip, &addr.sin_addr) == 0) {
        fprintf(stderr, "Invalid listen_ip\n");
        return 2;
    }
    if (bind(udp_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 2;
    }

    /* Open pcap handles */
    pcap_t* handles[MAX_INTERFACES] = {0};
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    size_t n_handles = open_pcap_handles(ifaces_csv, handles, errbuf, /*immediate*/1);
    if (n_handles == 0) {
        fprintf(stderr, "No interfaces opened for injection\n");
        return 3;
    }

    /* Handle Ctrl-C */
    signal(SIGINT, on_sigint);
    fprintf(stderr, "Listening %s:%d; MIRROR to %zu ifaces; MCS=%d GI=%d BW=%s LDPC=%d STBC=%d\n",
            listen_ip, port, n_handles, mcs_idx, gi, bw, ldpc, stbc);

    uint8_t buf[MAX_UDP_PAYLOAD];
    uint16_t seq = 0;

    while (g_running) {
        ssize_t r = recv(udp_sock, buf, sizeof(buf), 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            perror("recv");
            break;
        }
        mirror_send(handles, n_handles, (uint8_t)mcs_idx, gi, bw, ldpc, stbc, buf, (size_t)r, seq++);
    }

    for (size_t i = 0; i < n_handles; ++i) {
        if (handles[i]) pcap_close(handles[i]);
    }
    close(udp_sock);
    return 0;
}
