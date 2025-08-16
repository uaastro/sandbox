// wfb_ts_tx.c — UDP -> 802.11 injection with TX-side timestamp tail (8 bytes ns, CLOCK_MONOTONIC_RAW)
//
// Based on wfb_tx.c logic. We append 8 bytes (uint64_t, LE) t0_ns to the UDP payload,
// then inject a radiotap+802.11 Data frame.
// Address mapping (as earlier):
//   addr1: group_id (broadcast-like addressing scheme driven by your project)
//   addr2: transmitter_id in addr2[5]
//   addr3: link_id in addr3[4], radio_port in addr3[5]
//
// Radiotap TX flags: NOACK | NOSEQ | FIXED_RATE (as agreed).
//
// Build: gcc -O2 -Wall -o wfb_ts_tx wfb_ts_tx.c -lpcap

#include <pcap/pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>

#ifdef __linux__
  #include <endian.h>
#else
  #include <sys/endian.h>
#endif

#ifndef htole16
  #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    #define htole16(x) (x)
    #define htole32(x) (x)
    #define htole64(x) (x)
  #else
    #define htole16(x) __builtin_bswap16(x)
    #define htole32(x) __builtin_bswap32(x)
    #define htole64(x) __builtin_bswap64(x)
  #endif
#endif

#include "wfb_defs.h"

#define MAX_UDP_PAYLOAD  3000u
#define TS_TAIL_BYTES    8u  /* uint64_t t0_ns at the end of payload */

static volatile int g_run = 1;

static uint64_t mono_ns_raw(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void mac_set(uint8_t m[6], uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f){
  m[0]=a; m[1]=b; m[2]=c; m[3]=d; m[4]=e; m[5]=f;
}

struct cli_cfg {
  const char* bind_ip;
  int bind_port;
  int mcs_idx;
  int gi_short;   /* 0=long,1=short */
  int bw40;       /* 0=20,1=40 */
  int ldpc;       /* 0/1 */
  int stbc;       /* 0/1 */
  int group_id;   /* addr1 mapping - your project usage */
  int tx_id;      /* addr2[5] */
  int link_id;    /* addr3[4] */
  int radio_port; /* addr3[5] */
  const char* iface;
};

static void print_help(const char* prog) {
  printf(
    "Usage: sudo %s [options] <wlan_iface>\n"
    "Options:\n"
    "  --ip <addr>         UDP bind IP (default: 0.0.0.0)\n"
    "  --port <num>        UDP bind port (default: 5600)\n"
    "  --mcs_idx <n>       MCS index (default: 0)\n"
    "  --gi <short|long>   Guard interval (default: short)\n"
    "  --bw <20|40>        Bandwidth (default: 20)\n"
    "  --ldpc <0|1>        LDPC flag (default: 1)\n"
    "  --stbc <0|1>        STBC flag (default: 1)\n"
    "  --group_id <n>      Group id (default: 0)\n"
    "  --tx_id <n>         Transmitter id (default: 0) -> maps to addr2[5]\n"
    "  --link_id <n>       Link id (default: 0) -> maps to addr3[4]\n"
    "  --radio_port <n>    Radio port (default: 0) -> maps to addr3[5]\n"
    "  --help              Show this help and exit\n", prog);
}

static int parse_cli(int argc, char** argv, struct cli_cfg* c)
{
  c->bind_ip = "0.0.0.0";
  c->bind_port = 5600;
  c->mcs_idx = 0;
  c->gi_short = 1;
  c->bw40 = 0;
  c->ldpc = 1;
  c->stbc = 1;
  c->group_id = 0;
  c->tx_id = 0;
  c->link_id = 0;
  c->radio_port = 0;
  c->iface = NULL;

  static struct option longopts[] = {
    {"ip",         required_argument, 0, 0},
    {"port",       required_argument, 0, 0},
    {"mcs_idx",    required_argument, 0, 0},
    {"gi",         required_argument, 0, 0},
    {"bw",         required_argument, 0, 0},
    {"ldpc",       required_argument, 0, 0},
    {"stbc",       required_argument, 0, 0},
    {"group_id",   required_argument, 0, 0},
    {"tx_id",      required_argument, 0, 0},
    {"link_id",    required_argument, 0, 0},
    {"radio_port", required_argument, 0, 0},
    {"help",       no_argument,       0, 0},
    {0,0,0,0}
  };

  int optidx=0;
  while (1) {
    int ch = getopt_long(argc, argv, "", longopts, &optidx);
    if (ch == -1) break;
    if (ch == 0) {
      const char* name = longopts[optidx].name;
      const char* val  = optarg ? optarg : "";
      if      (strcmp(name,"ip")==0)         c->bind_ip = val;
      else if (strcmp(name,"port")==0)       c->bind_port = atoi(val);
      else if (strcmp(name,"mcs_idx")==0)    c->mcs_idx = atoi(val);
      else if (strcmp(name,"gi")==0)         c->gi_short = (strcmp(val,"short")==0) ? 1 : 0;
      else if (strcmp(name,"bw")==0)         c->bw40 = (atoi(val)==40) ? 1 : 0;
      else if (strcmp(name,"ldpc")==0)       c->ldpc = atoi(val)!=0;
      else if (strcmp(name,"stbc")==0)       c->stbc = atoi(val)!=0;
      else if (strcmp(name,"group_id")==0)   c->group_id = atoi(val);
      else if (strcmp(name,"tx_id")==0)      c->tx_id = atoi(val);
      else if (strcmp(name,"link_id")==0)    c->link_id = atoi(val);
      else if (strcmp(name,"radio_port")==0) c->radio_port = atoi(val);
      else if (strcmp(name,"help")==0) { print_help(argv[0]); exit(0); }
    }
  }
  if (optind >= argc) {
    fprintf(stderr, "Error: missing <wlan_iface>. Use --help.\n");
    return -1;
  }
  c->iface = argv[optind];
  return 0;
}

int main(int argc, char** argv)
{
  struct cli_cfg cfg;
  if (parse_cli(argc, argv, &cfg) != 0) return 1;

  /* UDP source (ingest) */
  int us = socket(AF_INET, SOCK_DGRAM, 0);
  if (us < 0) { perror("socket"); return 1; }
  struct sockaddr_in sa; memset(&sa,0,sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port   = htons(cfg.bind_port);
  if (!inet_aton(cfg.bind_ip, &sa.sin_addr)) { fprintf(stderr, "inet_aton(%s) failed\n", cfg.bind_ip); return 1; }
  if (bind(us, (struct sockaddr*)&sa, sizeof(sa)) < 0) { perror("bind"); return 1; }

  /* PCAP inject */
  char errbuf[PCAP_ERRBUF_SIZE] = {0};
  pcap_t* ph = pcap_create(cfg.iface, errbuf);
  if (!ph) { fprintf(stderr, "pcap_create(%s): %s\n", cfg.iface, errbuf); return 1; }
  (void)pcap_set_immediate_mode(ph, 1);
  if (pcap_activate(ph) != 0) {
    fprintf(stderr, "pcap_activate(%s): %s\n", cfg.iface, pcap_geterr(ph));
    return 1;
  }

  fprintf(stderr, "TX(ts): UDP %s:%d -> %s | MCS=%d GI=%s BW=%s LDPC=%d STBC=%d | group=%d tx=%d link=%d port=%d\n",
          cfg.bind_ip, cfg.bind_port, cfg.iface, cfg.mcs_idx,
          cfg.gi_short?"short":"long", cfg.bw40?"40":"20",
          cfg.ldpc, cfg.stbc, cfg.group_id, cfg.tx_id, cfg.link_id, cfg.radio_port);

  uint8_t buf[4096];

  /* Prepare constant radiotap + 802.11 header template */
  struct wfb_radiotap_tx rt;
  memset(&rt, 0, sizeof(rt));
  rt.it_version = 0;
  rt.it_len     = sizeof(rt);
  rt.it_present = (1u<<IEEE80211_RADIOTAP_TX_FLAGS) | (1u<<IEEE80211_RADIOTAP_MCS);

  /* TX_FLAGS: NOACK (0x0008) | NOSEQ (0x0010) | FIXED_RATE (0x0100) */
  rt.tx_flags = htole16(0x0008u | 0x0010u | 0x0100u);

  rt.mcs.known = IEEE80211_RADIOTAP_MCS_HAVE_MCS |
                 IEEE80211_RADIOTAP_MCS_HAVE_BW  |
                 IEEE80211_RADIOTAP_MCS_HAVE_GI  |
                 IEEE80211_RADIOTAP_MCS_HAVE_FEC |
                 IEEE80211_RADIOTAP_MCS_HAVE_STBC;
  rt.mcs.flags = 0;
  if (cfg.bw40)     rt.mcs.flags |= IEEE80211_RADIOTAP_MCS_BW_40;
  if (cfg.gi_short) rt.mcs.flags |= IEEE80211_RADIOTAP_MCS_SGI;
  if (cfg.ldpc)     rt.mcs.flags |= IEEE80211_RADIOTAP_MCS_FEC_LDPC;
  if (cfg.stbc)     rt.mcs.flags |= IEEE80211_RADIOTAP_MCS_STBC_MASK; /* assume 1 stream STBC */
  rt.mcs.mcs = (uint8_t)cfg.mcs_idx;

  struct wfb_dot11_hdr h;
  memset(&h, 0, sizeof(h));
  h.frame_control = htole16(0x0008); /* Data */
  h.duration      = htole16(0);

  /* addr1: group_id (your scheme) — here keep broadcast OUI and encode group in last byte */
  mac_set(h.addr1, 0xff,0xff,0xff,0xff,0xff,(uint8_t)cfg.group_id);

  /* addr2: transmitter id in last byte */
  mac_set(h.addr2, 0x02,0x11,0x22,0x33,0x44,(uint8_t)cfg.tx_id);

  /* addr3: link/radio_port encoded into [4],[5] */
  mac_set(h.addr3, 0x02,0x11,0x22,0x33,(uint8_t)cfg.link_id,(uint8_t)cfg.radio_port);

  uint16_t seq = 0;

  while (1) {
    uint8_t udp_buf[MAX_UDP_PAYLOAD];
    ssize_t r = recv(us, udp_buf, sizeof(udp_buf), 0);
    if (r < 0) {
      if (errno == EINTR) continue;
      perror("recv");
      break;
    }
    size_t udp_len = (size_t)r;
    if (udp_len + TS_TAIL_BYTES > MAX_UDP_PAYLOAD) {
      /* clip or skip; choose skip to keep semantics clear */
      fprintf(stderr, "drop: udp payload too large (%zu)\n", udp_len);
      continue;
    }

    /* Compose the 802.11 frame */
    uint8_t* p = buf;
    memcpy(p, &rt, sizeof(rt)); p += sizeof(rt);

    /* Set seq (12-bit, in bits 4..15) */
    h.seq_ctrl = htole16((seq & 0x0FFF) << 4);
    seq = (uint16_t)((seq + 1) & 0x0FFF);
    memcpy(p, &h, sizeof(h)); p += sizeof(h);

    /* Copy UDP payload */
    memcpy(p, udp_buf, udp_len); p += udp_len;

    /* Append t0_ns tail (LE) as 8 bytes */
    uint64_t t0 = mono_ns_raw();
    uint64_t t0_le = htole64(t0);
    memcpy(p, &t0_le, TS_TAIL_BYTES); p += TS_TAIL_BYTES;

    size_t frame_len = (size_t)(p - buf);
    int rc = pcap_inject(ph, buf, frame_len);
    if (rc < 0) {
      fprintf(stderr, "pcap_inject: %s\n", pcap_geterr(ph));
    }
  }

  if (ph) pcap_close(ph);
  close(us);
  return 0;
}
