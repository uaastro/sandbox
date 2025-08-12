// wfb_rx.c — 802.11 capture (monitor mode) -> UDP (configurable)
// CLI (optional): --ip, --port, --tx_id, --link_id, --radio_port, --help
// Required positional: <wlan_iface>
// Stats every STATS_PERIOD_MS (default 1000 ms): rssi min/avg/max, packets, bytes, kbps, lost, quality.

#include <pcap/pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>

#ifdef __linux__
  #include <endian.h>
#else
  #include <sys/endian.h>
#endif

#ifndef le16toh
  #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    #define le16toh(x) (x)
    #define le32toh(x) (x)
  #else
    #define le16toh(x) __builtin_bswap16(x)
    #define le32toh(x) __builtin_bswap32(x)
  #endif
#endif

#include "wfb_defs.h"

/* ---- Config ---- */
#ifndef STATS_PERIOD_MS
#define STATS_PERIOD_MS 1000
#endif

/* Defaults */
static const char* g_dest_ip_default   = "127.0.0.1";
static const int   g_dest_port_default = 5600;

/* Monotonic milliseconds */
static uint64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

/* Parse radiotap: fill flags + per-chain rssi/noise. Chain index advances on ANTENNA. */
struct rt_stats {
  uint16_t rt_len;
  uint8_t  flags;
  uint8_t  antenna[RX_ANT_MAX];
  int8_t   rssi[RX_ANT_MAX];   /* SCHAR_MIN => not present */
  int8_t   noise[RX_ANT_MAX];  /* SCHAR_MAX => not present */
  int      chains;
};

static int parse_radiotap_rx(const uint8_t* p, size_t caplen, struct rt_stats* rs)
{
  if (caplen < sizeof(struct wfb_radiotap_hdr_min)) return -1;
  const struct wfb_radiotap_hdr_min* rh = (const struct wfb_radiotap_hdr_min*)p;
  uint16_t it_len = rh->it_len;
  if (it_len > caplen || it_len < sizeof(struct wfb_radiotap_hdr_min)) return -1;

  rs->rt_len = it_len;
  rs->flags = 0;
  rs->chains = 0;
  for (int i=0;i<RX_ANT_MAX;i++){ rs->antenna[i]=0xff; rs->rssi[i]=SCHAR_MIN; rs->noise[i]=SCHAR_MAX; }

  /* present chain */
  uint32_t presents[8]; int np=0;
  size_t poff = offsetof(struct wfb_radiotap_hdr_min, it_present);
  do {
    if (poff + 4 > it_len) break;
    uint32_t v;
    memcpy(&v, p + poff, 4);
    presents[np++] = v;
    poff += 4;
  } while (np < 8 && (presents[np-1] & 0x80000000u));

  size_t off = poff;
  int ant_idx = 0;

  for (int wi=0; wi<np; ++wi) {
    uint32_t pres = presents[wi];
    for (uint8_t f=0; f<32; ++f) {
      if (!(pres & (1u<<f))) continue;
      /* alignment and size helpers from defs */
      off = wfb_rt_align(f, off);
      size_t sz = wfb_rt_size(f);
      if (sz==0 || off + sz > it_len) { off += sz; continue; }

      const uint8_t* field = p + off;

      switch (f) {
        case IEEE80211_RADIOTAP_FLAGS:
          rs->flags = *field;
          break;
        case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
          if (ant_idx < RX_ANT_MAX) rs->rssi[ant_idx] = (int8_t)*field;
          break;
        case IEEE80211_RADIOTAP_DBM_ANTNOISE:
          if (ant_idx < RX_ANT_MAX) rs->noise[ant_idx] = (int8_t)*field;
          break;
        case IEEE80211_RADIOTAP_ANTENNA:
          if (ant_idx < RX_ANT_MAX) {
            rs->antenna[ant_idx] = *field;
            ant_idx++; /* advance chain as in rx.cpp */
          }
          break;
        default: break;
      }
      off += sz;
    }
  }
  rs->chains = ant_idx;
  return 0;
}

static volatile int g_run = 1;
static void on_sigint(int){ g_run = 0; }

struct cli_cfg {
  const char* iface;
  const char* ip;
  int port;
  int tx_id;
  int link_id;
  int radio_port;
};

static void print_help(const char* prog)
{
  printf(
    "Usage: sudo %s [options] <wlan_iface>\n"
    "Options:\n"
    "  --ip <addr>         UDP destination IP (default: %s)\n"
    "  --port <num>        UDP destination port (default: %d)\n"
    "  --tx_id <id>        Filter by TX ID (addr2[5]); -1 disables filter (default: 0)\n"
    "  --link_id <id>      Filter by Link ID (addr3[4]); -1 disables filter (default: 0)\n"
    "  --radio_port <id>   Filter by Radio Port (addr3[5]); -1 disables filter (default: 0)\n"
    "  --help              Show this help and exit\n"
    "\nExample:\n"
    "  sudo %s --ip 127.0.0.1 --port 5600 --tx_id -1 --link_id 0 --radio_port 0 wlan0\n",
    prog, g_dest_ip_default, g_dest_port_default, prog
  );
}

static int parse_cli(int argc, char** argv, struct cli_cfg* cfg)
{
  cfg->ip = g_dest_ip_default;
  cfg->port = g_dest_port_default;
  cfg->tx_id = 0;       /* filters default to 0; use -1 to disable */
  cfg->link_id = 0;
  cfg->radio_port = 0;

  static struct option longopts[] = {
    {"ip",         required_argument, 0, 0},
    {"port",       required_argument, 0, 0},
    {"tx_id",      required_argument, 0, 0},
    {"link_id",    required_argument, 0, 0},
    {"radio_port", required_argument, 0, 0},
    {"help",       no_argument,       0, 0},
    {0,0,0,0}
  };

  int optidx = 0;
  while (1) {
    int c = getopt_long(argc, argv, "", longopts, &optidx);
    if (c == -1) break;
    if (c == 0) {
      const char* name = longopts[optidx].name;
      const char* val  = optarg ? optarg : "";
      if      (strcmp(name,"ip")==0)         cfg->ip = val;
      else if (strcmp(name,"port")==0)       cfg->port = atoi(val);
      else if (strcmp(name,"tx_id")==0)      cfg->tx_id = atoi(val);
      else if (strcmp(name,"link_id")==0)    cfg->link_id = atoi(val);
      else if (strcmp(name,"radio_port")==0) cfg->radio_port = atoi(val);
      else if (strcmp(name,"help")==0) {
        print_help(argv[0]);
        exit(0);
      }
    }
  }
  if (optind >= argc) {
    fprintf(stderr, "Error: missing required <wlan_iface>. Use --help for usage.\n");
    return -1;
  }
  cfg->iface = argv[optind];
  return 0;
}

int main(int argc, char** argv)
{
  struct cli_cfg cli;
  if (parse_cli(argc, argv, &cli) != 0) return 1;

  signal(SIGINT, on_sigint);

  /* UDP out socket */
  int us = socket(AF_INET, SOCK_DGRAM, 0);
  if (us < 0) { perror("socket"); return 1; }
  struct sockaddr_in dst;
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_port = htons(cli.port);
  if (!inet_aton(cli.ip, &dst.sin_addr)) {
    fprintf(stderr, "inet_aton failed for %s\n", cli.ip);
    return 1;
  }

  /* PCAP capture */
  char errbuf[PCAP_ERRBUF_SIZE] = {0};
  pcap_t* ph = pcap_create(cli.iface, errbuf);
  if (!ph) { fprintf(stderr, "pcap_create(%s): %s\n", cli.iface, errbuf); return 1; }
  (void)pcap_set_immediate_mode(ph, 1);
  if (pcap_activate(ph) != 0) {
    fprintf(stderr, "pcap_activate(%s): %s\n", cli.iface, pcap_geterr(ph));
    return 1;
  }

  fprintf(stderr,
          "RX: %s -> UDP %s:%d | stats %d ms | filters: TX=%d LINK=%d PORT=%d (use -1 to disable)\n",
          cli.iface, cli.ip, cli.port, STATS_PERIOD_MS,
          cli.tx_id, cli.link_id, cli.radio_port);

  /* Period accumulators */
  uint64_t t0 = now_ms();
  uint64_t bytes_period = 0;
  uint32_t rx_pkts_period = 0;
  int rssi_min =  127;
  int rssi_max = -127;
  int64_t rssi_sum = 0;
  uint32_t rssi_samples = 0;

  /* Loss tracking via 12-bit seq */
  int have_seq = 0;
  uint16_t expect_seq = 0;
  uint32_t lost_period = 0;

  while (g_run) {
    struct pcap_pkthdr* hdr = NULL;
    const u_char* pkt = NULL;
    int rc = pcap_next_ex(ph, &hdr, &pkt);
    if (rc == 0) {
      /* periodic tick handled below */
    } else if (rc < 0) {
      fprintf(stderr, "pcap_next_ex: %s\n", pcap_geterr(ph));
      break;
    } else if (pkt && hdr->caplen >= sizeof(struct wfb_radiotap_hdr_min)) {

      struct rt_stats rs;
      if (parse_radiotap_rx(pkt, hdr->caplen, &rs) != 0) goto stats_tick;
      if (rs.rt_len >= hdr->caplen) goto stats_tick;

      const uint8_t* dot11 = pkt + rs.rt_len;
      size_t dlen = hdr->caplen - rs.rt_len;
      if (dlen < sizeof(struct wfb_dot11_hdr)) goto stats_tick;

      const struct wfb_dot11_hdr* h = (const struct wfb_dot11_hdr*)dot11;
      uint16_t fc = le16toh(h->frame_control);
      uint8_t type = (fc >> 2) & 0x3;
      uint8_t subtype = (fc >> 4) & 0xF;
      if (type != 2) goto stats_tick; /* only Data */

      size_t hdr_len = sizeof(struct wfb_dot11_hdr);
      int qos = (subtype & 0x08) ? 1 : 0;
      if (qos) { if (dlen < hdr_len + 2) goto stats_tick; hdr_len += 2; }
      int order = (fc & 0x8000) ? 1 : 0;
      if (order) { if (dlen < hdr_len + 4) goto stats_tick; hdr_len += 4; }

      if (rs.flags & RADIOTAP_F_DATAPAD) {
        size_t aligned = (hdr_len + 3u) & ~3u;
        if (aligned > dlen) goto stats_tick;
        hdr_len = aligned;
      }

      const uint8_t* payload = dot11 + hdr_len;
      size_t payload_len = dlen - hdr_len;
      if ((rs.flags & RADIOTAP_F_FCS) && payload_len >= 4) payload_len -= 4;
      if (payload_len == 0) goto stats_tick;

      /* Address-based filters (defaults active; -1 disables) */
      uint8_t tx_id      = h->addr2[5];
      uint8_t link_id    = h->addr3[4];
      uint8_t radio_port = h->addr3[5];
      if (cli.tx_id      >= 0 && tx_id      != (uint8_t)cli.tx_id)      goto stats_tick;
      if (cli.link_id    >= 0 && link_id    != (uint8_t)cli.link_id)    goto stats_tick;
      if (cli.radio_port >= 0 && radio_port != (uint8_t)cli.radio_port) goto stats_tick;

      /* Sequence / loss */
      uint16_t seq = (le16toh(h->seq_ctrl) >> 4) & 0x0FFF;
      if (!have_seq) {
        have_seq = 1;
        expect_seq = (uint16_t)((seq + 1) & 0x0FFF);
      } else {
        if (seq != expect_seq) {
          uint16_t gap = (uint16_t)((seq - expect_seq) & 0x0FFF);
          lost_period += gap;
          expect_seq = (uint16_t)((seq + 1) & 0x0FFF);
        } else {
          expect_seq = (uint16_t)((expect_seq + 1) & 0x0FFF);
        }
      }

      /* Per-packet RSSI = max across chains that are present */
      int pkt_rssi_valid = 0;
      int pkt_rssi = -127;
      for (int i=0;i<rs.chains && i<RX_ANT_MAX; ++i) {
        if (rs.rssi[i] != SCHAR_MIN) {
          pkt_rssi_valid = 1;
          if (rs.rssi[i] > pkt_rssi) pkt_rssi = rs.rssi[i];
        }
      }
      if (pkt_rssi_valid) {
        if (pkt_rssi < rssi_min) rssi_min = pkt_rssi;
        if (pkt_rssi > rssi_max) rssi_max = pkt_rssi;
        rssi_sum += pkt_rssi;
        rssi_samples++;
      }

      /* Forward payload to UDP destination */
      (void)sendto(us, payload, payload_len, 0, (struct sockaddr*)&dst, sizeof(dst));

      /* Accumulate stats */
      rx_pkts_period += 1;
      bytes_period   += payload_len;
    }

stats_tick:
    uint64_t t1 = now_ms();
    if (t1 - t0 >= (uint64_t)STATS_PERIOD_MS) {
      double seconds = (double)(t1 - t0) / 1000.0;
      double kbps = seconds > 0.0 ? (bytes_period * 8.0 / 1000.0) / seconds : 0.0;
      uint32_t expected = rx_pkts_period + lost_period;
      int quality = expected ? (int)((rx_pkts_period * 100.0) / expected + 0.5) : 100;
      double rssi_avg = (rssi_samples > 0) ? ((double)rssi_sum / (double)rssi_samples) : 0.0;
      if (rssi_samples == 0) { rssi_min = 0; rssi_max = 0; }

      fprintf(stderr,
        "[STATS] dt=%llu ms | pkts=%u lost=%u quality=%d%% | bytes=%llu rate=%.1f kbps | rssi min/avg/max = %d/%.1f/%d dBm\n",
        (unsigned long long)(t1 - t0), rx_pkts_period, lost_period, quality,
        (unsigned long long)bytes_period, kbps,
        rssi_min, rssi_avg, rssi_max);

      /* reset period */
      t0 = t1;
      bytes_period = 0;
      rx_pkts_period = 0;
      lost_period = 0;
      rssi_min = 127; rssi_max = -127; rssi_sum = 0; rssi_samples = 0;
    }
  }

  if (ph) pcap_close(ph);
  close(us);
  return 0;
}