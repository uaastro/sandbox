// wfb_ts_rx.c — 802.11 capture with TSFT and per-packet Δt:
// Δt_us = TSFT_rx_us - t0_ns/1000, where t0_ns is the last 8 bytes of payload appended by wfb_ts_tx.
//
// - Multi-interface receive (like wfb_rx.c).
// - Filters: --tx_id (any/include/exclude with '!' — quote in bash), --link_id, --radio_port.
// - Forwards payload to UDP WITHOUT the last 8 bytes (timestamp tail stripped).
// - Prints per-packet line with seq and Δt (if both TSFT and t0 present).
//
// Build: gcc -O2 -Wall -o wfb_ts_rx wfb_ts_rx.c -lpcap

#include <pcap/pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
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
    #define le64toh(x) (x)
  #else
    #define le16toh(x) __builtin_bswap16(x)
    #define le32toh(x) __builtin_bswap32(x)
    #define le64toh(x) __builtin_bswap64(x)
  #endif
#endif

#include "wfb_defs.h"

#define MAX_IFS 8
#define TS_TAIL_BYTES 8u

/* ---- Radiotap parse (need TSFT) ---- */
struct rt_stats {
  uint16_t rt_len;
  uint8_t  flags;
  uint8_t  antenna[RX_ANT_MAX];
  int8_t   rssi[RX_ANT_MAX];
  int8_t   noise[RX_ANT_MAX];
  int      chains;

  uint64_t tsft_us; /* TSFT in microseconds */
  int      has_tsft;
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
  rs->has_tsft = 0;
  for (int i=0;i<RX_ANT_MAX;i++){ rs->antenna[i]=0xff; rs->rssi[i]=SCHAR_MIN; rs->noise[i]=SCHAR_MAX; }

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
      off = wfb_rt_align(f, off);
      size_t sz = wfb_rt_size(f);
      if (sz==0 || off + sz > it_len) { off += sz; continue; }
      const uint8_t* field = p + off;

      switch (f) {
        case IEEE80211_RADIOTAP_TSFT:
          if (sz == 8) { uint64_t v; memcpy(&v, field, 8); rs->tsft_us = le64toh(v); rs->has_tsft = 1; }
          break;
        case IEEE80211_RADIOTAP_FLAGS:
          rs->flags = *field; break;
        case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
          if (ant_idx < RX_ANT_MAX) {rs->rssi[ant_idx] = (int8_t)*field;} break;
        case IEEE80211_RADIOTAP_DBM_ANTNOISE:
          if (ant_idx < RX_ANT_MAX) {rs->noise[ant_idx] = (int8_t)*field;} break;
        case IEEE80211_RADIOTAP_ANTENNA:
          if (ant_idx < RX_ANT_MAX) { rs->antenna[ant_idx] = *field; ant_idx++; } break;
        default: break;
      }
      off += sz;
    }
  }
  rs->chains = ant_idx;
  return 0;
}

/* ---- 802.11 header view ---- */
struct wfb_pkt_view {
  const struct wfb_dot11_hdr* h;
  const uint8_t* payload;
  size_t payload_len;
  uint16_t seq12;
};

static int extract_dot11(const uint8_t* pkt, size_t caplen, const struct rt_stats* rs, struct wfb_pkt_view* out)
{
  if (rs->rt_len >= caplen) return -1;
  const uint8_t* dot11 = pkt + rs->rt_len;
  size_t dlen = caplen - rs->rt_len;
  if (dlen < sizeof(struct wfb_dot11_hdr)) return -1;

  const struct wfb_dot11_hdr* h = (const struct wfb_dot11_hdr*)dot11;
  uint16_t fc = le16toh(h->frame_control);
  uint8_t type = (fc >> 2) & 0x3;
  uint8_t subtype = (fc >> 4) & 0xF;
  if (type != 2) return -1; /* only Data */

  size_t hdr_len = sizeof(struct wfb_dot11_hdr);
  int qos = (subtype & 0x08) ? 1 : 0;
  if (qos) { if (dlen < hdr_len + 2) return -1; hdr_len += 2; }
  int order = (fc & 0x8000) ? 1 : 0;
  if (order) { if (dlen < hdr_len + 4) return -1; hdr_len += 4; }

  if (rs->flags & RADIOTAP_F_DATAPAD) {
    size_t aligned = (hdr_len + 3u) & ~3u;
    if (aligned > dlen) return -1;
    hdr_len = aligned;
  }

  const uint8_t* payload = dot11 + hdr_len;
  size_t payload_len = dlen - hdr_len;
  if ((rs->flags & RADIOTAP_F_FCS) && payload_len >= 4) payload_len -= 4;
  if (payload_len == 0) return -1;

  out->h = h;
  out->payload = payload;
  out->payload_len = payload_len;
  out->seq12 = (le16toh(h->seq_ctrl) >> 4) & 0x0FFF;
  return 0;
}

/* ---- TX-ID flexible filter (same as in wfb_rx.c) ---- */

enum { TXF_ANY = 0, TXF_INCLUDE = 1, TXF_EXCLUDE = 2 };
struct txid_filter { int mode; uint64_t map[4]; };

static void txf_set(struct txid_filter* f, unsigned v) { if (v<=255) f->map[v>>6] |= (uint64_t)1ull<<(v&63); }
static int  txf_test(const struct txid_filter* f, unsigned v) { if (v>255) return 0; return (f->map[v>>6]>>(v&63))&1ull; }
static void txf_clear_all(struct txid_filter* f){ f->map[0]=f->map[1]=f->map[2]=f->map[3]=0; }

static int parse_uint(const char* s, unsigned* out) {
  char* end=NULL; long v=strtol(s,&end,0);
  if (!s||s==end||v<0||v>255) {
    return -1;
  } 
  *out=(unsigned)v; 
  return 0;
}

/* "any"/"-1" | list | "!list"  (remember to quote '!' in bash) */
static int txf_parse(struct txid_filter* f, const char* spec)
{
  f->mode = TXF_INCLUDE; txf_clear_all(f); txf_set(f,0); /* default only {0} */
  if (!spec || !*spec) return 0;

  while (isspace((unsigned char)*spec)) ++spec;
  if (strcmp(spec,"any")==0 || strcmp(spec,"-1")==0){ f->mode=TXF_ANY; txf_clear_all(f); return 0; }

  int excl = 0;
  if (spec[0]=='!'){ excl=1; ++spec; }
  f->mode = excl?TXF_EXCLUDE:TXF_INCLUDE;

  char buf[256]; strncpy(buf,spec,sizeof(buf)-1); buf[sizeof(buf)-1]=0;
  char* save=NULL; char* tok=strtok_r(buf,",",&save);
  txf_clear_all(f);
  while (tok) {
    while (isspace((unsigned char)*tok)) ++tok;
    char* dash=strchr(tok,'-');
    if (dash){ *dash=0; unsigned a,b; if (parse_uint(tok,&a)==0 && parse_uint(dash+1,&b)==0) {
        if (a<=b) for (unsigned v=a; v<=b; ++v) txf_set(f,v);
        else      for (unsigned v=b; v<=a; ++v) txf_set(f,v);
      }
    } else { unsigned v; if (parse_uint(tok,&v)==0) txf_set(f,v); }
    tok=strtok_r(NULL,",",&save);
  }
  return 0;
}
static int txf_match(const struct txid_filter* f, uint8_t tx) {
  if (f->mode == TXF_ANY) return 1;
  int present = txf_test(f, tx);
  return (f->mode == TXF_INCLUDE) ? present : !present;
}

/* ---- CLI ---- */
static volatile int g_run = 1;
static void on_sigint(int){ g_run = 0; }

struct cli_cfg {
  int n_if;
  const char* ifname[MAX_IFS];
  const char* ip;
  int port;
  struct txid_filter txf;
  int link_id;
  int radio_port;
};

static void print_help(const char* prog)
{
  printf(
    "Usage: sudo %s [options] <wlan_iface1> [<wlan_iface2> ...]\n"
    "Options:\n"
    "  --ip <addr>         UDP destination IP (default: 127.0.0.1)\n"
    "  --port <num>        UDP destination port (default: 5800)\n"
    "  --tx_id <spec>      TX filter: 'any'/'-1', include '1,2,5-7', exclude '!0,7' (quote '!')\n"
    "  --link_id <id>      Filter by Link ID (addr3[4]); -1 disables (default: 0)\n"
    "  --radio_port <id>   Filter by Radio Port (addr3[5]); -1 disables (default: 0)\n"
    "  --help              Show this help and exit\n"
    "\nExamples:\n"
    "  sudo %s --tx_id any wlan0\n"
    "  sudo %s --tx_id '!0,7' wlan0 wlan1\n",
    prog, prog, prog
  );
}

static int parse_cli(int argc, char** argv, struct cli_cfg* cfg)
{
  cfg->ip = "127.0.0.1";
  cfg->port = 5800;
  txf_parse(&cfg->txf, "0"); /* default only {0} */
  cfg->link_id = 0;
  cfg->radio_port = 0;
  cfg->n_if = 0;

  static struct option longopts[] = {
    {"ip",           required_argument, 0, 0},
    {"port",         required_argument, 0, 0},
    {"tx_id",        required_argument, 0, 0},
    {"link_id",      required_argument, 0, 0},
    {"radio_port",   required_argument, 0, 0},
    {"help",         no_argument,       0, 0},
    {0,0,0,0}
  };

  int optidx=0;
  while (1) {
    int c = getopt_long(argc, argv, "", longopts, &optidx);
    if (c == -1) break;
    if (c == 0) {
      const char* name = longopts[optidx].name;
      const char* val  = optarg ? optarg : "";
      if      (strcmp(name,"ip")==0)           cfg->ip = val;
      else if (strcmp(name,"port")==0)         cfg->port = atoi(val);
      else if (strcmp(name,"tx_id")==0)        txf_parse(&cfg->txf, val);
      else if (strcmp(name,"link_id")==0)      cfg->link_id = atoi(val);
      else if (strcmp(name,"radio_port")==0)   cfg->radio_port = atoi(val);
      else if (strcmp(name,"help")==0) { print_help(argv[0]); exit(0); }
    }
  }
  if (optind >= argc) {
    fprintf(stderr, "Error: missing <wlan_iface>. Use --help.\n");
    return -1;
  }
  for (int i=optind; i<argc && cfg->n_if < MAX_IFS; ++i) cfg->ifname[cfg->n_if++] = argv[i];
  if (cfg->n_if == 0) { fprintf(stderr, "Error: no interfaces.\n"); return -1; }
  return 0;
}

/* ---- main ---- */
int main(int argc, char** argv)
{
  struct cli_cfg cli;
  if (parse_cli(argc, argv, &cli) != 0) return 1;

  signal(SIGINT, on_sigint);

  /* UDP out */
  int us = socket(AF_INET, SOCK_DGRAM, 0);
  if (us < 0) { perror("socket"); return 1; }
  struct sockaddr_in dst; memset(&dst,0,sizeof(dst));
  dst.sin_family = AF_INET; dst.sin_port = htons(cli.port);
  if (!inet_aton(cli.ip, &dst.sin_addr)) { fprintf(stderr,"inet_aton(%s) failed\n", cli.ip); return 1; }

  /* open pcap on each iface */
  pcap_t* ph[MAX_IFS] = {0}; int fds[MAX_IFS]; for(int i=0;i<MAX_IFS;i++) fds[i]=-1;
  int n_open=0; char errbuf[PCAP_ERRBUF_SIZE]={0};
  for (int i=0;i<cli.n_if; ++i) {
    pcap_t* p = pcap_create(cli.ifname[i], errbuf);
    if (!p) { fprintf(stderr,"pcap_create(%s): %s\n", cli.ifname[i], errbuf); continue; }
    (void)pcap_set_immediate_mode(p, 1);
    (void)pcap_setnonblock(p, 1, errbuf);
    if (pcap_activate(p) != 0) { fprintf(stderr,"pcap_activate(%s): %s\n", cli.ifname[i], pcap_geterr(p)); pcap_close(p); continue; }
    int fd = pcap_get_selectable_fd(p);
    if (fd < 0) { fprintf(stderr,"pcap_get_selectable_fd(%s) failed; skip\n", cli.ifname[i]); pcap_close(p); continue; }
    ph[n_open]=p; fds[n_open]=fd; n_open++;
  }
  if (n_open==0) { fprintf(stderr,"No usable interfaces opened.\n"); return 1; }

  fprintf(stderr,"RX(ts): ");
  for (int i=0;i<n_open;i++) fprintf(stderr,"%s%s", cli.ifname[i], (i+1<n_open?", ":""));
  fprintf(stderr," -> UDP %s:%d | tx_id filter=%s\n",
          cli.ip, cli.port, (cli.txf.mode==TXF_ANY?"any":(cli.txf.mode==TXF_INCLUDE?"include":"exclude")));

  while (g_run) {
    struct timeval tv; tv.tv_sec=1; tv.tv_usec=0;
    fd_set rfds; FD_ZERO(&rfds);
    int maxfd=-1;
    for (int i=0;i<n_open;i++){ FD_SET(fds[i], &rfds); if (fds[i]>maxfd) maxfd=fds[i]; }

    int sel = select(maxfd+1, &rfds, NULL, NULL, &tv);
    if (sel < 0) { if (errno==EINTR) continue; perror("select"); break; }

    for (int i=0;i<n_open;i++) {
      if (sel==0 || !FD_ISSET(fds[i], &rfds)) continue;

      while (1) {
        struct pcap_pkthdr* hdr=NULL; const u_char* pkt=NULL;
        int rc = pcap_next_ex(ph[i], &hdr, &pkt);
        if (rc <= 0) break;

        struct rt_stats rs;
        if (parse_radiotap_rx(pkt, hdr->caplen, &rs) != 0) continue;

        struct wfb_pkt_view v;
        if (extract_dot11(pkt, hdr->caplen, &rs, &v) != 0) continue;

        /* filters by addr fields */
        uint8_t tx_id      = v.h->addr2[5];
        uint8_t link_id    = v.h->addr3[4];
        uint8_t radio_port = v.h->addr3[5];
        if (!txf_match(&cli.txf, tx_id)) continue;
        if (cli.link_id    >= 0 && link_id    != (uint8_t)cli.link_id)    continue;
        if (cli.radio_port >= 0 && radio_port != (uint8_t)cli.radio_port) continue;

        /* Extract t0 tail if present */
        uint64_t t0_ns = 0;
        int has_t0 = 0;
        if (v.payload_len >= TS_TAIL_BYTES) {
          uint64_t t0_le;
          memcpy(&t0_le, v.payload + (v.payload_len - TS_TAIL_BYTES), TS_TAIL_BYTES);
          t0_ns = le64toh(t0_le);
          has_t0 = 1;
        }

        if (rs.has_tsft && has_t0) {
          int64_t dt_us = (int64_t)rs.tsft_us - (int64_t)(t0_ns / 1000ull);
          uint16_t seq = v.seq12;
          fprintf(stderr, "[DT] seq=%u iface=%d dt_us=%" PRId64 " tsft_us=%" PRIu64 " t0_ns=%" PRIu64 "\n",
                  seq, i, dt_us, (uint64_t)rs.tsft_us, t0_ns);
        }

        /* Forward payload without the last 8 bytes (strip timestamp) */
        size_t out_len = v.payload_len;
        if (has_t0 && out_len >= TS_TAIL_BYTES) out_len -= TS_TAIL_BYTES;
        if (out_len > 0) (void)sendto(us, v.payload, out_len, 0, (struct sockaddr*)&dst, sizeof(dst));
      }
    }
  }

  for (int i=0;i<n_open;i++) if (ph[i]) pcap_close(ph[i]);
  close(us);
  return 0;
}
