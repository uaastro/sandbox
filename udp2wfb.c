// udp_inject_cli.c — приём UDP и инжекция в эфир через указанный WLAN-интерфейс (monitor mode).
// CLI с дефолтами:
//   --ip 0.0.0.0
//   --port 5600
//   --mcs_idx 0
//   --gi short (long|short)
//   --bw 20 (20|40)
//   --ldpc 1
//   --stbc 1
//   --group_id 0
//   --tx_id 0
//   --link_id 0
//   --radio_port 0
//
// Позиционный обязательный параметр: <wlan_iface>
//
// Сборка: gcc -O2 -Wall -o udp_inject_cli udp_inject_cli.c -lpcap
// Пример:
//   sudo ./udp_inject_cli --ip 127.0.0.1 --port 5600 --mcs_idx 0 --gi short --bw 20 --ldpc 1 --stbc 1 
//                         --group_id 1 --tx_id 1 --link_id 1 --radio_port 5 wlx00c0cab6e6f4
//
// Важно: интерфейс заранее перевести в monitor mode и выставить канал (iw dev <iface> set channel ...)

#define _GNU_SOURCE
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <getopt.h>
#include <ctype.h>

#ifdef __linux__
  #include <endian.h>
#else
  #include <sys/endian.h>
#endif

#ifndef htole16
  #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    #define htole16(x) (x)
    #define htole32(x) (x)
  #else
    #define htole16(x) __builtin_bswap16(x)
    #define htole32(x) __builtin_bswap32(x)
  #endif
#endif

#define MAX_FRAME        4096
#define MAX_UDP_PAYLOAD  2000

// Radiotap present bits
#define RT_PRESENT_TX_FLAGS (1u << 15)
#define RT_PRESENT_MCS      (1u << 19)

// Radiotap MCS-known bits
#define MCS_KNOWN_BW    0x01
#define MCS_KNOWN_MCS   0x02
#define MCS_KNOWN_GI    0x04
#define MCS_KNOWN_FEC   0x10
#define MCS_KNOWN_STBC  0x20

// Radiotap MCS-flags bits
#define MCS_FLAGS_SGI           0x04
#define MCS_FLAGS_LDPC          0x10
#define MCS_FLAGS_STBC_SHIFT    5
// BW (2 LSBs mcs_flags): 0=20, 1=40

struct __attribute__((__packed__)) rt_hdr {
  uint8_t  it_version;
  uint8_t  it_pad;
  uint16_t it_len;
  uint32_t it_present;
  uint16_t tx_flags;   // ВСЕГДА: NOACK|NOSEQ|FIXED RATE
  uint8_t  mcs_known;
  uint8_t  mcs_flags;
  uint8_t  mcs_index;
};

struct __attribute__((__packed__)) dot11_hdr {
  uint16_t frame_control;
  uint16_t duration;
  uint8_t  addr1[6];
  uint8_t  addr2[6];
  uint8_t  addr3[6];
  uint16_t seq_ctrl;
};

static volatile int g_run = 1;
static void on_sigint(int){ g_run = 0; }

static void mac_set(uint8_t m[6], uint8_t a0,uint8_t a1,uint8_t a2,uint8_t a3,uint8_t a4,uint8_t a5){
  m[0]=a0; m[1]=a1; m[2]=a2; m[3]=a3; m[4]=a4; m[5]=a5;
}

static uint8_t mcs_flags_from_args(int gi_short, int bw40, int ldpc, int stbc) {
  uint8_t f = 0;
  if (bw40) f |= 1; // 0=20,1=40
  if (gi_short) f |= MCS_FLAGS_SGI;
  if (ldpc)     f |= MCS_FLAGS_LDPC;
  if (stbc < 0) stbc = 0; 
  if (stbc > 3) stbc = 3;
  f |= (uint8_t)(stbc << MCS_FLAGS_STBC_SHIFT);
  return f;
}

static void build_addr1_group(uint8_t a[6], uint8_t group_id){
  mac_set(a, 0x02,0x11,0x22, 0x10, 0x00, group_id);
}
static void build_addr2_tx(uint8_t a[6], uint8_t tx_id){
  mac_set(a, 0x02,0x11,0x22, 0x20, 0x00, tx_id);
}
static void build_addr3_link_port(uint8_t a[6], uint8_t link_id, uint8_t radio_port){
  mac_set(a, 0x02,0x11,0x22, 0x30, link_id, radio_port);
}

static size_t build_radiotap(uint8_t *out,
                             uint8_t mcs_idx, int gi_short, int bw40, int ldpc, int stbc)
{
  struct rt_hdr rt;
  memset(&rt, 0, sizeof(rt));
  rt.it_version = 0;
  rt.it_pad     = 0;
  rt.it_len     = htole16((uint16_t)sizeof(rt));
  rt.it_present = htole32(RT_PRESENT_TX_FLAGS | RT_PRESENT_MCS);

  // NOACK + NOSEQ + FIXED RATE + NO AGGREGATION
  rt.tx_flags = htole16(0x0008 | 0x0010 | 0x0100 | 0x0080);

  rt.mcs_known  = (uint8_t)(MCS_KNOWN_BW | MCS_KNOWN_MCS | MCS_KNOWN_GI | MCS_KNOWN_FEC | MCS_KNOWN_STBC);
  rt.mcs_flags  = mcs_flags_from_args(gi_short, bw40, ldpc, stbc);
  rt.mcs_index  = mcs_idx;
  memcpy(out, &rt, sizeof(rt));
  return sizeof(rt);
}

static size_t build_dot11(uint8_t* out, uint16_t seq,
                          uint8_t group_id, uint8_t tx_id, uint8_t link_id, uint8_t radio_port)
{
  struct dot11_hdr h = {0};
  h.frame_control = htole16(0x0008); // Data
  h.duration      = htole16(0);
  build_addr1_group(h.addr1, group_id);
  build_addr2_tx(h.addr2, tx_id);
  build_addr3_link_port(h.addr3, link_id, radio_port);
  h.seq_ctrl = htole16((uint16_t)((seq & 0x0fff) << 4));
  memcpy(out, &h, sizeof(h));
  return sizeof(h);
}

static int send_packet(pcap_t* ph,
                       const uint8_t* payload, size_t payload_len,
                       uint16_t seq_num,
                       uint8_t mcs_idx, int gi_short, int bw40, int ldpc, int stbc,
                       uint8_t group_id, uint8_t tx_id, uint8_t link_id, uint8_t radio_port)
{
  if (payload_len + 128 > MAX_FRAME) {
    fprintf(stderr, "payload too large: %zu\n", payload_len);
    return -1;
  }

  uint8_t frame[MAX_FRAME];
  size_t pos = 0;
  pos += build_radiotap(frame + pos, mcs_idx, gi_short, bw40, ldpc, stbc);
  pos += build_dot11(frame + pos, seq_num, group_id, tx_id, link_id, radio_port);
  memcpy(frame + pos, payload, payload_len);
  pos += payload_len;

  int ret = pcap_inject(ph, frame, (int)pos);
  if (ret < 0) {
    fprintf(stderr, "pcap_inject: %s\n", pcap_geterr(ph));
    return -1;
  }

  fprintf(stderr, "TX seq=%u len=%zu MCS=%u GI=%s BW=%s LDPC=%d STBC=%d  G=%u TX=%u L=%u P=%u\n",
          (unsigned)seq_num, payload_len, (unsigned)mcs_idx,
          gi_short ? "short" : "long",
          bw40 ? "40" : "20",
          ldpc, stbc, group_id, tx_id, link_id, radio_port);
  return 0;
}

static void usage(const char* prog){
  fprintf(stderr,
"Usage: sudo %s [options] <wlan_iface>\n"
"Options (defaults in []):\n"
"  --ip <addr>           [0.0.0.0]\n"
"  --port <num>          [5600]\n"
"  --mcs_idx <0..31>     [0]\n"
"  --gi <long|short>     [short]\n"
"  --bw <20|40>          [20]\n"
"  --ldpc <0|1>          [1]\n"
"  --stbc <0..3>         [1]\n"
"  --group_id <0..255>   [0]\n"
"  --tx_id <0..255>      [0]\n"
"  --link_id <0..255>    [0]\n"
"  --radio_port <0..255> [0]\n",
  prog);
}

int main(int argc, char** argv) {
  // defaults
  const char* ip = "0.0.0.0";
  int port = 5600;
  int mcs_idx = 0;
  int gi_short = 1; // default short
  int bw40 = 0;     // default 20MHz
  int ldpc = 1;
  int stbc = 1;
  int group_id = 0, tx_id = 0, link_id = 0, radio_port = 0;

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
    {0,0,0,0}
  };

  int optidx = 0;
  while (1) {
    int c = getopt_long(argc, argv, "", longopts, &optidx);
    if (c == -1) break;
    if (c != 0) continue;
    const char* name = longopts[optidx].name;
    const char* val = optarg;
    if (strcmp(name,"ip")==0) ip = val;
    else if (strcmp(name,"port")==0) port = atoi(val);
    else if (strcmp(name,"mcs_idx")==0) mcs_idx = atoi(val);
    else if (strcmp(name,"gi")==0) {
      if (strcasecmp(val,"short")==0) gi_short = 1;
      else if (strcasecmp(val,"long")==0) gi_short = 0;
      else { fprintf(stderr,"Invalid --gi (use long|short)\n"); return 1; }
    }
    else if (strcmp(name,"bw")==0) {
      if (strcmp(val,"20")==0) bw40 = 0;
      else if (strcmp(val,"40")==0) bw40 = 1;
      else { fprintf(stderr,"Invalid --bw (use 20|40)\n"); return 1; }
    }
    else if (strcmp(name,"ldpc")==0) ldpc = atoi(val) ? 1 : 0;
    else if (strcmp(name,"stbc")==0) { stbc = atoi(val); if (stbc<0) stbc=0; if (stbc>3) stbc=3; }
    else if (strcmp(name,"group_id")==0) group_id = atoi(val) & 0xFF;
    else if (strcmp(name,"tx_id")==0)    tx_id    = atoi(val) & 0xFF;
    else if (strcmp(name,"link_id")==0)  link_id  = atoi(val) & 0xFF;
    else if (strcmp(name,"radio_port")==0) radio_port = atoi(val) & 0xFF;
  }

  if (optind >= argc) {
    usage(argv[0]);
    fprintf(stderr, "\nError: <wlan_iface> is required\n");
    return 1;
  }
  const char* iface = argv[optind];

  signal(SIGINT, on_sigint);

  // UDP bind
  int us = socket(AF_INET, SOCK_DGRAM, 0);
  if (us < 0) { perror("socket"); return 1; }
  struct sockaddr_in sa = {0};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  if (inet_aton(ip, &sa.sin_addr) == 0) {
    fprintf(stderr, "Invalid --ip\n"); return 1;
  }
  if (bind(us, (struct sockaddr*)&sa, sizeof(sa)) < 0) { perror("bind"); return 1; }

  // pcap open
  char errbuf[PCAP_ERRBUF_SIZE] = {0};
  pcap_t* ph = pcap_create(iface, errbuf);
  if (!ph) { fprintf(stderr, "pcap_create(%s): %s\n", iface, errbuf); return 1; }
  (void)pcap_set_immediate_mode(ph, 1);
  if (pcap_activate(ph) != 0) {
    fprintf(stderr, "pcap_activate(%s): %s\n", iface, pcap_geterr(ph));
    return 1;
  }

  fprintf(stderr, "UDP %s:%d -> WLAN %s | MCS=%d GI=%s BW=%s LDPC=%d STBC=%d | G=%d TX=%d L=%d P=%d\n",
          ip, port, iface, mcs_idx, gi_short?"short":"long", bw40?"40":"20",
          ldpc, stbc, group_id, tx_id, link_id, radio_port);

  uint8_t buf[MAX_UDP_PAYLOAD];
  uint16_t seq = 0;

  while (g_run) {
    ssize_t n = recv(us, buf, sizeof(buf), 0);
    if (n < 0) { if (errno==EINTR) continue; perror("recv"); break; }
    if (n == 0) continue;

    (void)send_packet(ph, buf, (size_t)n, seq,
                      (uint8_t)mcs_idx, gi_short, bw40, ldpc, stbc,
                      (uint8_t)group_id, (uint8_t)tx_id, (uint8_t)link_id, (uint8_t)radio_port);

    seq = (uint16_t)((seq + 1) & 0x0fff);
  }

  if (ph) pcap_close(ph);
  close(us);
  return 0;
}