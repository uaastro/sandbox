// rx_forward_iter.c — RX (monitor) -> UDP 127.0.0.1:5800
// Radiotap iterator как в rx.cpp, корректная сборка цепочек, SNR=rssi-noise (если noise известен).

#define _GNU_SOURCE
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <limits.h>
#include <net/ieee80211_radiotap.h>

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

static const char* IFACE   = "wlx00c0cab8318b";
static const char* DEST_IP = "127.0.0.1";
enum { DEST_PORT = 5800 };

enum { RX_ANT_MAX = 4 };

struct __attribute__((__packed__)) dot11_hdr {
  uint16_t frame_control;
  uint16_t duration;
  uint8_t  addr1[6];
  uint8_t  addr2[6];
  uint8_t  addr3[6];
  uint16_t seq_ctrl;
};

static void mac_to_str(const uint8_t m[6], char* out, size_t n) {
  snprintf(out, n, "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]);
}
static void hexdump(const uint8_t* data, size_t len) {
  for (size_t i=0; i<len; i+=16) {
    fprintf(stderr, "%04zx: ", i);
    size_t j;
    for (j=0; j<16 && i+j<len; ++j) fprintf(stderr, "%02x ", data[i+j]);
    for (; j<16; ++j) fprintf(stderr, "   ");
    fprintf(stderr, " |");
    for (j=0; j<16 && i+j<len; ++j) {
      unsigned char c = data[i+j];
      fprintf(stderr, "%c", (c>=32 && c<127) ? c : '.');
    }
    fprintf(stderr, "|\n");
  }
}

static volatile int g_run = 1;
static void on_sigint(int){ g_run = 0; }

int main(void)
{
  signal(SIGINT, on_sigint);

  // UDP out
  int us = socket(AF_INET, SOCK_DGRAM, 0);
  if (us < 0) { perror("socket"); return 1; }
  struct sockaddr_in dst = {0};
  dst.sin_family = AF_INET; dst.sin_port = htons(DEST_PORT);
  if (!inet_aton(DEST_IP, &dst.sin_addr)) { fprintf(stderr,"inet_aton failed\n"); return 1; }

  // PCAP
  char errbuf[PCAP_ERRBUF_SIZE] = {0};
  pcap_t* ph = pcap_create(IFACE, errbuf);
  if (!ph) { fprintf(stderr, "pcap_create(%s): %s\n", IFACE, errbuf); return 1; }
  (void)pcap_set_immediate_mode(ph, 1);
  if (pcap_activate(ph) != 0) {
    fprintf(stderr, "pcap_activate(%s): %s\n", IFACE, pcap_geterr(ph));
    return 1;
  }

  fprintf(stderr, "RX on %s -> UDP %s:%d (radiotap iterator)\n", IFACE, DEST_IP, DEST_PORT);

  while (g_run) {
    struct pcap_pkthdr* hdr = NULL;
    const u_char* pkt = NULL;
    int rc = pcap_next_ex(ph, &hdr, &pkt);
    if (rc == 0) continue;
    if (rc < 0) { fprintf(stderr, "pcap_next_ex: %s\n", pcap_geterr(ph)); break; }
    if (!pkt || hdr->caplen < 8) continue;

    // Radiotap iterator
    struct ieee80211_radiotap_iterator it;
    int ret = ieee80211_radiotap_iterator_init(&it,
        (struct ieee80211_radiotap_header*)pkt, hdr->caplen, NULL);
    if (ret) continue;

    uint8_t flags = 0;
    uint8_t antenna[RX_ANT_MAX]; memset(antenna, 0xff, sizeof(antenna));
    int8_t  rssi[RX_ANT_MAX];    for (int i=0;i<RX_ANT_MAX;i++) rssi[i] = SCHAR_MIN;
    int8_t  noise[RX_ANT_MAX];   for (int i=0;i<RX_ANT_MAX;i++) noise[i] = SCHAR_MAX;
    int ant_idx = 0;

    while ((ret = ieee80211_radiotap_iterator_next(&it)) == 0 && ant_idx < RX_ANT_MAX) {
      switch (it.this_arg_index) {
        case IEEE80211_RADIOTAP_FLAGS:
          flags = *(uint8_t*)(it.this_arg);
          break;
        case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
          rssi[ant_idx] = *(int8_t*)(it.this_arg);
          break;
        case IEEE80211_RADIOTAP_DBM_ANTNOISE:
          noise[ant_idx] = *(int8_t*)(it.this_arg);
          break;
        case IEEE80211_RADIOTAP_ANTENNA:
          antenna[ant_idx] = *(uint8_t*)(it.this_arg);
          ant_idx++; // как в rx.cpp — переходим к следующей цепочке
          break;
        default:
          break;
      }
    }

    // отрезаем radiotap согласно итератору
    int rt_len = it._max_length;
    if (rt_len <= 0 || rt_len >= (int)hdr->caplen) continue;
    const uint8_t* dot11 = pkt + rt_len;
    size_t dlen = hdr->caplen - rt_len;
    if (dlen < sizeof(struct dot11_hdr)) continue;

    const struct dot11_hdr* h = (const struct dot11_hdr*)dot11;
    uint16_t fc = le16toh(h->frame_control);
    uint8_t type = (fc >> 2) & 0x3;
    uint8_t subtype = (fc >> 4) & 0xF;
    if (type != 2) continue; // только Data

    size_t hdr_len = sizeof(struct dot11_hdr);
    int qos = (subtype & 0x08) ? 1 : 0;
    if (qos) { if (dlen < hdr_len + 2) continue; hdr_len += 2; }
    int order = (fc & 0x8000) ? 1 : 0;
    if (order) { if (dlen < hdr_len + 4) continue; hdr_len += 4; }

    const uint8_t* payload = dot11 + hdr_len;
    size_t payload_len = dlen - hdr_len;
    if (payload_len == 0) continue;

    // Если FCS включён в пакете — отрезать 4 байта
    const uint8_t RTAP_F_FCS = 0x10;
    if ((flags & RTAP_F_FCS) && payload_len >= 4) payload_len -= 4;

    uint16_t seq_ctrl = le16toh(h->seq_ctrl);
    uint16_t seq = (seq_ctrl >> 4) & 0x0FFF;
    char mac2[32]; mac_to_str(h->addr2, mac2, sizeof(mac2));

    fprintf(stderr, "[RX] seq=%u from=%s payload_len=%zu flags=0x%02x\n",
            seq, mac2, payload_len, flags);

    for (int i=0;i<ant_idx && i<RX_ANT_MAX; i++) {
      int8_t r  = rssi[i];
      int8_t nz = noise[i];
      int8_t snr = (nz != SCHAR_MAX) ? (r - nz) : 0;
      char nzbuf[8]; if (nz == SCHAR_MAX) snprintf(nzbuf, sizeof(nzbuf), "NA");
                     else snprintf(nzbuf, sizeof(nzbuf), "%d", (int)nz);
      fprintf(stderr, "   ant[%d]=%u  rssi=%d dBm  noise=%s  snr=%d dB\n",
              i, (unsigned)antenna[i], (int)r, nzbuf, (int)snr);
    }

    hexdump(payload, payload_len);

    ssize_t sent = sendto(us, payload, payload_len, 0, (struct sockaddr*)&dst, sizeof(dst));
    fprintf(stderr, "[RX] UDP-out len=%zd\n", sent);
  }

  close(us);
  return 0;
}