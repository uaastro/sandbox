// rx_forward_wfb.cpp — RX (monitor) -> UDP 127.0.0.1:5800
// Использует ваш стек: #include "wifibroadcast.hpp"
// Собирает статистику по антеннам (RSSI/NOISE/SNR) по схеме из rx.cpp
// Сборка: g++ -O2 -Wall -std=c++17 -o rx_forward_wfb rx_forward_wfb.cpp -lpcap

#define _GNU_SOURCE
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <climits>
#include <string>
#include "wifibroadcast.hpp"   // ваш заголовок

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
static const int   DEST_PORT = 5800;

enum { RX_ANT_MAX = 4 };

#pragma pack(push,1)
struct dot11_hdr {
  uint16_t frame_control;
  uint16_t duration;
  uint8_t  addr1[6];
  uint8_t  addr2[6];
  uint8_t  addr3[6];
  uint16_t seq_ctrl;
};
#pragma pack(pop)

static void mac_to_str(const uint8_t m[6], char* out, size_t n) {
  snprintf(out, n, "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]);
}

static void hexdump(const uint8_t* data, size_t len) {
  for (size_t i=0; i<len; i+=16) {
    fprintf(stderr, "%04zx: ", i);
    size_t j=0;
    for (; j<16 && i+j<len; ++j) fprintf(stderr, "%02x ", data[i+j]);
    for (; j<16; ++j) fprintf(stderr, "   ");
    fprintf(stderr, " |");
    for (j=0; j<16 && i+j<len; ++j) {
      unsigned char c = data[i+j];
      fprintf(stderr, "%c", (c>=32 && c<127)? c: '.');
    }
    fprintf(stderr, "|\n");
  }
}

/* ---------- Radiotap parser (выравнивание + present chain) ---------- */
// Требуемые индексы полей соответствуют вашим дефайнам в wifibroadcast.hpp
// (IEEE80211_RADIOTAP_*)
#ifndef IEEE80211_RADIOTAP_TSFT
  #define IEEE80211_RADIOTAP_TSFT            0
  #define IEEE80211_RADIOTAP_FLAGS           1
  #define IEEE80211_RADIOTAP_RATE            2
  #define IEEE80211_RADIOTAP_CHANNEL         3
  #define IEEE80211_RADIOTAP_FHSS            4
  #define IEEE80211_RADIOTAP_DBM_ANTSIGNAL   5
  #define IEEE80211_RADIOTAP_DBM_ANTNOISE    6
  #define IEEE80211_RADIOTAP_LOCK_QUALITY    7
  #define IEEE80211_RADIOTAP_TX_ATTENUATION  8
  #define IEEE80211_RADIOTAP_DB_TX_ATTENUATION 9
  #define IEEE80211_RADIOTAP_DBM_TX_POWER   10
  #define IEEE80211_RADIOTAP_ANTENNA        11
  #define IEEE80211_RADIOTAP_DB_ANTSIGNAL   12
  #define IEEE80211_RADIOTAP_DB_ANTNOISE    13
  #define IEEE80211_RADIOTAP_RX_FLAGS       14
  #define IEEE80211_RADIOTAP_TX_FLAGS       15
  #define IEEE80211_RADIOTAP_MCS            19
#endif

// Radiotap header
#pragma pack(push,1)
struct rt_hdr_min {
  uint8_t  it_version;
  uint8_t  it_pad;
  uint16_t it_len;
  uint32_t it_present; // может быть цепочка (EXT=bit31)
};
#pragma pack(pop)

static inline size_t align_for_field(uint8_t field_idx, size_t off) {
  // выравнивания по спецификации radiotap
  size_t align = 1;
  switch (field_idx) {
    case IEEE80211_RADIOTAP_TSFT: align=8; break;
    case IEEE80211_RADIOTAP_CHANNEL: align=2; break;
    case IEEE80211_RADIOTAP_FHSS: align=2; break;
    case IEEE80211_RADIOTAP_LOCK_QUALITY: align=2; break;
    case IEEE80211_RADIOTAP_TX_ATTENUATION: align=2; break;
    case IEEE80211_RADIOTAP_DB_TX_ATTENUATION: align=2; break;
    case IEEE80211_RADIOTAP_RX_FLAGS: align=2; break;
    case IEEE80211_RADIOTAP_TX_FLAGS: align=2; break;
    default: align=1; break;
  }
  size_t rem = off % align;
  if (rem) off += (align - rem);
  return off;
}
static inline size_t size_of_field(uint8_t field_idx) {
  switch (field_idx) {
    case IEEE80211_RADIOTAP_TSFT: return 8;
    case IEEE80211_RADIOTAP_FLAGS: return 1;
    case IEEE80211_RADIOTAP_RATE: return 1;
    case IEEE80211_RADIOTAP_CHANNEL: return 4;
    case IEEE80211_RADIOTAP_FHSS: return 2;
    case IEEE80211_RADIOTAP_DBM_ANTSIGNAL: return 1;
    case IEEE80211_RADIOTAP_DBM_ANTNOISE: return 1;
    case IEEE80211_RADIOTAP_LOCK_QUALITY: return 2;
    case IEEE80211_RADIOTAP_TX_ATTENUATION: return 2;
    case IEEE80211_RADIOTAP_DB_TX_ATTENUATION: return 2;
    case IEEE80211_RADIOTAP_DBM_TX_POWER: return 1;
    case IEEE80211_RADIOTAP_ANTENNA: return 1;
    case IEEE80211_RADIOTAP_DB_ANTSIGNAL: return 1;
    case IEEE80211_RADIOTAP_DB_ANTNOISE: return 1;
    case IEEE80211_RADIOTAP_RX_FLAGS: return 2;
    case IEEE80211_RADIOTAP_TX_FLAGS: return 2;
    case IEEE80211_RADIOTAP_MCS: return 3;
    default: return 0; // неизвестные пропустим нулём — сдвиг не делаем
  }
}

struct RtStats {
  uint16_t rt_len{0};
  uint8_t  flags{0};           // radiotap Flags (бит 0x10 = FCS, 0x20 = DATAPAD)
  uint8_t  antenna[RX_ANT_MAX];
  int8_t   rssi[RX_ANT_MAX];
  int8_t   noise[RX_ANT_MAX];
  int      chains{0};
};

static bool parse_radiotap_rxcpp_like(const uint8_t* p, size_t caplen, RtStats& rs)
{
  if (caplen < sizeof(rt_hdr_min)) return false;
  const rt_hdr_min* rh = reinterpret_cast<const rt_hdr_min*>(p);
  uint16_t it_len = rh->it_len;
  if (it_len > caplen || it_len < sizeof(rt_hdr_min)) return false;

  // init
  rs.rt_len = it_len;
  rs.flags = 0;
  rs.chains = 0;
  for (int i=0;i<RX_ANT_MAX;i++){ rs.antenna[i]=0xff; rs.rssi[i]=SCHAR_MIN; rs.noise[i]=SCHAR_MAX; }

  // собрать present chain
  uint32_t presents[8]; int np=0;
  size_t poff = offsetof(rt_hdr_min, it_present);
  do {
    if (poff + 4 > it_len) break;
    uint32_t v = *(const uint32_t*)(p + poff);
    presents[np++] = v;
    poff += 4;
  } while (np < 8 && (presents[np-1] & 0x80000000u));

  // начало полей
  size_t off = poff;
  int ant_idx = 0;

  for (int wi=0; wi<np; ++wi) {
    uint32_t pres = presents[wi];
    for (uint8_t f = 0; f < 32; ++f) {
      if (!(pres & (1u<<f))) continue;
      off = align_for_field(f, off);
      size_t sz = size_of_field(f);
      if (sz==0 || off + sz > it_len) { off += sz; continue; }

      const uint8_t* field = p + off;

      switch (f) {
        case IEEE80211_RADIOTAP_FLAGS:
          rs.flags = *field;
          break;
        case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
          if (ant_idx < RX_ANT_MAX) rs.rssi[ant_idx] = (int8_t)*field;
          break;
        case IEEE80211_RADIOTAP_DBM_ANTNOISE:
          if (ant_idx < RX_ANT_MAX) rs.noise[ant_idx] = (int8_t)*field;
          break;
        case IEEE80211_RADIOTAP_ANTENNA:
          if (ant_idx < RX_ANT_MAX) {
            rs.antenna[ant_idx] = *field;
            ant_idx++; // переход к следующей цепочке — как в rx.cpp
          }
          break;
        default:
          break;
      }
      off += sz;
    }
  }
  rs.chains = ant_idx;
  return true;
}

/* ------------------------------ MAIN ------------------------------ */
int main() {
  // UDP out
  int us = socket(AF_INET, SOCK_DGRAM, 0);
  if (us < 0) { perror("socket"); return 1; }
  sockaddr_in dst{}; dst.sin_family=AF_INET; dst.sin_port=htons(DEST_PORT);
  inet_aton(DEST_IP, &dst.sin_addr);

  // PCAP
  char errbuf[PCAP_ERRBUF_SIZE] = {0};
  pcap_t* ph = pcap_create(IFACE, errbuf);
  if (!ph) { fprintf(stderr, "pcap_create(%s): %s\n", IFACE, errbuf); return 1; }
  (void)pcap_set_immediate_mode(ph, 1);
  if (pcap_activate(ph) != 0) {
    fprintf(stderr, "pcap_activate(%s): %s\n", IFACE, pcap_geterr(ph)); return 1;
  }

  fprintf(stderr, "RX on %s -> UDP %s:%d (with wifibroadcast.hpp)\n", IFACE, DEST_IP, DEST_PORT);

  while (true) {
    struct pcap_pkthdr* hdr = nullptr;
    const u_char* pkt = nullptr;
    int rc = pcap_next_ex(ph, &hdr, &pkt);
    if (rc == 0) continue;
    if (rc < 0) { fprintf(stderr, "pcap_next_ex: %s\n", pcap_geterr(ph)); break; }
    if (!pkt || hdr->caplen < sizeof(rt_hdr_min)) continue;

    RtStats rs;
    if (!parse_radiotap_rxcpp_like(pkt, hdr->caplen, rs)) continue;
    if (rs.rt_len >= hdr->caplen) continue;

    const uint8_t* dot11 = pkt + rs.rt_len;
    size_t dlen = hdr->caplen - rs.rt_len;
    if (dlen < sizeof(dot11_hdr)) continue;

    const dot11_hdr* h = reinterpret_cast<const dot11_hdr*>(dot11);
    uint16_t fc = le16toh(h->frame_control);
    uint8_t type = (fc >> 2) & 0x3;
    uint8_t subtype = (fc >> 4) & 0xF;
    if (type != 2) continue; // только Data

    size_t hdr_len = sizeof(dot11_hdr);
    int qos = (subtype & 0x08) ? 1 : 0; if (qos) { if (dlen < hdr_len + 2) continue; hdr_len += 2; }
    int order = (fc & 0x8000) ? 1 : 0; if (order) { if (dlen < hdr_len + 4) continue; hdr_len += 4; }

    // DATAPAD (0x20) — если нужно, выровнять длину заголовка до /4
    if (rs.flags & 0x20) {
      size_t aligned = (hdr_len + 3u) & ~3u;
      if (aligned > dlen) continue;
      hdr_len = aligned;
    }

    const uint8_t* payload = dot11 + hdr_len;
    size_t payload_len = dlen - hdr_len;

    // FCS: если включён (0x10), отрезаем 4 байта
    if ((rs.flags & 0x10) && payload_len >= 4) payload_len -= 4;
    if (payload_len == 0) continue;

    uint16_t seq = (le16toh(h->seq_ctrl) >> 4) & 0x0FFF;
    char mac2[32]; mac_to_str(h->addr2, mac2, sizeof(mac2));

    fprintf(stderr, "[RX] seq=%u from=%s payload_len=%zu flags=0x%02x\n",
            seq, mac2, payload_len, rs.flags);

    // печатаем цепочки: RSSI/NOISE/SNR
    for (int i=0;i<rs.chains && i<RX_ANT_MAX; ++i) {
      const int8_t r = rs.rssi[i];
      const int8_t n = rs.noise[i];
      bool noise_ok = (n != SCHAR_MAX);
      int snr = noise_ok ? (int)r - (int)n : 0;
      if (rs.antenna[i] != 0xff || r != SCHAR_MIN || n != SCHAR_MAX) {
        fprintf(stderr, "   ant[%d]=%u  rssi=%d dBm  noise=%s  snr=%d dB\n",
                i, (unsigned)rs.antenna[i], (int)r,
                noise_ok ? std::to_string((int)n).c_str() : "NA",
                snr);
      }
    }

    hexdump(payload, payload_len);

    // UDP forward
    ssize_t sent = sendto(us, payload, payload_len, 0, (sockaddr*)&dst, sizeof(dst));
    fprintf(stderr, "[RX] UDP-out len=%zd\n", sent);
  }

  return 0;
}