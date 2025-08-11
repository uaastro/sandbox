// rx_forward_wfb.cpp — RX (monitor) -> UDP 127.0.0.1:5800
// Periodic stats (default 1000 ms): rssi_min/avg/max, packets, bytes, rate, lost, quality.

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
#include <chrono>
#include "wifibroadcast.hpp"   // provides RX_ANT_MAX, Radiotap constants

// Fallback Radiotap field indexes (define only if missing)
#ifndef IEEE80211_RADIOTAP_TSFT
  #define IEEE80211_RADIOTAP_TSFT              0
  #define IEEE80211_RADIOTAP_FLAGS             1
  #define IEEE80211_RADIOTAP_RATE              2
  #define IEEE80211_RADIOTAP_CHANNEL           3
  #define IEEE80211_RADIOTAP_FHSS              4
  #define IEEE80211_RADIOTAP_DBM_ANTSIGNAL     5
  #define IEEE80211_RADIOTAP_DBM_ANTNOISE      6
  #define IEEE80211_RADIOTAP_LOCK_QUALITY      7
  #define IEEE80211_RADIOTAP_TX_ATTENUATION    8
  #define IEEE80211_RADIOTAP_DB_TX_ATTENUATION 9
  #define IEEE80211_RADIOTAP_DBM_TX_POWER      10
  #define IEEE80211_RADIOTAP_ANTENNA           11
  #define IEEE80211_RADIOTAP_DB_ANTSIGNAL      12
  #define IEEE80211_RADIOTAP_DB_ANTNOISE       13
  #define IEEE80211_RADIOTAP_RX_FLAGS          14
  #define IEEE80211_RADIOTAP_TX_FLAGS          15
  #define IEEE80211_RADIOTAP_MCS               19
#endif

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

// ---- stats period (ms) ----
#ifndef STATS_PERIOD_MS
#define STATS_PERIOD_MS 1000
#endif

static const char* IFACE   = "wlx00c0cab8318b";
static const char* DEST_IP = "127.0.0.1";
static const int   DEST_PORT = 5800;

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

/* ---------------- Radiotap parsing helpers ---------------- */

// Minimal radiotap header
#pragma pack(push,1)
struct rt_hdr_min {
  uint8_t  it_version;
  uint8_t  it_pad;
  uint16_t it_len;
  uint32_t it_present; // may be extended with bit31 set
};
#pragma pack(pop)

// Align offset according to radiotap field requirements
static inline size_t align_for_field(uint8_t field_idx, size_t off) {
  size_t align = 1;
  switch (field_idx) {
    case IEEE80211_RADIOTAP_TSFT: align = 8; break;
    case IEEE80211_RADIOTAP_CHANNEL:
    case IEEE80211_RADIOTAP_FHSS:
    case IEEE80211_RADIOTAP_LOCK_QUALITY:
    case IEEE80211_RADIOTAP_TX_ATTENUATION:
    case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
    case IEEE80211_RADIOTAP_RX_FLAGS:
    case IEEE80211_RADIOTAP_TX_FLAGS:
      align = 2; break;
    default: align = 1; break;
  }
  size_t rem = off % align;
  if (rem) off += (align - rem);
  return off;
}

// Return size of a radiotap field (only those we touch)
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
    default: return 0;
  }
}

struct RtStats {
  uint16_t rt_len{0};
  uint8_t  flags{0};              // radiotap Flags (0x10=FCS present, 0x20=DATAPAD)
  uint8_t  antenna[RX_ANT_MAX];
  int8_t   rssi[RX_ANT_MAX];      // SCHAR_MIN means "not present"
  int8_t   noise[RX_ANT_MAX];     // SCHAR_MAX means "not present"
  int      chains{0};
};

// Parse radiotap like rx.cpp: fill per-chain RSSI/NOISE; advance chain on ANTENNA.
static bool parse_radiotap_rxcpp_like(const uint8_t* p, size_t caplen, RtStats& rs)
{
  if (caplen < sizeof(rt_hdr_min)) return false;
  const rt_hdr_min* rh = reinterpret_cast<const rt_hdr_min*>(p);
  uint16_t it_len = rh->it_len;
  if (it_len > caplen || it_len < sizeof(rt_hdr_min)) return false;

  rs.rt_len = it_len;
  rs.flags = 0;
  rs.chains = 0;
  for (int i=0;i<RX_ANT_MAX;i++){ rs.antenna[i]=0xff; rs.rssi[i]=SCHAR_MIN; rs.noise[i]=SCHAR_MAX; }

  // collect present chain
  uint32_t presents[8]; int np=0;
  size_t poff = offsetof(rt_hdr_min, it_present);
  do {
    if (poff + 4 > it_len) break;
    uint32_t v = *(const uint32_t*)(p + poff);
    presents[np++] = v;
    poff += 4;
  } while (np < 8 && (presents[np-1] & 0x80000000u));

  size_t off = poff;
  int ant_idx = 0;

  for (int wi=0; wi<np; ++wi) {
    uint32_t pres = presents[wi];
    for (uint8_t f=0; f<32; ++f) {
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
            ant_idx++; // move to next chain (as in rx.cpp)
          }
          break;
        default: break;
      }
      off += sz;
    }
  }
  rs.chains = ant_idx;
  return true;
}

/* ----------------------------- main ----------------------------- */
int main() {
  // UDP socket (single)
  int us = socket(AF_INET, SOCK_DGRAM, 0);
  if (us < 0) { perror("socket"); return 1; }
  sockaddr_in dst{}; dst.sin_family=AF_INET; dst.sin_port=htons(DEST_PORT);
  inet_aton(DEST_IP, &dst.sin_addr);

  // PCAP capture
  char errbuf[PCAP_ERRBUF_SIZE] = {0};
  pcap_t* ph = pcap_create(IFACE, errbuf);
  if (!ph) { fprintf(stderr, "pcap_create(%s): %s\n", IFACE, errbuf); return 1; }
  (void)pcap_set_immediate_mode(ph, 1);
  if (pcap_activate(ph) != 0) {
    fprintf(stderr, "pcap_activate(%s): %s\n", IFACE, pcap_geterr(ph)); return 1;
  }

  fprintf(stderr, "RX on %s -> UDP %s:%d | stats every %d ms\n",
          IFACE, DEST_IP, DEST_PORT, STATS_PERIOD_MS);

  // Stats accumulators (per period)
  auto t0 = std::chrono::steady_clock::now();
  uint64_t bytes_period = 0;
  uint32_t rx_pkts_period = 0;
  int rssi_min =  127;   // dBm
  int rssi_max = -127;   // dBm
  int64_t rssi_sum = 0;  // for average
  uint32_t rssi_samples = 0;

  // Loss tracking (12-bit seq)
  bool have_seq = false;
  uint16_t expect_seq = 0;      // next expected seq (mod 4096)
  uint32_t lost_period = 0;     // lost packets (by seq gap) this period

  while (true) {
    struct pcap_pkthdr* hdr = nullptr;
    const u_char* pkt = nullptr;
    int rc = pcap_next_ex(ph, &hdr, &pkt);
    if (rc == 0) {
      // periodic stats check even on timeout
    } else if (rc < 0) {
      fprintf(stderr, "pcap_next_ex: %s\n", pcap_geterr(ph));
      break;
    } else if (pkt && hdr->caplen >= sizeof(rt_hdr_min)) {

      // Parse radiotap
      RtStats rs;
      if (!parse_radiotap_rxcpp_like(pkt, hdr->caplen, rs)) goto stats_tick;
      if (rs.rt_len >= hdr->caplen) goto stats_tick;

      const uint8_t* dot11 = pkt + rs.rt_len;
      size_t dlen = hdr->caplen - rs.rt_len;
      if (dlen < sizeof(dot11_hdr)) goto stats_tick;

      const dot11_hdr* h = reinterpret_cast<const dot11_hdr*>(dot11);
      uint16_t fc = le16toh(h->frame_control);
      uint8_t type = (fc >> 2) & 0x3;
      uint8_t subtype = (fc >> 4) & 0xF;
      if (type != 2) goto stats_tick; // only Data

      // MAC header length
      size_t hdr_len = sizeof(dot11_hdr);
      int qos = (subtype & 0x08) ? 1 : 0;
      if (qos) { if (dlen < hdr_len + 2) goto stats_tick; hdr_len += 2; }
      int order = (fc & 0x8000) ? 1 : 0;
      if (order) { if (dlen < hdr_len + 4) goto stats_tick; hdr_len += 4; }

      // DATAPAD alignment (radiotap flag 0x20)
      if (rs.flags & 0x20) {
        size_t aligned = (hdr_len + 3u) & ~3u;
        if (aligned > dlen) goto stats_tick;
        hdr_len = aligned;
      }

      // Payload and FCS handling (radiotap flag 0x10)
      const uint8_t* payload = dot11 + hdr_len;
      size_t payload_len = dlen - hdr_len;
      if ((rs.flags & 0x10) && payload_len >= 4) payload_len -= 4;
      if (payload_len == 0) goto stats_tick;

      // Sequence tracking (12-bit)
      uint16_t seq = (le16toh(h->seq_ctrl) >> 4) & 0x0FFF;
      if (!have_seq) {
        have_seq = true;
        expect_seq = (uint16_t)((seq + 1) & 0x0FFF);
      } else {
        if (seq != expect_seq) {
          // compute gap modulo 4096
          uint16_t gap = (uint16_t)((seq - expect_seq) & 0x0FFF);
          // if gap is small (normal forward jump), count as lost
          lost_period += gap;
          expect_seq = (uint16_t)((seq + 1) & 0x0FFF);
        } else {
          expect_seq = (uint16_t)((expect_seq + 1) & 0x0FFF);
        }
      }

      // Choose per-packet RSSI: take the best (max) across chains
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

      // Forward payload to UDP
      (void)sendto(us, payload, payload_len, 0, (sockaddr*)&dst, sizeof(dst));

      // Accumulate stats
      rx_pkts_period += 1;
      bytes_period   += payload_len;
    }

stats_tick:
    // Periodic stats output
    auto now = std::chrono::steady_clock::now();
    auto ms  = std::chrono::duration_cast<std::chrono::milliseconds>(now - t0).count();
    if (ms >= STATS_PERIOD_MS) {
      // data rate in kbps over the elapsed period
      double seconds = (double)ms / 1000.0;
      double kbps = seconds > 0.0 ? (bytes_period * 8.0 / 1000.0) / seconds : 0.0;

      // quality: rx / (rx + lost) * 100
      uint32_t expected = rx_pkts_period + lost_period;
      int quality = expected ? (int)((rx_pkts_period * 100.0) / expected + 0.5) : 100;

      // RSSI stats
      double rssi_avg = (rssi_samples > 0) ? ((double)rssi_sum / (double)rssi_samples) : 0.0;
      if (rssi_samples == 0) { rssi_min = 0; rssi_max = 0; }

      fprintf(stderr,
        "[STATS] period=%lld ms | pkts=%u lost=%u quality=%d%% | bytes=%llu rate=%.1f kbps | rssi min/avg/max = %d/%.1f/%d dBm\n",
        (long long)ms, rx_pkts_period, lost_period, quality,
        (unsigned long long)bytes_period, kbps,
        rssi_min, rssi_avg, rssi_max);

      // reset period accumulators
      t0 = now;
      bytes_period = 0;
      rx_pkts_period = 0;
      lost_period = 0;
      rssi_min = 127; rssi_max = -127; rssi_sum = 0; rssi_samples = 0;
    }
  }

  close(us);
  return 0;
}