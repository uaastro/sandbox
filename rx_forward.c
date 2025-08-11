// rx_forward.c — приём 802.11 кадров (monitor) и форвардинг payload -> UDP 127.0.0.1:5800
// Фикс: если в Radiotap Flags указан FCS — отрезаем последние 4 байта.
// Сборка: gcc -O2 -Wall -o rx_forward rx_forward.c -lpcap
// Запуск: sudo ./rx_forward

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

enum { MAX_PACKET = 8192 };

/* 802.11 MAC header (без QoS) */
struct __attribute__((__packed__)) dot11_hdr {
  uint16_t frame_control;
  uint16_t duration;
  uint8_t  addr1[6];
  uint8_t  addr2[6];
  uint8_t  addr3[6];
  uint16_t seq_ctrl;
};

/* утилита печати MAC */
static void mac_to_str(const uint8_t m[6], char* out, size_t n) {
  snprintf(out, n, "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]);
}

/* Radiotap parse info */
typedef struct {
  uint16_t rt_len;        /* длина заголовка radiotap */
  uint8_t  flags_present; /* поле Flags присутствовало */
  uint8_t  flags;         /* значение radiotap Flags */
  int8_t   rssi_dbm[4];   /* по индексам антенн 0..3, 127 = нет данных */
  int8_t   noise_dbm[4];
  uint8_t  saw_antenna_idx;
} rt_info_t;

static void rtinfo_init(rt_info_t* ri){
  memset(ri, 0, sizeof(*ri));
  ri->rt_len = 0;
  ri->flags_present = 0;
  ri->flags = 0;
  ri->saw_antenna_idx = 0;
  for (int i=0;i<4;i++){ ri->rssi_dbm[i] = 127; ri->noise_dbm[i] = 127; }
}

static void step(size_t *off, size_t sz, size_t cap){
  if (*off + sz <= cap) *off += sz; else *off = cap;
}

/* Минимальный парсер Radiotap: читаем цепочку present-слов и несколько базовых полей */
static int parse_radiotap(const uint8_t* pkt, size_t caplen, rt_info_t* out)
{
  if (caplen < 8) return -1;
  uint16_t it_len = (uint16_t)(pkt[2] | (pkt[3]<<8));
  if (it_len > caplen) return -1;
  out->rt_len = it_len;

  /* прочитать present chain */
  size_t off = 4;
  uint32_t presents[8]; int np=0;
  do {
    if (off + 4 > it_len) break;
    uint32_t pres = (uint32_t)pkt[off] | ((uint32_t)pkt[off+1]<<8) | ((uint32_t)pkt[off+2]<<16) | ((uint32_t)pkt[off+3]<<24);
    presents[np++] = pres;
    off += 4;
  } while (np < 8 && (presents[np-1] & 0x80000000u));

  size_t foff = off;

  for (int wi=0; wi<np; ++wi) {
    uint32_t p = presents[wi];

    /* bit 0: TSFT (8) */            if (p & (1u<<0))  step(&foff, 8, it_len);

    /* bit 1: Flags (1) */
    if (p & (1u<<1)) {
      if (foff + 1 <= it_len) { out->flags_present = 1; out->flags = pkt[foff]; }
      step(&foff, 1, it_len);
    }

    /* bit 2: Rate (1) */            if (p & (1u<<2))  step(&foff, 1, it_len);
    /* bit 3: Channel (4) */         if (p & (1u<<3))  step(&foff, 4, it_len);
    /* bit 4: FHSS (2) */            if (p & (1u<<4))  step(&foff, 2, it_len);

    /* bit 5: dBm Antenna Signal (1) */
    if (p & (1u<<5)) {
      if (foff + 1 <= it_len) {
        int8_t sig = (int8_t)pkt[foff];
        int ai = out->saw_antenna_idx < 4 ? out->saw_antenna_idx : 0;
        out->rssi_dbm[ai] = sig;
      }
      step(&foff, 1, it_len);
    }

    /* bit 6: dBm Antenna Noise (1) */
    if (p & (1u<<6)) {
      if (foff + 1 <= it_len) {
        int8_t nz = (int8_t)pkt[foff];
        int ai = out->saw_antenna_idx < 4 ? out->saw_antenna_idx : 0;
        out->noise_dbm[ai] = nz;
      }
      step(&foff, 1, it_len);
    }

    /* bit 7: Lock Quality (2) */    if (p & (1u<<7))  step(&foff, 2, it_len);
    /* bit 8: TX Attenuation (2) */  if (p & (1u<<8))  step(&foff, 2, it_len);
    /* bit 9: dB TX Atten (2) */     if (p & (1u<<9))  step(&foff, 2, it_len);
    /* bit10: dBm TX Power (1) */    if (p & (1u<<10)) step(&foff, 1, it_len);

    /* bit11: Antenna index (1) */
    if (p & (1u<<11)) {
      if (foff + 1 <= it_len) out->saw_antenna_idx = pkt[foff];
      step(&foff, 1, it_len);
    }

    /* bit12: dB Ant Sig (1) */      if (p & (1u<<12)) step(&foff, 1, it_len);
    /* bit13: dB Ant Noise (1) */    if (p & (1u<<13)) step(&foff, 1, it_len);
    /* bit14: RX Flags (2) */        if (p & (1u<<14)) step(&foff, 2, it_len);
    /* bit15: TX Flags (2) */        if (p & (1u<<15)) step(&foff, 2, it_len);
    /* bit19: MCS (3) */             if (p & (1u<<19)) step(&foff, 3, it_len);
    /* Остальные поля пропускаем (для задачи не критично) */
  }

  return 0;
}

static volatile int g_run = 1;
static void on_sigint(int){ g_run = 0; }

int main(void)
{
  signal(SIGINT, on_sigint);

  /* UDP отправитель */
  int us = socket(AF_INET, SOCK_DGRAM, 0);
  if (us < 0) { perror("socket"); return 1; }
  struct sockaddr_in dst = {0};
  dst.sin_family = AF_INET;
  dst.sin_port = htons(DEST_PORT);
  if (!inet_aton(DEST_IP, &dst.sin_addr)) { fprintf(stderr,"inet_aton failed\n"); return 1; }

  /* PCAP */
  char errbuf[PCAP_ERRBUF_SIZE] = {0};
  pcap_t* ph = pcap_create(IFACE, errbuf);
  if (!ph) { fprintf(stderr, "pcap_create(%s): %s\n", IFACE, errbuf); return 1; }
  (void)pcap_set_immediate_mode(ph, 1);
  if (pcap_activate(ph) != 0) {
    fprintf(stderr, "pcap_activate(%s): %s\n", IFACE, pcap_geterr(ph));
    return 1;
  }

  fprintf(stderr, "RX on %s -> UDP %s:%d\n", IFACE, DEST_IP, DEST_PORT);

  while (g_run) {
    struct pcap_pkthdr* hdr = NULL;
    const u_char* pkt = NULL;
    int rc = pcap_next_ex(ph, &hdr, &pkt);
    if (rc == 0) continue;      /* timeout */
    if (rc < 0) { fprintf(stderr, "pcap_next_ex: %s\n", pcap_geterr(ph)); break; }
    if (!pkt) continue;

    if (hdr->caplen < 8) continue;

    /* Radiotap */
    rt_info_t rti; rtinfo_init(&rti);
    if (parse_radiotap(pkt, hdr->caplen, &rti) != 0) continue;
    if (rti.rt_len >= hdr->caplen) continue;

    const uint8_t* dot11 = pkt + rti.rt_len;
    size_t dlen = hdr->caplen - rti.rt_len;
    if (dlen < sizeof(struct dot11_hdr)) continue;

    const struct dot11_hdr* h = (const struct dot11_hdr*)dot11;

    /* Проверка: тип Data? */
    uint16_t fc = le16toh(h->frame_control);
    uint8_t type = (fc >> 2) & 0x3;
    uint8_t subtype = (fc >> 4) & 0xF;
    if (type != 2) continue; // только Data

    /* Базовая длина заголовка */
    size_t hdr_len = sizeof(struct dot11_hdr);

    /* Если QoS Data — добавить 2 байта QoS Control */
    int qos = (subtype & 0x08) ? 1 : 0; // QoS subtypes: 8..15
    if (qos) {
      if (dlen < hdr_len + 2) continue;
      hdr_len += 2;
    }

    /* Если Order=1 и есть HT-Control — добавить 4 байта */
    int order = (fc & 0x8000) ? 1 : 0; // bit Order
    if (order) {
      if (dlen < hdr_len + 4) continue;
      hdr_len += 4;
    }

    if (dlen < hdr_len) continue;

    const uint8_t* payload = dot11 + hdr_len;
    size_t payload_len = dlen - hdr_len;

    /* Если драйвер оставил FCS (Radiotap Flags bit 0x10) — убрать 4 байта */
    const uint8_t RTAP_F_FCS = 0x10;
    if (rti.flags_present && (rti.flags & RTAP_F_FCS)) {
      if (payload_len >= 4) payload_len -= 4;
    }
    if (payload_len == 0) continue;

    /* seq (12 бит) */
    uint16_t seq_ctrl = le16toh(h->seq_ctrl);
    uint16_t seq = (seq_ctrl >> 4) & 0x0FFF;

    /* лог по двум антеннам (если драйвер дал значения) */
    char mac2[32]; mac_to_str(h->addr2, mac2, sizeof(mac2));
    fprintf(stderr, "RX seq=%u from=%s len=%zu flags=0x%02x  RSSI[0]=%d RSSI[1]=%d  Noise[0]=%d Noise[1]=%d\n",
            seq, mac2, payload_len, (unsigned)rti.flags,
            (int)rti.rssi_dbm[0], (int)rti.rssi_dbm[1],
            (int)rti.noise_dbm[0], (int)rti.noise_dbm[1]);

    /* форвардинг payload в UDP */
    sendto(us, payload, payload_len, 0, (struct sockaddr*)&dst, sizeof(dst));
  }

  if (ph) pcap_close(ph);
  close(us);
  return 0;
}