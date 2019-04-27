/*
 * A fork of esp8266_pcap_serial which strips out wifi_pkt_rx_ctrl_t struct 
 * before streaming to wireshark. It still streams up to 128 bytes only, since 
 * this is a SDK limitation. For unlimited buffer size, refer to my ESP_RTOS 
 * sniffer.
 * 
 * To use this sniffer, flash the ESP8266 with this sketch, run the 
 * SerialShark.py script, and reset the ESP8266 to start sniffing.
 * 
 * Note: Only 802.11 packets are sniffed atm. Change to your liking.
 */
#include <ESP8266WiFi.h>
#include <TimeLib.h>
#include <PCAP.h>

//===== SETTINGS =====//
#define CHANNEL         9       // channel to sniff
#define BAUD_RATE       115200  // baud rate for serial
#define CHANNEL_HOPPING false   // if true it will scan on all channels
#define MAX_CHANNEL     11      // max channels to hop - only necessary if CHANNEL_HOPPING is true
#define HOP_INTERVAL    500     // in ms (only necessary if CHANNEL_HOPPING is true)
#define LED             2       // led pin

typedef struct
{
    signed rssi:8;            /**< signal intensity of packet */
    unsigned rate:4;          /**< data rate */
    unsigned is_group:1;
    unsigned :1;              /**< reserve */
    unsigned sig_mode:2;      /**< 0:is not 11n packet; 1:is 11n packet */
    unsigned legacy_length:12;
    unsigned damatch0:1;
    unsigned damatch1:1;
    unsigned bssidmatch0:1;
    unsigned bssidmatch1:1;
    unsigned mcs:7;           /**< if is 11n packet, shows the modulation(range from 0 to 76) */
    unsigned cwb:1;           /**< if is 11n packet, shows if is HT40 packet or not */
    unsigned HT_length:16;             /**< reserve */
    unsigned smoothing:1;     /**< reserve */
    unsigned not_sounding:1;  /**< reserve */
    unsigned :1;              /**< reserve */
    unsigned aggregation:1;   /**< Aggregation */
    unsigned stbc:2;          /**< STBC */
    unsigned fec_coding:1;    /**< Flag is set for 11n packets which are LDPC */
    unsigned sgi:1;           /**< SGI */
    unsigned rxend_state:8;
    unsigned ampdu_cnt:8;     /**< ampdu cnt */
    unsigned channel:4;       /**< which channel this packet in */
    unsigned :4;              /**< reserve */
    signed noise_floor:8;
} wifi_pkt_rx_ctrl_t;

typedef struct 
{
    wifi_pkt_rx_ctrl_t rx_ctrl; /**< metadata header */
    uint8_t payload[0];       /**< Data or management payload. Length of payload is described by rx_ctrl.sig_len. Type of content determined by packet type argument of callback. */
} wifi_promiscuous_pkt_t;

PCAP pcap = PCAP();
uint8_t Channel = CHANNEL;
uint8_t led = 0;

void sniffer_handler(uint8_t *buff, uint16_t len)
{
    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
    uint32_t timestamp = now();
    uint32_t microseconds = (unsigned int)(micros() - millis() * 1000);
    pcap.newPacketSerial(timestamp, microseconds, len, (uint8_t*)ppkt->payload);
}

void setup()
{
    pinMode(LED, OUTPUT);
    
    wifi_set_channel(CHANNEL);
    wifi_set_opmode(STATION_MODE);
    wifi_promiscuous_enable(0);
    WiFi.disconnect();
    wifi_set_promiscuous_rx_cb(sniffer_handler);
    wifi_promiscuous_enable(1);
    
    Serial.begin(BAUD_RATE);
    delay(10);
    Serial.println("<<START>>");
    pcap.startSerial();
}

void loop()
{
    digitalWrite(LED, led ^= 1);
    delay(HOP_INTERVAL);
    
    if (CHANNEL_HOPPING)
    {
            Channel = (Channel % MAX_CHANNEL) + 1;
            wifi_set_channel(Channel);
    }
}
