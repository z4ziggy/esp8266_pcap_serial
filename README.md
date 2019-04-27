![](wireshark.gif)

# ESP8266 PCAP Sniffer

ESP8266 Sniffer sketch which outputs PCAP data via Serial. Max packet size is
128 bytes. Use the sniffer to stream 802.11 packets from ESP8266 to Wireshark
or dump into a PCAP file.

## Overview

A fork of [esp8266_pcap_serial](https://github.com/spacehuhn/ArduinoPcap/blob/master/examples/esp8266_pcap_serial/esp8266_pcap_serial.ino) which strips out wifi_pkt_rx_ctrl_t struct before
streaming to wireshark. It still streams up to 128 bytes only, since this is a
SDK limitation. For unlimited buffer size, refer to my ESP_RTOS sniffer.

To use this sniffer, flash the ESP8266 with this sketch, run the SerialShark.py 
script, and reset the ESP8266 to start sniffing.
 
**Note:** Only 802.11 packets are sniffed atm. Change to your liking.

## Compile & Flash

Load the sketch to your Arduino IDE and flash your ESP8266-based device. You
must install ArduinoPcap library first.

Run `SerialShark.py` to forward the PCAP stream from the ESP8266 to Wireshark:

```sh
~/Arduino/libraries/ArduinoPcap/extras/SerialShark.py
```
