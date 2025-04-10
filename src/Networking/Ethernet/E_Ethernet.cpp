/*
 * E_Ethernet.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/Ethernet/E_Ethernet.hpp>

namespace E {

static const std::set<ipv4_t> ip_broadcasts = {{
    {255, 255, 255, 255}, // IP broadcast
    {224, 0, 0, 5},       // OSPF multicast (AllSPFRouters)
    {224, 0, 0, 6},       // OSPF multicast (AllDRouters)
}};

Ethernet::Ethernet(Host &host)
    : HostModule("Ethernet", host), RoutingInfoInterface(host) {}
Ethernet::~Ethernet() {}
void Ethernet::packetArrived(std::string fromModule, Packet &&packet) {
  if (fromModule.compare("Host") == 0) {
    uint8_t first_byte, second_byte;
    packet.readData(12, &first_byte, 1);
    packet.readData(13, &second_byte, 1);

    if (first_byte == 0x08 && second_byte == 0x00) {
      this->sendPacket("IPv4", std::move(packet));
    } else if (first_byte == 0x86 && second_byte == 0xDD) {
      this->sendPacket("IPv6", std::move(packet));
    } else {
      this->print_log(NetworkLog::MODULE_ERROR, "Unsupported ethertype.");
      assert(0);
    }
  } else if (fromModule.compare("IPv4") == 0) {
    uint8_t first_byte = 0x08;
    uint8_t second_byte = 0x00;
    packet.writeData(12, &first_byte, 1);
    packet.writeData(13, &second_byte, 1);

    ipv4_t dst_ip;
    packet.readData(30, dst_ip.data(), 4);
    constexpr mac_t mac_broadcast = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    if (ip_broadcasts.find(dst_ip) != ip_broadcasts.end()) {
      ipv4_t src_ip;
      packet.readData(26, src_ip.data(), 4);
      int port = this->getRoutingTable(src_ip);
      auto src = this->getMACAddr(port);

      if (!src.has_value()) {
        printf("Unrecognized port: %d. Packet[%ld] is dropped.\n", port,
               packet.getUUID());
        return;
      }

      packet.writeData(0, mac_broadcast.data(), 6);
      packet.writeData(6, src.value().data(), 6);
    } else {
      int port = this->getRoutingTable(dst_ip);
      auto src = this->getMACAddr(port);
      auto dst = this->getARPTable(dst_ip);

      if (!src.has_value()) {
        printf("Unrecognized port: %d. Packet[%ld] is dropped.\n", port,
               packet.getUUID());
        return;
      }

      if (!dst.has_value()) {
        //printf(
          //  "Destination unreachable: %d.%d.%d.%d. Packet[%ld] is dropped.\n",
            //dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3], packet.getUUID());
        return;
      }

      packet.writeData(0, dst.value().data(), 6);
      packet.writeData(6, src.value().data(), 6);
    }
    this->sendPacket("Host", std::move(packet));
  } else if (fromModule.compare("IPv6") == 0) {
    uint8_t first_byte = 0x86;
    uint8_t second_byte = 0xDD;
    packet.writeData(12, &first_byte, 1);
    packet.writeData(13, &second_byte, 1);
    this->sendPacket("Host", std::move(packet));
  }
}

} // namespace E
