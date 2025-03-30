/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#include "TCPAssignment.hpp"
#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>

namespace E {

TCPAssignment::TCPAssignment(Host &host)
    : HostModule("TCP", host), RoutingInfoInterface(host),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      TimerModule("TCP", host) {}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize() {TCP_state = CLOSE_state;}

void TCPAssignment::finalize() {}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  //TCP_state도 적절히 수정해야함                                  
  switch (param.syscallNumber) {
  case SOCKET:
    this->syscall_socket(syscallUUID, pid, std::get<int>(param.params[0]),
                        std::get<int>(param.params[1]), std::get<int>(param.params[2]));
    break;
  case CLOSE:
    this->syscall_close(syscallUUID, pid, std::get<int>(param.params[0]));
    break;
  case READ:
    // this->syscall_read(syscallUUID, pid, std::get<int>(param.params[0]),
    //                    std::get<void *>(param.params[1]),
    //                    std::get<int>(param.params[2]));
    break;
  case WRITE:
    // this->syscall_write(syscallUUID, pid, std::get<int>(param.params[0]),
    //                     std::get<void *>(param.params[1]),
    //                     std::get<int>(param.params[2]));
    break;
  case CONNECT:
    this->syscall_connect(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        (socklen_t)std::get<int>(param.params[2]));
      
    break;
  case LISTEN:
    // this->syscall_listen(syscallUUID, pid, std::get<int>(param.params[0]),
    //                      std::get<int>(param.params[1]));
    break;
  case ACCEPT:
    // this->syscall_accept(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case BIND:
    this->syscall_bind(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        (socklen_t)std::get<int>(param.params[2]));
    break;
  case GETSOCKNAME:
    // this->syscall_getsockname(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case GETPEERNAME:
    // this->syscall_getpeername(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  default:
    assert(0);
  }
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol) {
  int fd = this->createFileDescriptor(pid);
  this->returnSystemCall(syscallUUID, fd);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen) {
  
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen) {
  Packet SYN(100);
  uint16_t data = 0b0100; //syn

  //SYN packet에 정보 추가

  SYN.writeData(46, &data, 2);
  sendPacket("IPv4", SYN);
  TCP_state = SYN_SENT_state;
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd) {
  this->removeFileDescriptor(pid, fd);
  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  
  // 1. 패킷 파싱
  uint32_t srcIP, destIP;
  uint16_t srcPort, destPort, seqNum, ackNum, flags;
  
  packet.readData(14 + 12, &srcIP, 4);  // IPv4 헤더에서 출발지 IP 주소 읽기
  packet.readData(14 + 16, &destIP, 4); // IPv4 헤더에서 목적지 IP 주소 읽기
  packet.readData(34, &srcPort, 2);     // TCP 헤더에서 출발지 포트 읽기
  packet.readData(36, &destPort, 2);    // TCP 헤더에서 목적지 포트 읽기
  packet.readData(38, &seqNum, 4);      // TCP 헤더에서 시퀀스 번호 읽기
  packet.readData(42, &ackNum, 4);      // TCP 헤더에서 ACK 번호 읽기
  packet.readData(46, &flags, 2);       // TCP 헤더에서 플래그 읽기
  
  srcPort = ntohs(srcPort);
  destPort = ntohs(destPort);
  seqNum = ntohl(seqNum);
  ackNum = ntohl(ackNum);
  flags = ntohs(flags);

  //source dest 주소 바꾸고, ack 번호는 seq # +1로 세팅하고,seq 번호는 seq 변수에 1 더해서 ㄱㄱ
  //flag는 밑에 switch에서 이미 함.

  // Filling in all TCP header fields (e.g., source/destination ports, sequence and 
  //  acknowledgment numbers, flags, window size, etc.)
  // Appending the payload (user/application data)
  // 연결한 소켓에다가 payload를 적으면 될 듯?
  // Computing and setting the TCP checksum
  // Passing the completed segment to the IP layer for transmission
  
  bool syn = flags & 0b0100;
  bool ack = flags & 0b0010;
  bool fin = flags & 0b0001;
  
  // 3. TCP 상태 전이 처리
  switch (TCP_state) {
    case (CLOSE_state):

    case (LISTEN_state):
      if (syn){
        Packet SYNACK(100);
        uint16_t data = 0b0110; //syn, ack
        SYNACK.writeData(46, &data, 2);
        sendPacket(fromModule, SYNACK);
        TCP_state = SYN_RCVD_state;
      }
      break;
    case (SYN_RCVD_state):
      if (ack){
        TCP_state = ESTABLISHED_state;
      }
      break;
    case (SYN_SENT_state):
      if (syn && ack){
        Packet ACK(100);
        uint16_t data = 0b0010; //ack
        ACK.writeData(46, &data, 2);
        sendPacket(fromModule, ACK);
        TCP_state = SYN_RCVD_state;
      }
      break;
    case (ESTABLISHED_state):
      if (fin){
        Packet FIN(100);
        uint16_t data = 0b0001; //fin
        FIN.writeData(46, &data, 2);
        sendPacket(fromModule, FIN);
        TCP_state = CLOSE_WAIT_state;
      }
      break;
    case (CLOSE_WAIT_state):
      break;
    case (FIN_WAIT_1_state): 
      if (fin){
        Packet ACK(100);
        uint16_t data = 0b0010; //ack
        ACK.writeData(46, &data, 2);
        if (ack) TCP_state = TIME_WAIT_state;
        else TCP_state = CLOSING_state;
      }
      else if (ack){
        TCP_state = FIN_WAIT_2_state;
      }
      break;
    case (CLOSING_state):
      if (ack){
        TCP_state = TIME_WAIT_state;
      }
      break;
    case (LAST_ACK_state):
      if (ack){
        TCP_state = CLOSE_state;
      }
      break;
    case (FIN_WAIT_2_state):
      if (fin){
        Packet ACK(100);
        uint16_t data = 0b0010; //ack
        ACK.writeData(46, &data, 2);
        TCP_state = TIME_WAIT_state;
      }
      break;
    case (TIME_WAIT_state):
      TCP_state = CLOSE_state;
      break;
    default:
      break;
  }
}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

} // namespace E
