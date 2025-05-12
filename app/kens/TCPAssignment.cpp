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
#include <E/E_TimeUtil.hpp>
#include <cerrno>

#include <chrono>
#include <thread>

namespace E {

TCPAssignment::TCPAssignment(Host &host)
    : HostModule("TCP", host), RoutingInfoInterface(host),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      TimerModule("TCP", host) {}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize() {
  TCP_state = CLOSE_state;
  seq = 123456;
  sock_table.clear();
  SYNACK_queue.clear();
  stop = false;
}

void TCPAssignment::finalize() {}

bool isNonBlocking(int sockfd){ return false; }

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  //printf("param0 : %d, syscallnum : %d\n", std::get<int>(param.params[0]), param.syscallNumber);
                                 
  switch (param.syscallNumber) {
  case SOCKET:
    this->syscall_socket(syscallUUID, pid, std::get<int>(param.params[0]),
                        std::get<int>(param.params[1]));
    break;
  case CLOSE:
    this->syscall_close(syscallUUID, pid, std::get<int>(param.params[0]));
    break;
  case READ:
    this->syscall_read(syscallUUID, pid, std::get<int>(param.params[0]),
                       std::get<void *>(param.params[1]),
                       std::get<int>(param.params[2]));
    break;
  case WRITE:
    this->syscall_write(syscallUUID, pid, std::get<int>(param.params[0]),
                        std::get<void *>(param.params[1]),
                        std::get<int>(param.params[2]));
    break;
  case CONNECT:
    this->syscall_connect(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        (socklen_t)std::get<int>(param.params[2]));
    break;
  case LISTEN:
    this->syscall_listen(syscallUUID, pid, std::get<int>(param.params[0]),
                         std::get<int>(param.params[1]));
    break;
  case ACCEPT:
    this->syscall_accept(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case BIND:
    this->syscall_bind(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        (socklen_t)std::get<int>(param.params[2]));
    break;
  case GETSOCKNAME:
    this->syscall_getsockname(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case GETPEERNAME:
    this->syscall_getpeername(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  default:
    assert(0);
  }
}

void TCPAssignment::send_ACK(SocketInfo& sock){
  uint8_t tcp_segment[sizeof(tcphdr)];
  ipv4_t dest_ip;
  tcphdr header;
  header.th_dport = sock.peerport;
  header.th_sport = sock.port;
  Packet packet(54);
  packet.writeData(30, &sock.peerip, 4);
  packet.readData(30, &dest_ip, 4);
  int port = getRoutingTable(dest_ip);
  std::optional<ipv4_t> src_IP = getIPAddr(port);
  ipv4_t src_ip = src_IP.value();
  packet.writeData(26, &src_ip, 4);
  header.th_win = 200;
  header.th_off = 5;
  header.th_flags = TH_ACK;
  header.th_seq = htonl(sock.nextseqnum);
  header.th_ack = htonl(sock.readacknum);
  header.th_sum = 0;
  packet.writeData(34, &header, sizeof(tcphdr));
  packet.readData(34, tcp_segment, sizeof(tcphdr));
  header.th_sum = (~ntohs(NetworkUtil::tcp_sum(sock.ip, sock.peerip, tcp_segment, sizeof(tcphdr))))&0xFFFF;
  packet.writeData(34, &header, sizeof(tcphdr));
  sendPacket("IPv4", std::move(packet));
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int sockfd, void *buf, size_t count){

  //printf("read\n");

  
  SocketInfo& sock = sock_table[{pid, sockfd}];

  if (sock.recv_len==0){
    sock.read_requests.emplace_back(syscallUUID, buf, count);
    return;
  }

  int write_len = (sock.recv_len < count) ? sock.recv_len : count;

  memcpy(buf, sock.recv_buffer, write_len);

  memmove(sock.recv_buffer, sock.recv_buffer + write_len, sock.recv_len-write_len);

  sock.recv_len -= write_len;

  sock.readacknum+=write_len;

  send_ACK(sock);

  this->returnSystemCall(syscallUUID, write_len);
}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int sockfd, void *buf, size_t count){

  SocketInfo& sock = sock_table[{pid, sockfd}];

  //uint16_t write_size = (m<(sock.rwnd-sock.nextseqnum+sock.send_base))?m:(sock.rwnd-sock.nextseqnum+sock.send_base);

  uint16_t write_size = (1024<count)?1024:count;

  if(sock.nextseqnum-sock.send_base+write_size < sock.rwnd){
    ipv4_t dest_ip;

    uint8_t tcp_segment[5000];

    tcphdr header;
    header.th_dport = sock.peerport;
    header.th_sport = sock.port;

    Packet packet(write_size+54);
    packet.writeData(30, &sock.peerip, 4);
    packet.readData(30, &dest_ip, 4);
    int port = getRoutingTable(dest_ip);
    std::optional<ipv4_t> src_IP = getIPAddr(port);
    ipv4_t src_ip = src_IP.value();
    packet.writeData(26, &src_ip, 4);

    //printf("%d.%d.%d.%d %d.%d.%d.%d %d %d\n", src_ip[0], src_ip[1], src_ip[2], src_ip[3], dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3], header.th_sport, header.th_dport);

    header.th_seq = htonl(sock.nextseqnum);
    //printf("write seq# : %u\n", htonl(header.th_seq));
    header.th_win = htons(sock.rwnd);
    header.th_off = 5;
    header.th_flags = TH_ACK;
    header.th_x2 = 0;
    
    header.th_ack = htonl(sock.peer_seq_num+1);

    packet.writeData(54, buf, write_size);

    header.th_sum = 0;
    packet.writeData(34, &header, sizeof(tcphdr));
    packet.readData(34, tcp_segment, sizeof(tcphdr) + write_size);
    uint32_t srcip, destip;

    packet.readData(26, &srcip, 4);
    packet.readData(30, &destip, 4);
    header.th_sum = (~ntohs(NetworkUtil::tcp_sum(srcip, destip, tcp_segment, sizeof(tcphdr) + write_size)))&0xFFFF;
    packet.writeData(34, &header, sizeof(tcphdr));

    sendPacket("IPv4", std::move(packet));

    this->returnSystemCall(syscallUUID, write_size);

    Time time = TCPAssignment::getCurrentTime();

    std::tuple<int, int, bool, uint32_t, uint32_t, uint16_t, uint16_t, Packet> payload = std::make_tuple(pid, sockfd, false, srcip, destip, header.th_sport, header.th_dport, packet.clone());
  
    sock.timerkeys[sock.nextseqnum] = addTimer(payload, time+TimeUtil::makeTime(100, TimeUtil::MSEC));

    sock.nextseqnum += write_size;

  }
  else{
    sock.write_requests.emplace_back(write_size);  
    memcpy(sock.send_buffer + sock.sb_pointer, buf, write_size);
    sock.sb_pointer += write_size;
    this->returnSystemCall(syscallUUID, write_size);
  }
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type) {
  //assert(false);
  int fd = this->createFileDescriptor(pid);
  this->returnSystemCall(syscallUUID, fd);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen) {
  
  if (!addr || addrlen < sizeof(struct sockaddr_in)) {
    this->returnSystemCall(syscallUUID, EINVAL);
    return;
  }

  struct sockaddr_in *sock_addr = reinterpret_cast<struct sockaddr_in *>(addr);

  // AF_INET만 허용
  if (sock_addr->sin_family != AF_INET) {
      this->returnSystemCall(syscallUUID, EAFNOSUPPORT);
      return;
  }

  uint32_t ip_addr = sock_addr->sin_addr.s_addr;
  uint16_t port = sock_addr->sin_port;

  auto IPnPort = sock_table.find({pid, sockfd});
  if (IPnPort != sock_table.end()) {
      uint32_t existing_ip = IPnPort->second.ip;
      uint16_t existing_port = IPnPort->second.port;

      if (existing_ip == ip_addr && existing_port == port) {
          this->returnSystemCall(syscallUUID, 0); // 이미 동일한 주소로 바인딩 → 성공
          return;
      } else {
          this->returnSystemCall(syscallUUID, -EINVAL); // 다른 주소로 바인딩 시도 → 오류
          return;
      }
  }

  // 바인딩된 주소/포트 중복 확인
  for (const auto &[key, value] : sock_table) {
      uint32_t bound_ip = value.ip;
      uint16_t bound_port = value.port;

      // 포트가 동일하고, IP가 동일하거나 INADDR_ANY(0.0.0.0)로 설정된 경우 충돌
      if (bound_port == port && (bound_ip == ip_addr || bound_ip == INADDR_ANY || ip_addr == INADDR_ANY)) {
          this->returnSystemCall(syscallUUID, EADDRINUSE);
          return;
      }
  }

  // 바인딩 정보 저장
  sock_table[{pid, sockfd}] = {ip_addr, port, false};
  sock_table[{pid, sockfd}].backlog = 1;
  sock_table[{pid, sockfd}].left_connect_place = 1;
  sock_table[{pid, sockfd}].connected = false;
  sock_table[{pid, sockfd}].rwnd = 1024;
  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog) {
  // 소켓이 바인딩되었는지 확인
  auto it = sock_table.find({pid, sockfd});
  if (it == sock_table.end()) {
      this->returnSystemCall(syscallUUID, EINVAL); // 바인딩되지 않은 소켓
      return;
  }

  // 이미 listen 상태인지 확인
  if (it->second.listen_state) {
      this->returnSystemCall(syscallUUID, 0); // 이미 listen 상태라면 성공
      return;
  }

  if (backlog < 0) {
    backlog = 0;
  }

  it->second.listen_state = true;
  it->second.left_connect_place = backlog;
  it->second.backlog = backlog;
  //printf("backlog : %d\n", backlog);
  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  
  //usleep 한 다음에 취소하는 식으로 시간 제한 둬야 할지도
  if (sock_table[{pid, sockfd}].accept_queue.empty()){
    sock_table[{pid, sockfd}].accept_requests[{pid, sockfd}] = {syscallUUID, addr, addrlen};
    return;
  }

  auto [srcip, destip, srcport, destport] = sock_table[{pid, sockfd}].accept_queue.front();
  sock_table[{pid, sockfd}].accept_queue.pop_front();

  struct sockaddr_in *client_addr = reinterpret_cast<struct sockaddr_in *>(addr);
  client_addr->sin_family = AF_INET;
  client_addr->sin_addr.s_addr = destip;
  client_addr->sin_addr.s_addr = destip;
  client_addr->sin_port = destport;

  // 새로운 소켓 파일 디스크립터 할당
  int new_sockfd = this->createFileDescriptor(pid);  // 새로운 소켓을 할당하는 함수
  if (new_sockfd <= 0) {
      this->returnSystemCall(syscallUUID, -ENOMEM); // 새 소켓 할당 실패
      return;
  }

  sock_table[{pid, new_sockfd}] = {destip, destport, false, 0, {}};
  sock_table[{pid, new_sockfd}].peerip = srcip;
  sock_table[{pid, new_sockfd}].peerport = srcport;
  sock_table[{pid, new_sockfd}].connected = true;

  this->returnSystemCall(syscallUUID, new_sockfd);

}

uint16_t TCPAssignment::allocateEphemeralPort() {
  for (uint16_t port = 49152; port <= 65535; ++port) {
      bool used = false;
      for (const auto& [key, value] : sock_table) {
          if (value.port == port) {
              used = true;
              break;
          }
      }
      if (!used) return port;
  }
  throw std::runtime_error("No available ephemeral port");
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen) {

  // connect syscall 내부에 추가

  struct sockaddr_in *server_addr = reinterpret_cast<struct sockaddr_in *>(addr);

  //printf("connect : %d %d %u\n", pid, sockfd, Socket.ip);

  Packet packet (54);
  tcphdr header;

  uint32_t srcip, destip = server_addr->sin_addr.s_addr;
  header.th_dport = server_addr->sin_port;
  
  packet.writeData(30, &destip, 4);

  ipv4_t dest_ip;
  packet.readData(30, &dest_ip, 4);
  int port = getRoutingTable(dest_ip);
  std::optional<ipv4_t> src_IP = getIPAddr(port);
  ipv4_t src_ip = src_IP.value();
  packet.writeData(26, &src_ip, 4);

  packet.readData(26, &srcip, 4);
  
  auto it = sock_table.find({pid, sockfd});
  if (it == sock_table.end()) {
    header.th_sport = htons(0);
    sock_table[{pid, sockfd}] = {srcip, header.th_sport};
  }
  else{
    header.th_sport = sock_table[{pid, sockfd}].port;
  }

  uint8_t tcp_segment[sizeof(tcphdr)];

  SocketInfo& Socket = sock_table[{pid, sockfd}];
  Socket.rwnd = 51200;

  header.th_seq = htonl(Socket.nextseqnum++);
  header.th_ack = 0;
  header.th_flags = TH_SYN; //syn
  header.th_win = htons(Socket.rwnd);
  header.th_off = 5;
  header.th_x2 = 0;

  header.th_sum = 0;
  packet.writeData(34, &header, sizeof(tcphdr));
  packet.readData(34, tcp_segment, sizeof(tcphdr));

  header.th_sum = (~ntohs(NetworkUtil::tcp_sum(destip, srcip, tcp_segment, sizeof(tcphdr))))&0xFFFF;

  packet.writeData(34, &header, sizeof(tcphdr));
  
  Packet packet2 = packet.clone();

  sock_table[{pid, sockfd}].peerip = destip;
  sock_table[{pid, sockfd}].peerport = header.th_dport;

  sendPacket("IPv4", std::move(packet));
  //printf("sent syn\n");


  Time time = TCPAssignment::getCurrentTime();

  std::tuple<int, int, bool, uint32_t, uint32_t, uint16_t, uint16_t, Packet> payload = std::make_tuple(pid, sockfd, true, srcip, header.th_sport,  destip, header.th_dport, packet2);

  UUID timerkey = addTimer(payload, time + TimeUtil::makeTime(100, TimeUtil::MSEC));

  SYNACK_queue[{destip, header.th_dport}] = {syscallUUID, timerkey};

}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  // fd가 바인딩되어 있는지 확인
  auto it = sock_table.find({pid, sockfd});
  if (it == sock_table.end()) {
      this->returnSystemCall(syscallUUID, -EBADF); // 해당 소켓이 존재하지 않음
      return;
  }

  // addrlen이 NULL이면 에러
  if (!addrlen || !addr || *addrlen < sizeof(struct sockaddr_in)) {
      this->returnSystemCall(syscallUUID, -EINVAL);
      return;
  }

  struct sockaddr_in *sock_addr = reinterpret_cast<struct sockaddr_in *>(addr);
  sock_addr->sin_family = AF_INET;
  sock_addr->sin_addr.s_addr = it->second.ip;  // 저장된 IP 주소
  sock_addr->sin_port = it->second.port;        // 저장된 포트 번호

  // addrlen을 업데이트 (호출한 프로세스가 변경된 크기를 알도록)
  *addrlen = sizeof(struct sockaddr_in);

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
    // fd가 바인딩되어 있는지 확인
  auto it = sock_table.find({pid, sockfd});
  if (it == sock_table.end()) {
      this->returnSystemCall(syscallUUID, -EBADF); // 해당 소켓이 존재하지 않음
      return;
  }

  // addrlen이 NULL이면 에러
  if (!addrlen || !addr || *addrlen < sizeof(struct sockaddr_in)) {
      this->returnSystemCall(syscallUUID, -EINVAL);
      return;
  }

  struct sockaddr_in *sock_addr = reinterpret_cast<struct sockaddr_in *>(addr);
  sock_addr->sin_family = AF_INET;
  sock_addr->sin_addr.s_addr = it->second.peerip;  // 저장된 IP 주소
  sock_addr->sin_port = it->second.peerport;        // 저장된 포트 번호

  // addrlen을 업데이트 (호출한 프로세스가 변경된 크기를 알도록)
  *addrlen = sizeof(struct sockaddr_in);

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd) {
  
  if(sock_table[{pid, fd}].sb_pointer == 0){
    sock_table.erase({pid, fd});
  }
  else{
    sock_table[{pid, fd}].close_signal = true;
  }

  this->removeFileDescriptor(pid, fd);
  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  
  tcphdr header;
  packet.readData(34, &header, sizeof(tcphdr)); 

  uint32_t srcip, destip;

  packet.readData(26, &srcip, 4);
  packet.readData(30, &destip, 4);

  uint8_t tcp_segment[5000];
  packet.readData(34, tcp_segment, packet.getSize()-34);
  if(((~ntohs(NetworkUtil::tcp_sum(srcip, destip, tcp_segment, packet.getSize()-34)))&0xFFFF)!=0)
    return;

  bool syn = header.th_flags & TH_SYN;  // 0000 0010 → SYN
  bool ack = header.th_flags & TH_ACK;
  bool fin = header.th_flags & TH_FIN;

  SocketInfo* Socket = nullptr;
  int pid, sockfd;

  //std::cout << ((~ntohs(NetworkUtil::tcp_sum(srcip, destip, tcp_segment, packet.getSize()-34)))&0xFFFF) << std::endl;

  if(header.th_flags != TH_SYN){
    for (auto& [key, info] : sock_table) {
      //std::cout << "Socket Info : " << info.ip << " " << info.port << " "  << info.peerip << " "  << info.peerport << " "  << info.connected << std::endl;

      if ((info.ip == destip || info.ip == 0) && info.port == header.th_dport && info.peerip == srcip && info.peerport == header.th_sport && info.connected == true) {
        pid = key.first;
        sockfd = key.second;
        Socket = &info;
        break;
      }
    }
  }
  if (Socket == nullptr) {
    //printf("2\n");
    for (auto& [key, info] : sock_table) {
      if ((info.ip == destip || info.ip == 0) && info.port == header.th_dport && info.listen_state == true) {
        pid = key.first;
        sockfd = key.second;
        Socket = &info;
        break;
      }
    }
  }
  if (Socket == nullptr) {
    //printf("3\n");
    for (auto& [key, info] : sock_table) {
      if ((info.ip == destip || info.ip == 0) && info.port == header.th_dport) {
        Socket = &info;
        pid = key.first;
        sockfd = key.second;
        if(syn && !ack && !Socket->connected){
          auto it = SYNACK_queue.find({srcip, header.th_sport});
          if (it == SYNACK_queue.end()) {
            return;
          }
          Socket->SimultaneousConnect = true;
          UUID syscallUUID = it->second.first;
          Socket->peerip = srcip;
          Socket->peerport = header.th_sport;
          this->returnSystemCall(syscallUUID, 0);
        }
        break;
      }
    }
  }
  if (Socket == nullptr){
    return;
  }

  //std::cout << "Socket Info : " << Socket->ip << " " << Socket->port << " "  << Socket->peerip << " "  << Socket->peerport << " "  << Socket->connected << std::endl;
  //std::cout << "Packet Info : " << destip << " "  << header.th_dport << " "  << srcip << " "  << header.th_sport << std::endl;

  if (Socket->connected){
    if(packet.getSize()>54){ //data packet

      //printf("%d ", header.th_dport);
      
      if(fin)
      printf("fin\n\n");

      
      if(Socket->read_requests.empty()){
        //std::cout << "packet first" << std::endl;
        Socket->read_queue.emplace_back(packet.clone());
        return;
      }

      if(htonl(header.th_seq)!=Socket->peer_seq_num){
        if(htonl(header.th_seq)==Socket->peer_seq_num-(packet.getSize()-54))
        //  Socket->peer_seq_num -= (packet.getSize()-54);
          printf("%u\n", htonl(header.th_seq));
        return;
      }

      //printf("packet last\n");
      
      auto [syscallUUID, buf, count] = Socket->read_requests.front();

      Socket->read_requests.pop_front();

      //count < 512이면 read_requests에 개수만큼 있는지 확인하고 없으면 read에 보내기. 있으면 하나하나 꺼내서 쓰기.


      if(count < packet.getSize()-54){
        packet.readData(54, buf, count);
        Socket->readacknum = ntohl(header.th_seq)+count;
        Socket->recv_len = packet.getSize()-54-count;
        packet.readData(54+count, Socket->recv_buffer, Socket->recv_len);
        send_ACK(*Socket);
        this->returnSystemCall(syscallUUID, count);
        return;
      }

      packet.readData(54, buf, ((packet.getSize()-54<512) ? packet.getSize()-54 : 512));

      //printf("buf : %x, count : %d\n", buf, count);

      //printf("%u\n", ntohl(header.th_seq));

      Socket->readacknum = ntohl(header.th_seq)+((packet.getSize()-54<512) ? packet.getSize()-54 : 512);

      uint32_t srcip, destip;

      packet.readData(26, &srcip, 4);
      packet.readData(30, &destip, 4);

      Socket->ip = destip;  //0을 강제로 배정하긴 하는데 문제가 없으려나?
      Socket->peerip = srcip;

      send_ACK(*Socket);

      Socket->peer_seq_num+=packet.getSize()-54;
    
      this->returnSystemCall(syscallUUID, (packet.getSize()-54<512) ? packet.getSize()-54 : 512);

      return;
    }
    else if(ack){

      //printf("ack got\n");

      //std::cout << Socket->send_base << " " << htonl(header.th_ack) << std::endl;
      for (auto it = Socket->timerkeys.begin(); it != Socket->timerkeys.end(); ) {
        if ((it->first < htonl(header.th_ack) && htonl(header.th_ack) - it->first < 1<<30) || (htonl(header.th_ack) < 1024 && it->first > 0xFFFFFFFF-1024)) {
            //printf("%u %u \n", it->first, htonl(header.th_ack));
            cancelTimer(it->second);
            it = Socket->timerkeys.erase(it); 
        } else {
            ++it;
        }
      }

      if((Socket->send_base < htonl(header.th_ack) && htonl(header.th_ack) - Socket->send_base < 1<<30) || (Socket->send_base > 0xFFFFFFFF-1024 && htonl(header.th_ack)<= 1024))
        Socket->send_base = htonl(header.th_ack);
      else{

        return;
      }

      Socket->rwnd = header.th_win;

      if (sock_table[{pid, sockfd}].write_requests.empty()){
        //printf("oh no\n");
        return; //send_base는 이미 이동했으니 할 건 다 한거지.
      }

      //printf("asdfasdf\n\n");
    
      size_t write_size = Socket->write_requests.front();
      Socket->write_requests.pop_front();

      ipv4_t dest_ip;
  
      tcphdr header;
      header.th_dport = Socket->peerport;
      header.th_sport = Socket->port;
  
      Packet packet(write_size+54);
      packet.writeData(30, &Socket->peerip, 4);
      packet.readData(30, &dest_ip, 4);
      int port = getRoutingTable(dest_ip);
      std::optional<ipv4_t> src_IP = getIPAddr(port);
      ipv4_t src_ip = src_IP.value();
      packet.writeData(26, &src_ip, 4);
  
      //printf("%d.%d.%d.%d %d.%d.%d.%d %d %d\n", src_ip[0], src_ip[1], src_ip[2], src_ip[3], dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3], header.th_sport, header.th_dport);
  
      header.th_seq = htonl(Socket->nextseqnum);
      //printf("write seq# : %u\n", htonl(header.th_seq));
      header.th_win = htons(Socket->rwnd);
      header.th_off = 5;
      header.th_flags = TH_ACK;
      header.th_x2 = 0;
      
      header.th_ack = htonl(Socket->peer_seq_num+1);
  
      packet.writeData(54, Socket->send_buffer, write_size);
  
      header.th_sum = 0;
      packet.writeData(34, &header, sizeof(tcphdr));
      packet.readData(34, tcp_segment, sizeof(tcphdr) + write_size);
      uint32_t srcip, destip;
  
      packet.readData(26, &srcip, 4);
      packet.readData(30, &destip, 4);
      header.th_sum = (~ntohs(NetworkUtil::tcp_sum(srcip, destip, tcp_segment, sizeof(tcphdr) + write_size)))&0xFFFF;
      packet.writeData(34, &header, sizeof(tcphdr));
  
      sendPacket("IPv4", std::move(packet));

      Time time = TCPAssignment::getCurrentTime();

      std::tuple<int, int, bool, uint32_t, uint32_t, uint16_t, uint16_t, Packet> payload = std::make_tuple(pid, sockfd, false, srcip, destip, header.th_sport, header.th_dport, packet.clone());
    
      Socket->timerkeys[Socket->nextseqnum] = addTimer(payload, time+TimeUtil::makeTime(100, TimeUtil::MSEC));
  
      Socket->nextseqnum += write_size;

      Socket->sb_pointer -= write_size;

      memmove(Socket->send_buffer, Socket->send_buffer + write_size, Socket->sb_pointer);

      if(Socket->sb_pointer <= 0 && Socket->close_signal){
        sock_table.erase({pid, sockfd});
      }
      return;
    }
  }

  if (syn && !ack){

    if(Socket->left_connect_place <= 0){
      return;
    }
  
    //Socket->syn_queue.emplace_back(srcip, destip, header.th_sport, header.th_dport);
    Socket->left_connect_place--;

    Packet reply = packet.clone();

    ipv4_t dest_ip;
    packet.readData(26, &dest_ip, 4);
    int port = getRoutingTable(dest_ip);
    std::optional<ipv4_t> src_IP = getIPAddr(port);
    ipv4_t src_ip = src_IP.value();
    if(Socket->ip == 0){
      reply.writeData(26, &src_ip, 4); 
    }
    else{reply.writeData(26, &Socket->ip, 4);}
    
    reply.writeData(30, &dest_ip, 4);
    ipv4_t src_ip2;
    packet.readData(30, &src_ip2, 4);

    std::swap(header.th_sport, header.th_dport);
    header.th_ack = htonl(ntohl(header.th_seq) +1);
    header.th_flags = TH_SYN|TH_ACK; //synack

    header.th_sum = 0;
    reply.writeData(34, &header, sizeof(tcphdr));
    reply.readData(34, tcp_segment, sizeof(tcphdr));

    header.th_sum = (~ntohs(NetworkUtil::tcp_sum(destip, srcip, tcp_segment, sizeof(tcphdr))))&0xFFFF;

    reply.writeData(34, &header, sizeof(tcphdr));
    reply.readData(34, tcp_segment, sizeof(tcphdr));

    sendPacket(fromModule, std::move(reply));

    Time time = TCPAssignment::getCurrentTime();

    std::tuple<int, int, bool, uint32_t, uint32_t, uint16_t, uint16_t, Packet> payload = std::make_tuple(pid, sockfd, false, srcip, destip, header.th_sport, header.th_dport, reply.clone());
  
    UUID timerkey;
    if(!Socket->SimultaneousConnect)
      timerkey = addTimer(payload, time+TimeUtil::makeTime(100, TimeUtil::MSEC));
    else
      timerkey = 0;
  
    Socket->syn_queue.emplace_back(srcip, destip, header.th_dport, header.th_sport, timerkey); //위에 있을 때와 달리 port 순서 바꿔야함. 이미 바뀌었으니.

    Socket->peer_seq_num = ntohl(header.th_seq)+1;

    return;
  }

  if (ack && !syn){
    for (auto it = Socket->syn_queue.begin(); it != Socket->syn_queue.end(); ++it) {
      if (std::get<0>(*it) == srcip &&
      std::get<1>(*it) == destip &&
      std::get<2>(*it) == header.th_sport &&
      std::get<3>(*it) == header.th_dport) {

        if(!Socket->SimultaneousConnect)
          cancelTimer(std::get<4>(*it));

        Socket->syn_queue.erase(it);
        Socket->left_connect_place++;

        if (Socket->accept_requests.empty()){
          Socket->accept_queue.emplace_back(srcip, destip, header.th_sport, header.th_dport);
          return;
        }
        auto [syscallUUID, addr, addrlen] = Socket->accept_requests[{pid, sockfd}];
        Socket->accept_requests.erase({pid, sockfd});
      
        struct sockaddr_in *client_addr = reinterpret_cast<struct sockaddr_in *>(addr);
        client_addr->sin_family = AF_INET;
        client_addr->sin_addr.s_addr = destip;
        client_addr->sin_port = header.th_dport;
      
        // 새로운 소켓 파일 디스크립터 할당
        int new_sockfd = this->createFileDescriptor(pid);  // 새로운 소켓을 할당하는 함수
        if (new_sockfd < 0) {
            this->returnSystemCall(syscallUUID, -ENOMEM); // 새 소켓 할당 실패
            return;
        }
      
        sock_table[{pid, new_sockfd}] = {destip, header.th_dport, false, 0, {}};
        sock_table[{pid, new_sockfd}].peerip = srcip;
        sock_table[{pid, new_sockfd}].peerport = header.th_sport;
        sock_table[{pid, new_sockfd}].connected = true;
        sock_table[{pid, new_sockfd}].rwnd = htons(header.th_win);
        sock_table[{pid, new_sockfd}].nextseqnum = htonl(header.th_ack);
        sock_table[{pid, new_sockfd}].send_base = htonl(header.th_ack);
        sock_table[{pid, new_sockfd}].peer_seq_num = Socket->peer_seq_num;
      
        this->returnSystemCall(syscallUUID, new_sockfd);
        return;
      }
    }
    return;
  }

  if (syn && ack) {

    Socket->peer_seq_num = ntohl(header.th_seq)+1;

    printf("%u\n\n", Socket->peer_seq_num);

    //printf("%d %d\n", header.th_x2, header.th_off);
    
    auto it = SYNACK_queue.find({srcip, header.th_sport});
    if (it == SYNACK_queue.end()) {
      return;
    }
    UUID syscallUUID = it->second.first;
    cancelTimer(it->second.second);

    //printf("%d\n", header.th_win);

    uint32_t srcip, destip;

    packet.readData(26, &srcip, 4);
    packet.readData(30, &destip, 4);

    Packet reply = packet.clone();

    ipv4_t dest_ip;
    packet.readData(26, &dest_ip, 4);
    int port = getRoutingTable(dest_ip);
    std::optional<ipv4_t> src_IP = getIPAddr(port);
    ipv4_t src_ip = src_IP.value();
    reply.writeData(26, &src_ip, 4);
    reply.writeData(30, &dest_ip, 4);

    //header.th_win = 200;

    std::swap(header.th_sport, header.th_dport);

    //printf("%d.%d.%d.%d %d.%d.%d.%d %d %d is real\n", src_ip[0], src_ip[1], src_ip[2], src_ip[3], dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3], header.th_sport, header.th_dport);

    header.th_ack = htonl(ntohl(header.th_seq) +1);
    header.th_seq = htonl(Socket->nextseqnum);
    header.th_flags = 0x10; //ack
    header.th_win = 200;

    header.th_sum = 0;
    reply.writeData(34, &header, sizeof(tcphdr));
    reply.readData(34, tcp_segment, sizeof(tcphdr));

    header.th_sum = (~ntohs(NetworkUtil::tcp_sum(destip, srcip, tcp_segment, sizeof(tcphdr))))&0xFFFF;

    reply.writeData(34, &header, sizeof(tcphdr));

    sendPacket(fromModule, std::move(reply));

    Socket->connected = true;

    Socket->rwnd = htons(header.th_win);

    this->returnSystemCall(syscallUUID, 0);

    return;
  }

}

void TCPAssignment::timerCallback(std::any payload) {
  
  auto [pid, sockfd, connect, srcip, srcport, destip, destport, packet] = std::any_cast<std::tuple<int, int, bool, uint32_t, uint32_t, uint16_t, uint16_t, Packet>>(payload);

    
  tcphdr header;
  packet.readData(34, &header, sizeof(tcphdr));

  sendPacket("IPv4", std::move(packet));
  
  Time time = TCPAssignment::getCurrentTime();

  UUID timerkey = addTimer(std::make_tuple(pid, sockfd, connect, srcip, srcport, destip, destport, packet), time +TimeUtil::makeTime(100, TimeUtil::MSEC));

  if(connect){
    SYNACK_queue[{destip, destport}].second = timerkey;
  }
  else{
    auto it = sock_table.find({pid, sockfd});
    if (it == sock_table.end()) return; // 이미 close되어 사라졌으면 리턴
    
    SocketInfo &Socket = it->second;
    for (auto it = Socket.syn_queue.begin(); it != Socket.syn_queue.end(); ++it) {
      if (std::get<0>(*it) == srcip &&
      std::get<1>(*it) == destip &&
      std::get<2>(*it) == srcport &&
      std::get<3>(*it) == destport) {
        std::get<4>(*it) = timerkey;
      }
    }
  }
}

} // namespace E
