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
  header.th_seq = htonl(0);
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

  //std::cout << sock.recv_len << std::endl;

  memcpy(buf, sock.recv_buffer, count);

  memmove(sock.recv_buffer, sock.recv_buffer + count, sock.recv_len - count);

  sock.recv_len -= count;

  sock.readacknum+=count;

  send_ACK(sock);

  this->returnSystemCall(syscallUUID, count);
}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int sockfd, void *buf, size_t count){

  SocketInfo& sock = sock_table[{pid, sockfd}];

  uint8_t tcp_segment[sizeof(tcphdr)];
  ipv4_t dest_ip;

  uint16_t m = (512<count)?512:count;
  uint16_t write_size = (m<(sock.rwnd-sock.nextseqnum+sock.send_base))?m:(sock.rwnd-sock.nextseqnum+sock.send_base);

  if(sock.nextseqnum-sock.send_base < sock.rwnd){

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
    sock.nextseqnum += write_size;
    //printf("write seq# : %u\n", htonl(header.th_seq));
    header.th_win = 200;
    header.th_off = 5;
    header.th_flags = TH_ACK;
    header.th_ack = htonl(sock.peer_seq_num+1);
    header.th_sum = 0;
    packet.writeData(34, &header, sizeof(tcphdr));
    packet.readData(34, tcp_segment, sizeof(tcphdr));
    header.th_sum = (~ntohs(NetworkUtil::tcp_sum(sock.ip, sock.peerip, tcp_segment, sizeof(tcphdr))))&0xFFFF;
    packet.writeData(34, &header, sizeof(tcphdr));
    packet.writeData(54, buf, write_size);
    sendPacket("IPv4", std::move(packet));

    this->returnSystemCall(syscallUUID, write_size);
  }
  else{
    sock_table[{pid, sockfd}].write_requests.emplace_back(syscallUUID, buf, count);  
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
  SocketInfo& Socket = sock_table[{pid, sockfd}];

  Socket.rwnd = 200;

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
    header.th_sport = htons(12345);
    sock_table[{pid, sockfd}] = {srcip, header.th_sport};
  }
  else{
    header.th_sport = sock_table[{pid, sockfd}].port;
  }

  uint8_t tcp_segment[sizeof(tcphdr)];

  header.th_seq = htonl(Socket.nextseqnum++);
  header.th_ack = 0;
  header.th_flags = TH_SYN; //syn
  header.th_win = 200;
  header.th_off = 5;

  header.th_sum = 0;
  packet.writeData(34, &header, sizeof(tcphdr));
  packet.readData(34, tcp_segment, sizeof(tcphdr));

  header.th_sum = (~ntohs(NetworkUtil::tcp_sum(destip, srcip, tcp_segment, sizeof(tcphdr))))&0xFFFF;

  packet.writeData(34, &header, sizeof(tcphdr));
  packet.readData(34, tcp_segment, sizeof(tcphdr));

  sock_table[{pid, sockfd}].peerip = destip;
  sock_table[{pid, sockfd}].peerport = header.th_dport;

  sendPacket("IPv4", std::move(packet));
  //printf("sent syn\n");


  Time time = TCPAssignment::getCurrentTime();

  SYNACK_queue[{destip, header.th_dport}] = syscallUUID;

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
  sock_table.erase({pid, fd});
  this->removeFileDescriptor(pid, fd);
  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  
  tcphdr header;
  packet.readData(34, &header, sizeof(tcphdr)); 

  uint32_t srcip, destip;

  packet.readData(26, &srcip, 4);
  packet.readData(30, &destip, 4);

  bool syn = header.th_flags & TH_SYN;  // 0000 0010 → SYN
  bool ack = header.th_flags & TH_ACK;
  bool fin = header.th_flags & TH_FIN;

  SocketInfo* Socket = nullptr;
  int pid, sockfd;


  if(header.th_flags != TH_SYN){
    for (auto& [key, info] : sock_table) {
      if ((info.ip == destip || info.ip == 0) && info.port == header.th_dport && info.peerip == srcip && info.peerport == header.th_sport && info.connected == true) {
        pid = key.first;
        sockfd = key.second;
        Socket = &info;
        break;
      }
    }
  }
  if (Socket == nullptr) {

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
          UUID syscallUUID = it->second;
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

  if (Socket->connected){
    if(packet.getSize()>100){ //data packet
      
      if(fin)
      printf("fin\n\n");
      
      if(Socket->read_requests.empty()){
        //std::cout << "packet first" << std::endl;
        Socket->read_queue.emplace_back(packet.clone());
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

      uint32_t srcip, destip;

      packet.readData(26, &srcip, 4);
      packet.readData(30, &destip, 4);

      Packet reply(54);
      
      uint8_t tcp_segment[sizeof(tcphdr)];

      ipv4_t dest_ip;
      packet.readData(26, &dest_ip, 4);
      int port = getRoutingTable(dest_ip);
      std::optional<ipv4_t> src_IP = getIPAddr(port);
      ipv4_t src_ip = src_IP.value();
      reply.writeData(26, &src_ip, 4);
      reply.writeData(30, &dest_ip, 4);

      std::swap(header.th_sport, header.th_dport);
      header.th_ack = htonl(ntohl(header.th_seq)+((packet.getSize()-54<512) ? packet.getSize()-54 : 512));
      header.th_seq = htonl(0);
      header.th_flags = TH_ACK;
      header.th_win = 200;
      header.th_off = 5;

      header.th_sum = 0;
      reply.writeData(34, &header, sizeof(tcphdr));
      reply.readData(34, tcp_segment, sizeof(tcphdr));

      header.th_sum = (~ntohs(NetworkUtil::tcp_sum(destip, srcip, tcp_segment, sizeof(tcphdr))))&0xFFFF;

      reply.writeData(34, &header, sizeof(tcphdr));

      sendPacket(fromModule, std::move(reply));

      Socket->peer_seq_num++;
    
      this->returnSystemCall(syscallUUID, (packet.getSize()-54<512) ? packet.getSize()-54 : 512);

      return;
    }
    else if(ack){
      if (sock_table[{pid, sockfd}].write_requests.empty()){
        return;
      }
    
      auto [syscallUUID, buf, count] = sock_table[{pid, sockfd}].write_requests.front();
      sock_table[{pid, sockfd}].write_requests.pop_front();

      this->returnSystemCall(syscallUUID, count);
    }
  }

  if (syn && !ack){

    if(Socket->left_connect_place <= 0){
      return;
    }
    Socket->syn_queue.emplace_back(srcip, destip, header.th_sport, header.th_dport);
    Socket->left_connect_place--;

    Packet reply = packet.clone();
    
    uint8_t tcp_segment[sizeof(tcphdr)];

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
    header.th_flags = 0x12; //synack

    header.th_sum = 0;
    reply.writeData(34, &header, sizeof(tcphdr));
    reply.readData(34, tcp_segment, sizeof(tcphdr));

    header.th_sum = (~ntohs(NetworkUtil::tcp_sum(destip, srcip, tcp_segment, sizeof(tcphdr))))&0xFFFF;

    reply.writeData(34, &header, sizeof(tcphdr));
    reply.readData(34, tcp_segment, sizeof(tcphdr));

    sendPacket(fromModule, std::move(reply));

    return;
  }

  if (ack && !syn){
    
    for (auto it = Socket->syn_queue.begin(); it != Socket->syn_queue.end(); ++it) {
      if (*it == std::make_tuple(srcip, destip, header.th_sport, header.th_dport)) {
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
      
        this->returnSystemCall(syscallUUID, new_sockfd);
        return;
      }
    }
    return;
  }

  if (syn && ack) {

    Socket->peer_seq_num = ntohl(header.th_seq);

    //printf("%d %d\n", header.th_x2, header.th_off);
    
    auto it = SYNACK_queue.find({srcip, header.th_sport});
    if (it == SYNACK_queue.end()) {
      return;
    }
    UUID syscallUUID = it->second;

    //printf("%d\n", header.th_win);

    uint32_t srcip, destip;

    packet.readData(26, &srcip, 4);
    packet.readData(30, &destip, 4);

    Packet reply = packet.clone();
    
    uint8_t tcp_segment[sizeof(tcphdr)];

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
  // Remove below
  (void)payload;
}

} // namespace E
