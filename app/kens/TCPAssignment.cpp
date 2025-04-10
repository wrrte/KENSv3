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
}

void TCPAssignment::finalize() {}

bool isNonBlocking(int sockfd){ return false; }

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  //printf("param0 : %d, syscallnum : %d\n", std::get<int>(param.params[0]), param.syscallNumber);
                                 
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

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol) {
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
  client_addr->sin_port = destport;

  // 새로운 소켓 파일 디스크립터 할당
  int new_sockfd = this->createFileDescriptor(pid);  // 새로운 소켓을 할당하는 함수
  if (new_sockfd <= 0) {
      this->returnSystemCall(syscallUUID, -ENOMEM); // 새 소켓 할당 실패
      return;
  }

  sock_table[{pid, new_sockfd}] = {destip, destport, false, 0, {}};

  printf("accept : %u %u\n", destip, destport);

  this->returnSystemCall(syscallUUID, new_sockfd);

}

uint16_t TCPAssignment::allocateEphemeralPort() {
  printf("random port use \n\n\n\n");
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

  Packet packet (54);
  tcphdr header;

  struct sockaddr_in *server_addr = reinterpret_cast<struct sockaddr_in *>(addr);

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

  header.th_seq = htons(seq);
  header.th_ack = 0;
  header.th_flags = 0x02; //syn

  header.th_sum = 0;
  packet.writeData(34, &header, sizeof(tcphdr));
  packet.readData(34, tcp_segment, sizeof(tcphdr));

  header.th_sum = (~ntohs(NetworkUtil::tcp_sum(destip, srcip, tcp_segment, sizeof(tcphdr))))&0xFFFF;

  packet.writeData(34, &header, sizeof(tcphdr));
  packet.readData(34, tcp_segment, sizeof(tcphdr));

  sock_table[{pid, sockfd}] = {destip, header.th_dport};

  sendPacket("IPv4", std::move(packet));

  SYNACK_queue[{destip, header.th_dport}] = syscallUUID;

  this->returnSystemCall(syscallUUID, 0);

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
  sock_addr->sin_addr.s_addr = it->second.ip;  // 저장된 IP 주소
  sock_addr->sin_port = it->second.port;        // 저장된 포트 번호

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


  if (syn && !ack){


    SocketInfo* Socket = nullptr;

    for (auto& [key, info] : sock_table) {
      if (info.ip == destip && info.port == header.th_dport) {
        Socket = &info;
        break;
      }
    }
    if (Socket == nullptr) {
      for (auto& [key, info] : sock_table) {
        if (info.ip == 0 && info.port == header.th_dport) {
          Socket = &info;
          break;
        }
      }
    }
    if (Socket == nullptr){
     

      //printf("error\n\n\n");
      return;
    }

    if(Socket->left_connect_place <= 0){
      return;
    }

    if(destip == 134260928){
      printf("asdfasdfasdf\n");
    }
    
    Socket->syn_queue.emplace_back(srcip, destip, header.th_sport, header.th_dport);
    Socket->left_connect_place--;

    tcphdr header;
    packet.readData(34, &header, sizeof(tcphdr));

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
    reply.writeData(26, &Socket->ip, 4);
    reply.writeData(30, &dest_ip, 4);
    ipv4_t src_ip2;
    packet.readData(30, &src_ip2, 4);

    std::swap(header.th_sport, header.th_dport);
    header.th_ack = htonl(ntohl(header.th_seq) +1);
    header.th_flags |= 0x12; //synack

    header.th_sum = 0;
    reply.writeData(34, &header, sizeof(tcphdr));
    reply.readData(34, tcp_segment, sizeof(tcphdr));

    header.th_sum = (~ntohs(NetworkUtil::tcp_sum(destip, srcip, tcp_segment, sizeof(tcphdr))))&0xFFFF;

    reply.writeData(34, &header, sizeof(tcphdr));
    reply.readData(34, tcp_segment, sizeof(tcphdr));

    if(destip == 134260928){
      printf("asdfasdfasdf\n");
    }

    sendPacket(fromModule, std::move(reply));

    return;
  }

  if (ack && !syn){

    SocketInfo* Socket = nullptr;

    int pid, sockfd;

    for (auto& [key, info] : sock_table) {
      if ((info.ip == destip || info.ip == 0) && info.port == header.th_dport) {
        Socket = &info;
        pid = key.first;
        sockfd = key.second;
        break;
      }
    }
    if (Socket == nullptr){
      for (auto& [key, info] : sock_table) {
        if ((info.ip == destip || info.ip == 0) && info.port == header.th_dport) {
          Socket = &info;
          pid = key.first;
          sockfd = key.second;
          break;
        }
      }
    }
    if (Socket == nullptr){
      //printf("error\n\n\n");
      return;
    }

    if(destip == 134260928){
      printf("asdfasdfasdf\n");
    }
  
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
      
        sock_table[{pid, new_sockfd}] = {destip, header.th_dport};

        printf("ack : %d %d, %u %u\n", pid, new_sockfd, destip, header.th_dport);
      
        this->returnSystemCall(syscallUUID, new_sockfd);
        return;
      }
    }
  }

  if (syn && ack){
    
    auto it = SYNACK_queue.find({srcip, header.th_sport});
    if (it == SYNACK_queue.end()) {
      return;
    }
    
    UUID syscallUUID = it->second;

    tcphdr header;
    packet.readData(34, &header, sizeof(tcphdr));

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

    std::swap(header.th_sport, header.th_dport);
    header.th_ack = htonl(ntohl(header.th_seq) +1);
    header.th_flags = 0x10; //ack

    header.th_sum = 0;
    reply.writeData(34, &header, sizeof(tcphdr));
    reply.readData(34, tcp_segment, sizeof(tcphdr));

    header.th_sum = (~ntohs(NetworkUtil::tcp_sum(destip, srcip, tcp_segment, sizeof(tcphdr))))&0xFFFF;

    reply.writeData(34, &header, sizeof(tcphdr));
    reply.readData(34, tcp_segment, sizeof(tcphdr));

    sendPacket(fromModule, std::move(reply));

    this->returnSystemCall(syscallUUID, 0);
  }
}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

} // namespace E
