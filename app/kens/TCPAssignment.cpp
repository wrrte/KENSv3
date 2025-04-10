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
  seq = 0;
  socket_table.clear();
  accept_queue.clear();
  accept_requests.clear();
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

  auto socket_it = socket_table.find({pid, sockfd});
  if (socket_it != socket_table.end()) {
      const SocketInfo& info = socket_it->second;
  
      if (info.ip == ip_addr && info.port == port) {
          this->returnSystemCall(syscallUUID, 0); // 이미 동일한 주소로 바인딩됨
          return;
      } else {
          this->returnSystemCall(syscallUUID, -EINVAL); // 다른 주소로 재바인딩 시도
          return;
      }
  }

  for (const auto &[key, socket_info] : socket_table) {
    uint32_t bound_ip = socket_info.ip;
    uint16_t bound_port = socket_info.port;

    if (bound_port == port) {
      if (bound_ip == INADDR_ANY || ip_addr == INADDR_ANY || bound_ip == ip_addr) {
        this->returnSystemCall(syscallUUID, EADDRINUSE);
        return;
      }
    }
  }

  // 바인딩 정보 저장
  SocketInfo info;
  info.ip = ip_addr;
  info.port = port;
  info.backlog = -1;

  socket_table[{pid, sockfd}] = info;

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog) {
  // 소켓이 바인딩되었는지 확인
  auto it = socket_table.find({pid, sockfd});
  if (it == socket_table.end()) {
      this->returnSystemCall(syscallUUID, EINVAL); // 바인딩되지 않은 소켓
      return;
  }

  // 이미 listen 상태인지 확인
  if (socket_table[{pid, sockfd}].backlog != -1) {
      this->returnSystemCall(syscallUUID, 0); // 이미 listen 상태라면 성공
      return;
  }

  if (backlog < 0) {
    backlog = 0;
  }

  socket_table[{pid, sockfd}].backlog = backlog;

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen) {  
  
  //usleep 한 다음에 취소하는 식으로 시간 제한 둬야 할지도
  if (accept_queue.empty()){
    accept_requests.emplace_back(syscallUUID, pid, sockfd, addr, addrlen);
    
    return;
  }

  auto [srcip, destip, srcport, destport] = accept_queue.front();
  accept_queue.pop_front();

  struct sockaddr_in *client_addr = reinterpret_cast<struct sockaddr_in *>(addr);
  client_addr->sin_family = AF_INET;
  client_addr->sin_addr.s_addr = destip;
  client_addr->sin_port = destport;

  // 새로운 소켓 파일 디스크립터 할당
  int new_sockfd = this->createFileDescriptor(pid);  // 새로운 소켓을 할당하는 함수
  if (new_sockfd < 0) {
      this->returnSystemCall(syscallUUID, -ENOMEM); // 새 소켓 할당 실패
      return;
  }

  SocketInfo info;
  info.ip = destip;
  info.port = destport;
  info.backlog = -1;

  socket_table[{pid, sockfd}] = info;

  this->returnSystemCall(syscallUUID, new_sockfd);

}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen) {
  /*
  
  소켓이 아직 로컬 주소에 바인딩되지 않은 경우, 
  connect()는 소켓의 주소 패밀리가 AF_UNIX가 아니라면 사용하지 않는 로컬 주소인 주소에 소켓을 바인딩합니다.

  시작 소켓이 연결 모드가 아닌 경우 connect()는 소켓의 피어 주소를 설정하고 연결이 이루어지지 않습니다. 
  SOCK_DGRAM 소켓의 경우, 
  피어 주소는 후속 send() 함수에서 모든 데이터그램이 전송되는 위치를 식별하고 
  후속 recv() 함수에 대한 원격 발신자를 제한합니다. 
  주소가 프로토콜에 대한 널 주소인 경우, 소켓의 피어 주소는 재설정됩니다.
  */
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  // fd가 바인딩되어 있는지 확인
  auto it = socket_table.find({pid, sockfd});
  if (it == socket_table.end()) {
      this->returnSystemCall(syscallUUID, -EBADF); // 해당 소켓이 존재하지 않음
      return;
  }

  // addrlen이 NULL이면 에러
  if (!addrlen || !addr || *addrlen < sizeof(struct sockaddr_in)) {
      this->returnSystemCall(syscallUUID, -EINVAL);
      return;
  }

  const SocketInfo& info = it->second;

  struct sockaddr_in *sock_addr = reinterpret_cast<struct sockaddr_in *>(addr);
  sock_addr->sin_family = AF_INET;
  sock_addr->sin_addr.s_addr = info.ip;  // 저장된 IP 주소
  sock_addr->sin_port = info.port;      // 저장된 포트 번호

  // addrlen을 업데이트 (호출한 프로세스가 변경된 크기를 알도록)
  *addrlen = sizeof(struct sockaddr_in);

  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd) {
  socket_table.erase({pid, fd});
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
  for (auto& [key, info] : socket_table) {
    if (info.port == header.th_dport) {
      // IP가 정확히 일치하거나, info.ip가 INADDR_ANY인 경우 일치
      if (info.ip == destip || info.ip == INADDR_ANY) {
        SocketInfo& Socket = info;
        break;
      }
    }
  }
  if(Socket == nullptr){
    return;
  }


  if (syn){

    if(Socket->syn_queue.size() >= Socket->backlog){
      return;
    }
    
    tcphdr header;
    packet.readData(34, &header, sizeof(tcphdr));
    /*
    printf("\n\n\n==== TCP Header before ====\n");
    printf("Source Port       : %u\n", ntohs(header.th_sport));
    printf("Destination Port  : %u\n", ntohs(header.th_dport));
    printf("Sequence Number   : %u\n", ntohl(header.th_seq));
    printf("Ack Number        : %u\n", ntohl(header.th_ack));
    printf("Data Offset       : %u (words of 4 bytes)\n", header.th_off);
    printf("Flags             : 0x%02x\n", header.th_flags);
    printf("    URG: %d\n", (header.th_flags & 0x20) != 0);
    printf("    ACK: %d\n", (header.th_flags & 0x10) != 0);
    printf("    PSH: %d\n", (header.th_flags & 0x08) != 0);
    printf("    RST: %d\n", (header.th_flags & 0x04) != 0);
    printf("    SYN: %d\n", (header.th_flags & 0x02) != 0);
    printf("    FIN: %d\n", (header.th_flags & 0x01) != 0);
    printf("Window Size       : %u\n", ntohs(header.th_win));
    printf("Checksum          : 0x%04x\n", ntohs(header.th_sum));
    printf("Urgent Pointer    : %u\n\n", ntohs(header.th_urp));   
    */
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
    header.th_flags |= 0x12; //synack

    header.th_sum = 0;
    reply.writeData(34, &header, sizeof(tcphdr));
    reply.readData(34, tcp_segment, sizeof(tcphdr));

    header.th_sum = (~ntohs(NetworkUtil::tcp_sum(destip, srcip, tcp_segment, sizeof(tcphdr))))&0xFFFF;

    reply.writeData(34, &header, sizeof(tcphdr));
    reply.readData(34, tcp_segment, sizeof(tcphdr));
    //보낼 패킷의 checksum 출력
    //printf("after : 0x%x\n\n", ntohs(NetworkUtil::tcp_sum(destip, srcip, tcp_segment, sizeof(tcphdr))));

    sendPacket(fromModule, std::move(reply));

    return;
  }

  if (ack){
    for (auto it = Socket->syn_queue.begin(); it != Socket->syn_queue.end(); ++it) {
      if (*it == std::make_tuple(srcip, destip, header.th_sport, header.th_dport)) {
        Socket->syn_queue.erase(it);
        left_connect_place++;
        if (accept_requests.empty()){
          accept_queue.emplace_back(srcip, destip, header.th_sport, header.th_dport);
          return;
        }
        auto [syscallUUID, pid, sockfd, addr, addrlen] = accept_requests.front();
        accept_requests.pop_front();
      
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
      
        socket_table[{pid, new_sockfd}] = {destip, header.th_dport, 0};
      
        this->returnSystemCall(syscallUUID, new_sockfd);
        return;
      }
    }
  }
}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

} // namespace E
