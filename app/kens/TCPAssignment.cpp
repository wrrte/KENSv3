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
  bind_table.clear();
  connection_table.clear(); 
}

void TCPAssignment::finalize() {}

bool isNonBlocking(int sockfd){ return false; }

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  printf("syscallnum : %d\n", param.syscallNumber);
                                 
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
    assert(false);
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

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog) {
  // 소켓이 바인딩되었는지 확인
  auto it = bind_table.find({pid, sockfd});
  if (it == bind_table.end()) {
      this->returnSystemCall(syscallUUID, EINVAL); // 바인딩되지 않은 소켓
      return;
  }

  // 이미 listen 상태인지 확인
  if (listen_table.find({pid, sockfd}) != listen_table.end()) {
      this->returnSystemCall(syscallUUID, 0); // 이미 listen 상태라면 성공
      return;
  }

  if (backlog < 0) {
    backlog = 0;
  }

  // 소켓을 listen 상태로 변경
  listen_table[{pid, sockfd}] = backlog;
  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen) {  

  // 소켓이 listen 상태인지 확인
  auto listen_it = listen_table.find({pid, sockfd});
  if (listen_it == listen_table.end()) {
      // listen 상태가 아닌 소켓은 오류
      this->returnSystemCall(syscallUUID, EINVAL);
      return;
  }
  
  // 대기 큐에서 연결 요청을 가져옴
  auto queue_it = accept_queue.find({pid, sockfd});
  if (queue_it == accept_queue.end() || queue_it->second.empty()) {
      // 대기 큐가 비어있고 O_NONBLOCK이 설정되지 않았다면 차단
      if (isNonBlocking(sockfd)) {
          this->returnSystemCall(syscallUUID, EAGAIN); // 비동기 모드에서 큐가 비어있다면 오류 반환
      } else {
          wait();
      }
      return;
  }

  // 대기 큐에서 첫 번째 연결 요청을 수락
  struct sockaddr_in client_addr;
  socklen_t client_addr_len = sizeof(client_addr);
  struct sockaddr_in *client_addr_ptr = &client_addr;

  if (addr && addrlen && *addrlen >= sizeof(struct sockaddr_in)) {
      // 클라이언트 주소를 복사
      memcpy(addr, client_addr_ptr, sizeof(struct sockaddr_in));
      *addrlen = sizeof(struct sockaddr_in);
  }

  // 새로운 소켓 파일 디스크립터 할당
  int new_sockfd = this->createFileDescriptor(pid);  // 새로운 소켓을 할당하는 함수
  if (new_sockfd < 0) {
      this->returnSystemCall(syscallUUID, -ENOMEM); // 새 소켓 할당 실패
      return;
  }

  // 새 소켓을 listen 상태로 설정
  listen_table[{pid, new_sockfd}] = 0;

  // 대기 큐에서 연결 요청 제거
  queue_it->second.pop();

  // 연결 성공 시 새 소켓 반환
  this->returnSystemCall(syscallUUID, new_sockfd);
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

  auto IPnPort = bind_table.find({pid, sockfd});
  if (IPnPort != bind_table.end()) {
      uint32_t existing_ip = IPnPort->second.first;
      uint16_t existing_port = IPnPort->second.second;

      if (existing_ip == ip_addr && existing_port == port) {
          this->returnSystemCall(syscallUUID, 0); // 이미 동일한 주소로 바인딩 → 성공
          return;
      } else {
          this->returnSystemCall(syscallUUID, -EINVAL); // 다른 주소로 바인딩 시도 → 오류
          return;
      }
  }

  // 바인딩된 주소/포트 중복 확인
  for (const auto &[key, value] : bind_table) {
      uint32_t bound_ip = value.first;
      uint16_t bound_port = value.second;

      // 포트가 동일하고, IP가 동일하거나 INADDR_ANY(0.0.0.0)로 설정된 경우 충돌
      if (bound_port == port && (bound_ip == ip_addr || bound_ip == INADDR_ANY || ip_addr == INADDR_ANY)) {
          this->returnSystemCall(syscallUUID, EADDRINUSE);
          return;
      }
  }

  // 바인딩 정보 저장
  bind_table[{pid, sockfd}] = {ip_addr, port};
  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen) {
  // 유효한 주소인지 확인
  /*
  if (!addr || addrlen < sizeof(struct sockaddr)) {
      printf("asdf\n");
      this->returnSystemCall(syscallUUID, -EINVAL);
      return;
  }
      */
  assert(false);
  this->returnSystemCall(syscallUUID, 0);
  return;

  struct sockaddr_in *sock_addr = reinterpret_cast<struct sockaddr_in *>(addr);
  uint32_t peer_ip = sock_addr->sin_addr.s_addr;
  uint16_t peer_port = sock_addr->sin_port;

  if (bind_table.find({pid, sockfd}) == bind_table.end()) {
      struct sockaddr_in auto_bind_addr;
      auto_bind_addr.sin_family = AF_INET;
      auto_bind_addr.sin_addr.s_addr = INADDR_ANY;  // 시스템에서 자동 할당
      auto_bind_addr.sin_port = htons(rand() % (65535 - 1024) + 1024);  // 1024~65535 중 랜덤 포트

      bind_table[{pid, sockfd}] = {auto_bind_addr.sin_addr.s_addr, auto_bind_addr.sin_port};
  }

  printf("\ntest1\n\n");

  if (connection_table.find({pid, sockfd}) == connection_table.end()) {
      // 연결 테이블에 추가
      connection_table[{pid, sockfd}] = {peer_ip, peer_port};
      this->returnSystemCall(syscallUUID, 0);
      return;
  }

  Packet SYN(100);
  uint16_t data = 0b0100; //syn

  //SYN packet에 정보 추가

  SYN.writeData(46, &data, 2);
  sendPacket("IPv4", SYN);
  TCP_state = SYN_SENT_state;

  // 블로킹 소켓이면 즉시 연결 완료 처리 (실제 구현에서는 3-way handshake 필요)
  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  // fd가 바인딩되어 있는지 확인
  auto it = bind_table.find({pid, sockfd});
  if (it == bind_table.end()) {
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
  sock_addr->sin_addr.s_addr = it->second.first;  // 저장된 IP 주소
  sock_addr->sin_port = it->second.second;        // 저장된 포트 번호

  // addrlen을 업데이트 (호출한 프로세스가 변경된 크기를 알도록)
  *addrlen = sizeof(struct sockaddr_in);

  this->returnSystemCall(syscallUUID, 0); // 성공
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd) {
  bind_table.erase({pid, fd});
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
