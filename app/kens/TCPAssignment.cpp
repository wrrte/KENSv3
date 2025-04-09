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
  connect_requests.clear();
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
  TCP_state = LISTEN_state;
  this->returnSystemCall(syscallUUID, 0);
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

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen) {  

  /*
  주소가 널 포인터가 아닌 경우, 수락된 연결에 대한 피어의 주소는 주소가 가리키는 sockaddr 구조체에 저장되며, 
  이 주소의 길이는 address_len이 가리키는 객체에 저장됩니다.

  주소의 실제 길이가 제공된 sockaddr 구조체의 길이보다 크면, 저장된 주소는 잘립니다.

  프로토콜이 바인딩되지 않은 클라이언트의 연결을 허용하고 피어가 바인딩되지 않은 경우, 
  주소가 가리키는 객체에 저장된 값은 지정되지 않은 값입니다.

  수신 대기열에 연결 요청이 없고 소켓의 파일 기술자에 O_NONBLOCK이 설정되지 않은 경우, 
  연결이 있을 때까지 accept()가 차단됩니다. 
  listen() 큐에 연결 요청이 없고 소켓의 파일 기술자에 O_NONBLOCK이 설정되어 있으면 
  accept()는 실패하고 errno를 [EAGAIN] 또는 [EWOULDDBLOCK]으로 설정합니다.

  수락된 소켓은 자체적으로 더 많은 연결을 수락할 수 없습니다. 
  원래 소켓은 열린 상태로 유지되며 더 많은 연결을 수락할 수 있습니다.
  */

  //connect 큐 확인해서 있으면 그거 받고 할거 다 실행하고 리턴. 없으면 accept큐에 넣어두기.

  if (connect_requests.empty()){

    auto listen_it = listen_table.find({pid, sockfd});
    if (listen_it == listen_table.end()) {
        // listen 상태가 아닌 소켓은 오류
        this->returnSystemCall(syscallUUID, EINVAL);
        return;
    }

    accept_requests.emplace_back(syscallUUID, pid, addr, addrlen);
    return;
  }

  auto [fromModule, packet] = connect_requests.front();
  connect_requests.pop_front();

  sendSYNACK(fromModule, std::move(packet));

  uint16_t srcport, destport;
  uint32_t srcip, destip;
  packet.readData(26, &srcip, 4);
  packet.readData(34, &srcport, 2);

  packet.readData(30, &destip, 4);
  packet.readData(34+2, &destport, 2);

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

  // 새 소켓을 listen 상태로 설정
  listen_table[{pid, new_sockfd}] = 0;
  bind_table[{pid, new_sockfd}] = {destip, destport};

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

void TCPAssignment::sendSYNACK(std::string fromModule, Packet &&packet) {

  uint8_t flagsByte;
  uint16_t srcport, destport, seqnum, acknum;
  uint32_t srcip, destip;

  packet.readData(26, &srcip, 4);
  packet.readData(30, &destip, 4);

  packet.readData(34, &srcport, 2);
  packet.readData(34+2, &destport, 2);

  packet.readData(34+4, &seqnum, 4);
  packet.readData(34+8, &acknum, 4);

  packet.readData(34+13, &flagsByte, 1);

  Packet reply = packet.clone();
        
  ipv4_t dest_ip;

  packet.readData(26, &dest_ip, 4);;
  int port = getRoutingTable(dest_ip);
  std::optional<ipv4_t> src_IP = getIPAddr(port);

  reply.writeData(26, &src_IP, 4);
  reply.writeData(30, &dest_ip, 4);

  reply.writeData(34, &destport, 2);
  reply.writeData(34+2, &srcport, 2);

  acknum = seqnum +1;
  reply.writeData(34+8, &acknum, 4);

  flagsByte |= 0x12; //synack
  reply.writeData(34+13, &flagsByte, 1);

  uint8_t tcp_segment[1500];
  packet.readData(34, tcp_segment, packet.getSize());

  uint32_t sum1 = 0, sum2 = 0;
  for (size_t k = 0; k < 4; k++) {
    sum1 += (((uint32_t)src_IP.value()[k]) << (8 * k));
    sum2 += (((uint32_t)dest_ip[k]) << (8 * k));
  }

  uint16_t checksum = NetworkUtil::tcp_sum(sum1, sum2, tcp_segment, reply.getSize());
  reply.writeData(34+16, &checksum, 2);

  sendPacket(fromModule, std::move(reply));
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd) {
  bind_table.erase({pid, fd});
  this->removeFileDescriptor(pid, fd);
  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  
  // 1. 패킷 파싱
  uint8_t flagsByte;
  uint16_t srcport, destport, seqnum, acknum;
  uint32_t srcip, destip;

  packet.readData(26, &srcip, 4);
  packet.readData(30, &destip, 4);

  packet.readData(34, &srcport, 2);
  packet.readData(34+2, &destport, 2);

  packet.readData(34+4, &seqnum, 4);
  packet.readData(34+8, &acknum, 4);

  packet.readData(34+13, &flagsByte, 1);  // TCP 헤더의 13번째 바이트를 읽음

  bool syn = flagsByte & 0x02;  // 0000 0010 → SYN
  bool ack = flagsByte & 0x10;
  bool fin = flagsByte & 0x01;

  //source dest 주소 바꾸고, ack 번호는 seq # +1로 세팅하고,seq 번호는 seq 변수에 1 더해서 ㄱㄱ
  
  // 3. TCP 상태 전이 처리
  switch (TCP_state) {
    case (CLOSE_state):

    case (LISTEN_state):
      if (syn){
        if (accept_requests.empty()){
          //connect가 먼저 실행되었을 때 accept를 기다리는 부분. 따라서 connect 대기 큐에 넣기.
          connect_requests.emplace_back(fromModule, std::move(packet.clone()));
          break;
        }
        auto [syscallUUID, pid, addr, addrlen] = accept_requests.front();
        accept_requests.pop_front();

        sendSYNACK(fromModule, std::move(packet));
      
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
      
        // 새 소켓을 listen 상태로 설정
        listen_table[{pid, new_sockfd}] = 0;
        bind_table[{pid, new_sockfd}] = {destip, destport};
      
        this->returnSystemCall(syscallUUID, new_sockfd);
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
