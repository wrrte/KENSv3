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

std::unordered_map<int, std::unordered_map<int, int>> socket_table; // {pid -> {fd -> type}}
std::unordered_map<std::pair<int, int>, std::pair<uint32_t, uint16_t>> bind_table;


TCPAssignment::TCPAssignment(Host &host)
    : HostModule("TCP", host), RoutingInfoInterface(host),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      TimerModule("TCP", host) {}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize() {}

void TCPAssignment::finalize() {}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  switch (param.syscallNumber) {
  case SOCKET:
    this->syscall_socket(syscallUUID, pid, std::get<int>(param.params[0]),
                        std::get<int>(param.params[1]), std::get<int>(param.params[2]));
    break;
  case CLOSE:
    // this->syscall_close(syscallUUID, pid, std::get<int>(param.params[0]));
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
    // this->syscall_connect(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     (socklen_t)std::get<int>(param.params[2]));
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
  // 지원하는 도메인, 타입, 프로토콜인지 확인
  if (domain != AF_INET || type != SOCK_STREAM || protocol != IPPROTO_TCP) {
      this->returnSystemCall(syscallUUID, -EAFNOSUPPORT);
      return;
  }

  // 새로운 파일 디스크립터 할당 (최소 fd = 3부터 시작)
  int new_fd = 3;
  while (socket_table[pid].count(new_fd)) {
      new_fd++;
  }

  // 소켓 정보 저장
  socket_table[pid][new_fd] = type;

  // 성공적으로 생성된 fd 반환
  this->returnSystemCall(syscallUUID, new_fd);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen) {
  if (!addr || addrlen < sizeof(struct sockaddr_in)) {
      this->returnSystemCall(syscallUUID, -EINVAL);
      return;
  }

  struct sockaddr_in *sock_addr = reinterpret_cast<struct sockaddr_in *>(addr);

  // AF_INET만 허용
  if (sock_addr->sin_family != AF_INET) {
      this->returnSystemCall(syscallUUID, -EAFNOSUPPORT);
      return;
  }

  uint32_t ip_addr = sock_addr->sin_addr.s_addr;
  uint16_t port = sock_addr->sin_port;

  // 바인딩된 주소/포트 중복 확인
  for (const auto &[key, value] : bind_table) {
      uint32_t bound_ip = value.first;
      uint16_t bound_port = value.second;

      if (bound_port == port && (bound_ip == ip_addr || bound_ip == INADDR_ANY || ip_addr == INADDR_ANY)) {
          this->returnSystemCall(syscallUUID, -EADDRINUSE);
          return;
      }
  }

  // 바인딩 정보 저장
  bind_table[{pid, sockfd}] = {ip_addr, port};
  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below
  (void)fromModule;
  (void)packet;
}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

} // namespace E
