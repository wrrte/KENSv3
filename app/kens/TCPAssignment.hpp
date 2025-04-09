/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_TimerModule.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define CLOSE_state 0
#define LISTEN_state 1
#define SYN_RCVD_state 2
#define SYN_SENT_state 3
#define ESTABLISHED_state 4
#define CLOSE_WAIT_state 5
#define FIN_WAIT_1_state 6
#define CLOSING_state 7
#define LAST_ACK_state 8
#define FIN_WAIT_2_state 9
#define TIME_WAIT_state 10

namespace E {

class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;

  uint64_t TCP_state;
  uint64_t seq;

  std::unordered_map<std::pair<int, int>, std::pair<uint32_t, uint16_t>> bind_table;
  std::unordered_map<std::pair<int, int>, int> listen_table;
  std::list<std::tuple<UUID, struct sockaddr *, socklen_t *>> accept_requests;
  std::list<std::tuple<std::string, Packet &&, uint8_t, uint16_t, uint16_t, uint16_t, uint16_t, uint32_t, uint32_t>> connection_requests;

public:
  TCPAssignment(Host &host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();

protected:
  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  void syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol);
  void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
  void syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  void syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen);
  void syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen);
  void syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  void syscall_close(UUID syscallUUID, int pid, int fd);
  void sendSYNACK(std::string fromModule, Packet &&packet, uint8_t flagsByte, uint16_t srcport, uint16_t destport, uint16_t seqnum, uint16_t acknum, uint32_t srcip, uint32_t destip);
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;
};

class TCPAssignmentProvider {
private:
  TCPAssignmentProvider() {}
  ~TCPAssignmentProvider() {}

public:
  static void allocate(Host &host) { host.addHostModule<TCPAssignment>(host); }
};

} // namespace E

#endif /* E_TCPASSIGNMENT_HPP_ */
