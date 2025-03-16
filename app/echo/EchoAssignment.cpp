#include "EchoAssignment.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>

// !IMPORTANT: allowed system calls.
// !DO NOT USE OTHER NETWORK SYSCALLS (send, recv, select, poll, epoll, fork
// etc.)
//  * socket
//  * bind
//  * listen
//  * accept
//  * read
//  * write
//  * close
//  * getsockname
//  * getpeername
// See below for their usage.
// https://github.com/ANLAB-KAIST/KENSv3/wiki/Misc:-External-Resources#linux-manuals

int EchoAssignment::serverMain(const char *bind_ip, int port,
                               const char *server_hello) {

  int server_sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (server_sfd == -1) return -1;

  struct sockaddr_in server_addr = {};
  /*
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr(bind_ip);
  server_addr.sin_port = htons(port);
  */

  if (bind(server_sfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1)
      return -1;
  if (listen(server_sfd, 5) == -1) //왜 5?
      return -1;

  while (true) {
      struct sockaddr_in client_addr;
      socklen_t client_len = sizeof(client_addr);
      int client_sfd = accept(server_sfd, (struct sockaddr*)&client_addr, &client_len);
      if (client_sfd == -1) return -1;

      char buffer[1024] = {};
      ssize_t read_bytes = read(client_sfd, buffer, sizeof(buffer) - 1);
      if (read_bytes <= 0) {
          close(client_sfd);
          return -1;
      }
      buffer[read_bytes] = '\0';

      char response[1024];
      if (strcmp(buffer, "hello\n") == 0) {
          snprintf(response, sizeof(response), "%s\n", server_hello);
      } else if (strcmp(buffer, "whoami\n") == 0) {
          inet_ntop(AF_INET, &client_addr.sin_addr, response, sizeof(response));
          strcat(response, "\n");
      } else if (strcmp(buffer, "whoru\n") == 0) {
          inet_ntop(AF_INET, &server_addr.sin_addr, response, sizeof(response));
          strcat(response, "\n");
      } else {
          snprintf(response, sizeof(response), "%s", buffer);
      }

      write(client_sfd, response, strlen(response));
      close(client_sfd);
  }

  close(server_sfd);
  return 0;
}

int EchoAssignment::clientMain(const char *server_ip, int port,
                               const char *command) {
                                
  int client_sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (client_sfd == -1) return -1;

  struct sockaddr_in server_addr = {};
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr(server_ip);
  server_addr.sin_port = htons(port);

  if (connect(client_sfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1)
      return -1;

  write(client_sfd, command, strlen(command));
  
  char buffer[1024] = {};
  ssize_t read_bytes = read(client_sfd, buffer, sizeof(buffer) - 1);
  if (read_bytes <= 0) {
      close(client_sfd);
      return -1;
  }
  buffer[read_bytes] = '\0';
  
  printf("Server response: %s", buffer);
  close(client_sfd);
  return 0;
}

static void print_usage(const char *program) {
  printf("Usage: %s <mode> <ip-address> <port-number> <command/server-hello>\n"
         "Modes:\n  c: client\n  s: server\n"
         "Client commands:\n"
         "  hello : server returns <server-hello>\n"
         "  whoami: server returns <client-ip>\n"
         "  whoru : server returns <server-ip>\n"
         "  others: server echos\n"
         "Note: each command is terminated by newline character (\\n)\n"
         "Examples:\n"
         "  server: %s s 0.0.0.0 9000 hello-client\n"
         "  client: %s c 127.0.0.1 9000 whoami\n",
         program, program, program);
}

int EchoAssignment::Main(int argc, char *argv[]) {

  if (argc == 0)
    return 1;

  if (argc != 5) {
    print_usage(argv[0]);
    return 1;
  }

  int port = atoi(argv[3]);
  if (port == 0) {
    printf("Wrong port number\n");
    print_usage(argv[0]);
  }

  switch (*argv[1]) {
  case 'c':
    return clientMain(argv[2], port, argv[4]);
  case 's':
    return serverMain(argv[2], port, argv[4]);
  default:
    print_usage(argv[0]);
    return 1;
  }
}
