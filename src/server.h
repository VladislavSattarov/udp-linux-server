#ifndef SERVER_H
#define SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 31337
#define BUFFER_SIZE 1024

#define TAG_POWER 0x0
#define TAG_NETLABEL 0x1

int power_command(uint32_t length, const uint8_t *value);
int netlabel_command(uint32_t length, const uint8_t *value);
int log_command(uint32_t tag, uint32_t length, const uint8_t *value);
int process_packet(const uint8_t *buffer, ssize_t size, int sockfd,
		   struct sockaddr *client_addr, socklen_t client_addr_len);
int start_server();

#endif // SERVER_H