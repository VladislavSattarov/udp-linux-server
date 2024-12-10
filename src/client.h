#ifndef CLIENT_H
#define CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_PORT 31337
#define BUFFER_CLIENT_SIZE 2024

#define TAG_POWER 0x0
#define TAG_NETLABEL 0x1

int send_to_echo_server(int sockfd, const void *buffer, size_t len,
			struct sockaddr *addr, socklen_t addr_len,
			void *response_buffer, size_t response_size);
int prepare_server_addr(struct sockaddr_in *server_addr, const char *ip,
			uint16_t port);
int create_tlv_message(uint32_t tag, const uint8_t *value, uint32_t length,
		       uint8_t *output_buffer, size_t buffer_size);
int start_client(int *sfd);
int end_client(int sfd);

#endif // CLIENT_H