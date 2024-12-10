#include "client.h"

int start_client(int *sfd)
{
	int sockfd;
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("Socket");
		return -1;
	}
	*sfd = sockfd;
	return 0;
}

int prepare_server_addr(struct sockaddr_in *server_addr, const char *ip,
			uint16_t port)
{
	memset(server_addr, 0, sizeof(struct sockaddr_in));
	server_addr->sin_family = AF_INET;
	server_addr->sin_port = htons(port);

	if (inet_pton(AF_INET, ip, &server_addr->sin_addr) <= 0) {
		perror("Invalid server address");
		return -1;
	}

	return 0;
}

int send_to_echo_server(int sockfd, const void *buffer, size_t len,
			struct sockaddr *addr, socklen_t addr_len,
			void *response_buffer, size_t response_size)
{
	ssize_t sent = sendto(sockfd, buffer, len, 0, addr, addr_len);
	if (sent < 0) {
		perror("Sendto");
		return -1;
	}
	ssize_t received = 0;
	while (received < len) {
		received += recvfrom(sockfd, response_buffer, response_size, 0,
				     NULL, NULL);
		if (received < 0) {
			perror("Recvfrom");
			return -1;
		}
	}

	if ((size_t)received != len) {
		fprintf(stderr, "Mismatch between sent and received sizes\n");
		return -1;
	}

	return 0;
}

int create_tlv_message(uint32_t tag, const uint8_t *value, uint32_t length,
		       uint8_t *output_buffer, size_t buffer_size)
{
	if (buffer_size < 8 + length) {
		fprintf(stderr, "Buffer too small for TLV message\n");
		return -1;
	}

	uint32_t net_tag = htonl(tag);
	uint32_t net_length = htonl(length);

	memcpy(output_buffer, &net_tag, sizeof(net_tag));
	memcpy(output_buffer + sizeof(net_tag), &net_length,
	       sizeof(net_length));
	memcpy(output_buffer + sizeof(net_tag) + sizeof(net_length), value,
	       length);

	return 8 + length; // Возвращаем общий размер сообщения
}

int end_client(int sfd)
{
	close(sfd);
	return 0;
}