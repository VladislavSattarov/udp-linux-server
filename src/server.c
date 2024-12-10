#include "server.h"

//Команды, вроде как расширяются легко

int power_command(uint32_t length, const uint8_t *value)
{
	if (*value == 0) {
		fprintf(stderr, "Command: Amplifier Power OFF\n");
	} else if (*value == 1) {
		fprintf(stderr, "Command: Amplifier Power ON\n");
	} else {
		fprintf(stderr, "Unknown value for power command: %u\n",
			*value);
		return -1;
	}
	return 0;
}

int netlabel_command(uint32_t length, const uint8_t *value)
{
	if (length > 255) {
		fprintf(stderr, "Invalid length for network label: %u\n",
			length);
		return -1;
	}
	fprintf(stderr, "Command: Network Label: %.*s\n", length, value);
	return 0;
}

int log_command(uint32_t tag, uint32_t length, const uint8_t *value)
{
	switch (tag) {
	case TAG_POWER:
		return power_command(length, value);
		break;
	case TAG_NETLABEL:
		return netlabel_command(length, value);
		break;
	default:
		fprintf(stderr, "Unknown command tag: 0x%x\n", tag);
		return -1;
		break;
	}
}

int process_packet(const uint8_t *buffer, ssize_t size, int sockfd,
		   struct sockaddr *client_addr, socklen_t client_addr_len)
{
	const uint8_t *ptr = buffer;
	const uint8_t *end = buffer + size;

	while (ptr + 8 <= end) {
		uint32_t tag;
		uint32_t length;

		memcpy(&tag, ptr, sizeof(tag));
		ptr += sizeof(tag);

		memcpy(&length, ptr, sizeof(length));
		ptr += sizeof(length);

		tag = ntohl(tag);
		length = ntohl(length);

		if (ptr + length > end) {
			fprintf(stderr,
				"Invalid packet: not enough data for TLV value\n");
			return -1;
		}
		//проверка на знание команды
		if (log_command(tag, length, ptr) != 0) {
			printf("Command not executed, no echo sent\n");
			return -1;
		}
		ptr += length;
	}

	if (ptr != end) {
		fprintf(stderr, "Invalid packet: extra bytes at the end\n");
		return -1;
	}
	//если все команды, сервер узнал, то вернуть отправителю
	ssize_t sent =
		sendto(sockfd, buffer, size, 0, client_addr, client_addr_len);
	if (sent < 0) {
		perror("Sendto");
	} else {
		printf("Echoed command back to client\n");
	}
	return 0;
}

int start_server()
{
	//подготовка сокета
	int sockfd;
	struct sockaddr_in server_addr, client_addr;
	socklen_t client_len = sizeof(client_addr);
	uint8_t buffer[BUFFER_SIZE];

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("Socket");
		exit(EXIT_FAILURE);
	}

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(PORT);

	if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
	    0) {
		perror("Bind");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "Server is listening on port %d\n", PORT);
	//цикл прослушивания порта
	while (1) {
		memset(buffer, 0, BUFFER_SIZE);
		ssize_t received = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
					    (struct sockaddr *)&client_addr,
					    &client_len);
		if (received < 0) {
			perror("Receive");
			continue;
		}
		if (received < 8) {
			fprintf(stderr, "Received packet too short for TLV\n");
			continue;
		}
		process_packet(buffer, received, sockfd,
			       (struct sockaddr *)&client_addr, client_len);
	}

	close(sockfd);
	return 0;
}