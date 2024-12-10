#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
#include "server.h"
#include "client.h"

static void test_power_command_on(void **state)
{
	(void)state;
	uint8_t value = 1;
	int result = power_command(1, &value);
	assert_int_equal(result, 0);
}

static void test_power_command_off(void **state)
{
	(void)state;
	uint8_t value = 0;
	int result = power_command(1, &value);
	assert_int_equal(result, 0);
}

static void test_power_command_invalid_value(void **state)
{
	(void)state;
	uint8_t value = 5;
	int result = power_command(1, &value);
	assert_int_equal(result, -1);
}

static void test_netlabel_command_valid(void **state)
{
	(void)state;
	uint8_t value[] = "TestLabel";
	int result = netlabel_command(9, value);
	assert_int_equal(result, 0);
}

static void test_netlabel_command_too_long(void **state)
{
	(void)state;
	uint8_t value[300] = { 0 };
	int result = netlabel_command(300, value);
	assert_int_equal(result, -1);
}

static void test_echo_server_response(void **state)
{
	(void)state;

	int client_fd;
	struct sockaddr_in server_addr;
	uint8_t send_buffer[BUFFER_SIZE];
	uint8_t recv_buffer[BUFFER_SIZE];
	const char *server_ip = "127.0.0.1";

	assert_int_equal(start_client(&client_fd), 0);
	assert_int_equal(prepare_server_addr(&server_addr, server_ip, 31337),
			 0);

	struct timeval timeout = { 1, 0 };
	setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
		   sizeof(timeout));

	uint8_t value = 1;
	int message_size = create_tlv_message(TAG_POWER, &value, sizeof(value),
					      send_buffer, BUFFER_SIZE);
	assert_int_not_equal(message_size, -1);

	assert_int_equal(send_to_echo_server(
				 client_fd, send_buffer, message_size,
				 (struct sockaddr *)&server_addr,
				 sizeof(server_addr), recv_buffer, BUFFER_SIZE),
			 0);

	assert_memory_equal(send_buffer, recv_buffer, message_size);

	assert_int_equal(end_client(client_fd), 0);
}

static void test_echo_netlabel_command(void **state)
{
	(void)state;

	int client_fd;
	struct sockaddr_in server_addr;
	uint8_t send_buffer[BUFFER_SIZE];
	uint8_t recv_buffer[BUFFER_SIZE];
	const char *server_ip = "127.0.0.1";

	assert_int_equal(start_client(&client_fd), 0);
	assert_int_equal(prepare_server_addr(&server_addr, server_ip, 31337),
			 0);

	struct timeval timeout = { 1, 0 };
	setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
		   sizeof(timeout));

	const char *label = "TestLabel";
	int label_len = strlen(label);
	int message_size = create_tlv_message(TAG_NETLABEL,
					      (const uint8_t *)label, label_len,
					      send_buffer, BUFFER_SIZE);
	assert_int_not_equal(message_size, -1);

	assert_int_equal(send_to_echo_server(
				 client_fd, send_buffer, message_size,
				 (struct sockaddr *)&server_addr,
				 sizeof(server_addr), recv_buffer, BUFFER_SIZE),
			 0);

	assert_memory_equal(send_buffer, recv_buffer, message_size);

	assert_int_equal(end_client(client_fd), 0);
}

static void test_buffer_overflow(void **state)
{
	(void)state;

	int client_fd;
	struct sockaddr_in server_addr;
	uint8_t send_buffer[BUFFER_CLIENT_SIZE];
	uint8_t recv_buffer[BUFFER_SIZE];
	const char *server_ip = "127.0.0.1";

	assert_int_equal(start_client(&client_fd), 0);
	assert_int_equal(prepare_server_addr(&server_addr, server_ip, 31337),
			 0);

	struct timeval timeout = { 1, 0 };
	setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
		   sizeof(timeout));
	// Создание слишком длинного TLV сообщения
	uint8_t long_data[BUFFER_CLIENT_SIZE];
	memset(long_data, 'A', sizeof(long_data));
	int message_size = create_tlv_message(TAG_NETLABEL, long_data,
					      BUFFER_CLIENT_SIZE, send_buffer,
					      BUFFER_CLIENT_SIZE);
	assert_int_not_equal(message_size, BUFFER_CLIENT_SIZE);

	int result = send_to_echo_server(client_fd, send_buffer, message_size,
					 (struct sockaddr *)&server_addr,
					 sizeof(server_addr), recv_buffer,
					 BUFFER_SIZE);
	assert_int_equal(result, -1); // Ожидаем ошибку

	assert_int_equal(end_client(client_fd), 0);
}

static void test_unknown_tag(void **state)
{
	(void)state;

	int client_fd;
	struct sockaddr_in server_addr;
	uint8_t send_buffer[BUFFER_SIZE];
	uint8_t recv_buffer[BUFFER_SIZE];
	const char *server_ip = "127.0.0.1";

	assert_int_equal(start_client(&client_fd), 0);
	assert_int_equal(prepare_server_addr(&server_addr, server_ip, 31337),
			 0);

	struct timeval timeout = { 1, 0 };
	setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
		   sizeof(timeout));

	// Создание TLV с неизвестным тегом
	uint32_t unknown_tag = 0xDEADBEEF;
	uint8_t value = 42;
	int message_size = create_tlv_message(
		unknown_tag, &value, sizeof(value), send_buffer, BUFFER_SIZE);
	assert_int_not_equal(message_size, -1);

	int result = send_to_echo_server(client_fd, send_buffer, message_size,
					 (struct sockaddr *)&server_addr,
					 sizeof(server_addr), recv_buffer,
					 BUFFER_SIZE);
	assert_int_equal(result, -1); // Ожидаем ошибку

	assert_int_equal(end_client(client_fd), 0);
}

static void test_short_packet(void **state)
{
	(void)state;

	int client_fd;
	struct sockaddr_in server_addr;
	uint8_t send_buffer[BUFFER_SIZE];
	uint8_t recv_buffer[BUFFER_SIZE];
	const char *server_ip = "127.0.0.1";

	assert_int_equal(start_client(&client_fd), 0);
	assert_int_equal(prepare_server_addr(&server_addr, server_ip, 31337),
			 0);

	struct timeval timeout = { 1, 0 };
	setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
		   sizeof(timeout));

	// Создание слишком короткого пакета
	uint8_t short_packet[4] = { 0x00, 0x00, 0x00, 0x00 };
	int short_size = sizeof(short_packet);

	int result = send_to_echo_server(client_fd, short_packet, short_size,
					 (struct sockaddr *)&server_addr,
					 sizeof(server_addr), recv_buffer,
					 BUFFER_SIZE);
	assert_int_equal(result, -1);

	assert_int_equal(end_client(client_fd), 0);
}

static void test_multiple_commands(void **state)
{
	(void)state;

	int client_fd;
	struct sockaddr_in server_addr;
	uint8_t send_buffer[BUFFER_SIZE];
	uint8_t recv_buffer[BUFFER_SIZE];
	const char *server_ip = "127.0.0.1";

	assert_int_equal(start_client(&client_fd), 0);
	assert_int_equal(prepare_server_addr(&server_addr, server_ip, 31337),
			 0);

	struct timeval timeout = { 1, 0 };
	setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
		   sizeof(timeout));

	//Создание пакета с несколькими TLV
	uint8_t *ptr = send_buffer;
	size_t remaining_size = BUFFER_SIZE;

	//TAG_POWER
	uint8_t power_value = 1;
	int size1 = create_tlv_message(TAG_POWER, &power_value,
				       sizeof(power_value), ptr,
				       remaining_size);
	assert_int_not_equal(size1, -1);
	ptr += size1;
	remaining_size -= size1;

	//TAG_NETLABEL
	const char *label = "MultiTest";
	int size2 = create_tlv_message(TAG_NETLABEL, (const uint8_t *)label,
				       strlen(label), ptr, remaining_size);
	assert_int_not_equal(size2, -1);
	ptr += size2;
	remaining_size -= size2;

	size_t total_size = BUFFER_SIZE - remaining_size;

	ssize_t sent = sendto(client_fd, send_buffer, total_size, 0,
			      (struct sockaddr *)&server_addr,
			      sizeof(server_addr));

	ssize_t received =
		recvfrom(client_fd, recv_buffer, BUFFER_SIZE, 0, NULL, NULL);

	uint8_t *ptr_recv = recv_buffer;
	uint32_t recv_tag1;
	uint32_t recv_length1;
	uint8_t recv_value1;

	memcpy(&recv_tag1, ptr_recv, sizeof(recv_tag1));
	ptr_recv += sizeof(recv_tag1);
	memcpy(&recv_length1, ptr_recv, sizeof(recv_length1));
	ptr_recv += sizeof(recv_length1);
	memcpy(&recv_value1, ptr_recv, sizeof(recv_value1));
	ptr_recv += sizeof(recv_value1);

	recv_tag1 = ntohl(recv_tag1);
	recv_length1 = ntohl(recv_length1);

	assert_int_equal(recv_tag1, TAG_POWER);
	assert_int_equal(recv_length1, sizeof(recv_value1));
	assert_int_equal(recv_value1, power_value);

	//Обработка второго пакета
	uint32_t recv_tag2;
	uint32_t recv_length2;

	memcpy(&recv_tag2, ptr_recv, sizeof(recv_tag2));
	ptr_recv += sizeof(recv_tag2);
	memcpy(&recv_length2, ptr_recv, sizeof(recv_length2));
	ptr_recv += sizeof(recv_length2);

	recv_tag2 = ntohl(recv_tag2);
	recv_length2 = ntohl(recv_length2);

	assert_int_equal(recv_tag2, TAG_NETLABEL);
	assert_int_equal(recv_length2, strlen(label));

	assert_int_equal(end_client(client_fd), 0);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_power_command_on),
		cmocka_unit_test(test_power_command_off),
		cmocka_unit_test(test_power_command_invalid_value),
		cmocka_unit_test(test_netlabel_command_valid),
		cmocka_unit_test(test_netlabel_command_too_long),
		cmocka_unit_test(test_echo_server_response),
		cmocka_unit_test(test_echo_netlabel_command),
		cmocka_unit_test(test_buffer_overflow),
		cmocka_unit_test(test_unknown_tag),
		cmocka_unit_test(test_short_packet),
		cmocka_unit_test(test_multiple_commands),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}