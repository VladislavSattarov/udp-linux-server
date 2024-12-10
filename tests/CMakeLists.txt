enable_testing()

add_executable(test_server test_server.c)
target_link_libraries(test_server PRIVATE server client /usr/local/lib/libcmocka.so.0)
add_test(NAME test_server COMMAND test_server)