add_library(server server.c)
target_include_directories(server PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
add_library(client client.c)
target_include_directories(client PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(udp_server main.c)
target_link_libraries(udp_server PRIVATE server)