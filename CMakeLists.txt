cmake_minimum_required(VERSION 3.9)
project(dns_pj C)

set(CMAKE_C_STANDARD 99)

add_executable(test_dns main.c dns.h dns.c)
add_executable(client client.c dns.h dns.c)
add_executable(server server.c dns.h dns.c)
