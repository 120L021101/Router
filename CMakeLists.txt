cmake_minimum_required(VERSION 3.10)

project(MyRouter)

set(CMAKE_C_STANDARD 11)

# 源文件
set(SOURCES
    src/main.c
    src/arp.c
    src/ethernet.c
    src/hardware.c
    src/util.c
    src/ipv4.c
    src/route.c
    src/udp.c
    src/icmp.c
)

# 添加可执行文件
add_executable(myRouter ${SOURCES})

# 查找并链接 pcap 库
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

target_include_directories(myRouter PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(myRouter ${PCAP_LIBRARIES})
