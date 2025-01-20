export LD_LIBRARY_PATH=/mnt/f/Quater1/Formal/Router/config/lib/cJSON:$LD_LIBRARY_PATH 
gcc -o main main.c \
    -I ./recv/include \
    recv/src/pkg_rcver.c recv/src/ethernet.c recv/src/ipv4.c recv/src/arpv4.c recv/src/icmpv4.c recv/src/udp.c recv/src/tcp.c \
    -I ./route/include \
    route/src/ipv4_table.c \
    -I ./send/include \
    send/src/pkg_sender.c send/src/send.c \
    -I ./rcp/include \
    rcp/src/icmpv4_handle.c rcp/src/tcp_handle.c rcp/src/pcep_handle.c \
    -I ./config/include -I ./config/lib/ \
    config/src/route_init.c \
    -lpcap -lpthread -lz -L ./config/lib/cJSON/ -lcjson