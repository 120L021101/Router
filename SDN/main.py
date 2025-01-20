from scapy.all import sendp, Ether, get_if_hwaddr
from scapy.all import IP, TCP, Raw

def send_packet(packet, outgoing_interface, dest_mac):
    """
    发送数据包到指定接口和目的 MAC 地址，源 MAC 地址设置为接口的 MAC 地址。
    
    参数:
        packet (scapy.packet.Packet): 要发送的 Scapy 数据包。
        outgoing_interface (str): 出口接口名称 (如 "eth0")。
        dest_mac (str): 目标设备的 MAC 地址 (如 "00:11:22:33:44:55")。
    """
    # 获取源接口的 MAC 地址
    src_mac = get_if_hwaddr(outgoing_interface)
    
    # 在数据包前附加以太网头，指定源和目标 MAC 地址
    ethernet_packet = Ether(src=src_mac, dst=dest_mac) / packet

    # 使用 sendp 函数在链路层发送数据包
    sendp(ethernet_packet, iface=outgoing_interface, verbose=False)
    print(f"Packet sent from {src_mac} to {dest_mac} via {outgoing_interface}")

# 创建一个简单的 IP/TCP 数据包
data_payload = Raw(load="Hello, TCP!")
tcp_packet = IP(dst="192.168.2.2") / TCP(dport=1234, sport=12345, flags="S") / data_payload

# 发送数据包，源地址为 veth1 接口的地址
send_packet(tcp_packet, "veth1", "da:38:6b:2d:d6:72")
